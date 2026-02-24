const axios = require('axios');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const nodemailer = require('nodemailer');

class Integrations {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    this.slackWebhook = process.env.SLACK_WEBHOOK_URL;
    this.emailTransporter = null;
    this.setupEmail();
  }

  setupEmail() {
    if (process.env.SMTP_HOST) {
      this.emailTransporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
    }
  }

  async sendSlackNotification(scan, vulnerabilities) {
    if (!this.slackWebhook) return {success: false, reason: 'Slack not configured'};

    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;

    const message = {
      text: `🔍 Security Scan Completed`,
      blocks: [
        {
          type: 'header',
          text: {type: 'plain_text', text: '🔍 Security Scan Results'}
        },
        {
          type: 'section',
          fields: [
            {type: 'mrkdwn', text: `*Score:*\n${scan.security_score}/100`},
            {type: 'mrkdwn', text: `*Risk:*\n€${(scan.risk_exposure_eur || 0).toLocaleString()}`},
            {type: 'mrkdwn', text: `*Critical:*\n${criticalCount}`},
            {type: 'mrkdwn', text: `*High:*\n${highCount}`}
          ]
        }
      ]
    };

    try {
      await this.httpClient.post(this.slackWebhook, message);
      return {success: true};
    } catch (error) {
      return {success: false, error: error.message};
    }
  }

  async sendEmailAlert(to, scan, vulnerabilities) {
    if (!this.emailTransporter) return {success: false, reason: 'Email not configured'};

    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical');
    
    const html = `
      <h1>Security Scan Alert</h1>
      <p>A security scan has been completed with <strong>${criticalVulns.length} critical vulnerabilities</strong>.</p>
      
      <h2>Summary</h2>
      <ul>
        <li>Security Score: ${scan.security_score}/100</li>
        <li>Risk Exposure: €${(scan.risk_exposure_eur || 0).toLocaleString()}</li>
        <li>Vulnerabilities: ${scan.vulnerabilities_found}</li>
      </ul>
      
      <h2>Critical Vulnerabilities</h2>
      <ul>
        ${criticalVulns.map(v => `<li>${v.title} - €${(v.expected_loss_eur || 0).toLocaleString()}</li>`).join('')}
      </ul>
      
      <p>Please log in to the dashboard for full details.</p>
    `;

    try {
      await this.emailTransporter.sendMail({
        from: process.env.SMTP_USER,
        to: to,
        subject: `⚠️ Security Alert: ${criticalVulns.length} Critical Vulnerabilities Found`,
        html: html
      });
      return {success: true};
    } catch (error) {
      return {success: false, error: error.message};
    }
  }

  async createJiraIssue(vulnerability) {
    if (!process.env.JIRA_HOST) return {success: false, reason: 'Jira not configured'};

    const issue = {
      fields: {
        project: {key: 'SEC'},
        summary: vulnerability.title,
        description: `${vulnerability.description}\n\nRemediation: ${vulnerability.remediation_text}\n\nCVSS: ${vulnerability.cvss_score}`,
        issuetype: {name: 'Bug'},
        priority: {name: vulnerability.severity === 'critical' ? 'Highest' : 'High'}
      }
    };

    try {
      const response = await this.httpClient.post(
        `https://${process.env.JIRA_HOST}/rest/api/2/issue`,
        issue,
        {
          auth: {
            username: process.env.JIRA_EMAIL,
            password: process.env.JIRA_API_TOKEN
          }
        }
      );
      return {success: true, issue_key: response.data.key};
    } catch (error) {
      return {success: false, error: error.message};
    }
  }

  async createGitHubIssue(vulnerability, repo) {
    if (!process.env.GITHUB_TOKEN) return {success: false, reason: 'GitHub not configured'};

    const issue = {
      title: `[Security] ${vulnerability.title}`,
      body: `## Vulnerability Details\n\n${vulnerability.description}\n\n**Severity:** ${vulnerability.severity}\n**CVSS Score:** ${vulnerability.cvss_score}\n\n## Remediation\n\n${vulnerability.remediation_text}\n\n**Effort:** ${vulnerability.remediation_effort_hours} hours`,
      labels: ['security', vulnerability.severity]
    };

    try {
      const response = await this.httpClient.post(
        `https://api.github.com/repos/${repo}/issues`,
        issue,
        {
          headers: {
            'Authorization': `token ${process.env.GITHUB_TOKEN}`,
            'Accept': 'application/vnd.github.v3+json'
          }
        }
      );
      return {success: true, issue_number: response.data.number};
    } catch (error) {
      return {success: false, error: error.message};
    }
  }

  async sendWebhook(url, scan, vulnerabilities) {
    try {
      await this.httpClient.post(url, {
        event: 'scan_completed',
        scan: {
          id: scan.id,
          security_score: scan.security_score,
          risk_exposure_eur: scan.risk_exposure_eur,
          vulnerabilities_found: scan.vulnerabilities_found
        },
        vulnerabilities: vulnerabilities.map(v => ({
          severity: v.severity,
          title: v.title,
          expected_loss_eur: v.expected_loss_eur
        }))
      });
      return {success: true};
    } catch (error) {
      return {success: false, error: error.message};
    }
  }
}

module.exports = new Integrations();
