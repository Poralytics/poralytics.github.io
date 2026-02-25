/**
 * INTEGRATION SERVICE
 * Automatise la création de tickets, PRs, et notifications
 */

const db = require('../config/database');
const { logger } = require('../utils/error-handler');

class IntegrationService {
  constructor() {
    // Configuration des intégrations
    this.integrations = {
      jira: {
        enabled: false,
        baseUrl: process.env.JIRA_BASE_URL,
        email: process.env.JIRA_EMAIL,
        apiToken: process.env.JIRA_API_TOKEN,
        projectKey: process.env.JIRA_PROJECT_KEY || 'SEC'
      },
      github: {
        enabled: false,
        token: process.env.GITHUB_TOKEN,
        owner: process.env.GITHUB_OWNER,
        repo: process.env.GITHUB_REPO
      },
      slack: {
        enabled: false,
        webhookUrl: process.env.SLACK_WEBHOOK_URL,
        channel: process.env.SLACK_CHANNEL || '#security'
      }
    };
  }

  /**
   * Créer automatiquement un ticket Jira pour une vulnérabilité
   */
  async createJiraTicket(vulnerability, user) {
    if (!this.integrations.jira.enabled) {
      return { created: false, reason: 'Jira integration not enabled' };
    }

    try {
      const ticket = {
        fields: {
          project: { key: this.integrations.jira.projectKey },
          summary: `[${vulnerability.severity.toUpperCase()}] ${vulnerability.title}`,
          description: this.formatJiraDescription(vulnerability),
          issuetype: { name: 'Bug' },
          priority: this.mapSeverityToPriority(vulnerability.severity),
          labels: ['security', 'nexus', vulnerability.type, vulnerability.severity]
        }
      };

      // En production: vrai appel Jira API
      // const response = await fetch(`${this.integrations.jira.baseUrl}/rest/api/3/issue`, {
      //   method: 'POST',
      //   headers: {
      //     'Authorization': `Basic ${Buffer.from(`${this.integrations.jira.email}:${this.integrations.jira.apiToken}`).toString('base64')}`,
      //     'Content-Type': 'application/json'
      //   },
      //   body: JSON.stringify(ticket)
      // });

      // Simulation pour la démo
      const simulatedResponse = {
        id: `${vulnerability.id}-${Date.now()}`,
        key: `${this.integrations.jira.projectKey}-${Math.floor(Math.random() * 1000)}`,
        self: `${this.integrations.jira.baseUrl}/browse/${this.integrations.jira.projectKey}-123`
      };

      // Enregistrer dans la DB
      db.prepare(`
        INSERT INTO integration_events (
          user_id,
          integration_type,
          event_type,
          reference_id,
          reference_type,
          external_id,
          external_url,
          status,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        user.id,
        'jira',
        'ticket_created',
        vulnerability.id,
        'vulnerability',
        simulatedResponse.key,
        simulatedResponse.self,
        'success',
        Math.floor(Date.now() / 1000)
      );

      logger.logInfo('Jira ticket created', { vulnId: vulnerability.id, jiraKey: simulatedResponse.key });

      return {
        created: true,
        ticket_id: simulatedResponse.key,
        url: simulatedResponse.self
      };
    } catch (error) {
      logger.logError(error, { context: 'createJiraTicket', vulnId: vulnerability.id });
      return { created: false, error: error.message };
    }
  }

  /**
   * Créer automatiquement une Pull Request GitHub avec le fix
   */
  async createGitHubPR(vulnerability, fixCode, user) {
    if (!this.integrations.github.enabled) {
      return { created: false, reason: 'GitHub integration not enabled' };
    }

    try {
      const branchName = `security-fix-${vulnerability.id}-${Date.now()}`;
      const prTitle = `Fix: ${vulnerability.title}`;
      const prBody = this.formatGitHubPRDescription(vulnerability, fixCode);

      // En production: vrai appel GitHub API
      // 1. Create branch
      // 2. Create/update file with fix
      // 3. Create pull request

      // Simulation
      const simulatedPR = {
        number: Math.floor(Math.random() * 1000),
        html_url: `https://github.com/${this.integrations.github.owner}/${this.integrations.github.repo}/pull/${Math.floor(Math.random() * 1000)}`,
        state: 'open'
      };

      // Enregistrer dans la DB
      db.prepare(`
        INSERT INTO integration_events (
          user_id,
          integration_type,
          event_type,
          reference_id,
          reference_type,
          external_id,
          external_url,
          status,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        user.id,
        'github',
        'pr_created',
        vulnerability.id,
        'vulnerability',
        simulatedPR.number.toString(),
        simulatedPR.html_url,
        'success',
        Math.floor(Date.now() / 1000)
      );

      logger.logInfo('GitHub PR created', { vulnId: vulnerability.id, prNumber: simulatedPR.number });

      return {
        created: true,
        pr_number: simulatedPR.number,
        url: simulatedPR.html_url,
        branch: branchName
      };
    } catch (error) {
      logger.logError(error, { context: 'createGitHubPR', vulnId: vulnerability.id });
      return { created: false, error: error.message };
    }
  }

  /**
   * Envoyer une notification Slack
   */
  async sendSlackNotification(message, severity = 'info') {
    if (!this.integrations.slack.enabled) {
      return { sent: false, reason: 'Slack integration not enabled' };
    }

    try {
      const color = this.getSeverityColor(severity);
      const payload = {
        channel: this.integrations.slack.channel,
        attachments: [{
          color,
          title: message.title,
          text: message.text,
          fields: message.fields || [],
          footer: 'NEXUS Security Platform',
          ts: Math.floor(Date.now() / 1000)
        }]
      };

      // En production: vrai appel Slack webhook
      // await fetch(this.integrations.slack.webhookUrl, {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(payload)
      // });

      logger.logInfo('Slack notification sent', { severity });

      return { sent: true };
    } catch (error) {
      logger.logError(error, { context: 'sendSlackNotification' });
      return { sent: false, error: error.message };
    }
  }

  /**
   * Workflow: Nouveau scan complété
   */
  async handleScanCompleted(scan, user) {
    const vulns = db.prepare(`
      SELECT * FROM vulnerabilities 
      WHERE scan_id = ? 
      AND status != 'fixed'
      ORDER BY 
        CASE severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          ELSE 4
        END
      LIMIT 10
    `).all(scan.id);

    const results = {
      jira_tickets: [],
      github_prs: [],
      slack_sent: false
    };

    // Créer tickets Jira pour les vulns critiques et high
    for (const vuln of vulns.filter(v => ['critical', 'high'].includes(v.severity))) {
      const jiraResult = await this.createJiraTicket(vuln, user);
      if (jiraResult.created) {
        results.jira_tickets.push(jiraResult);
      }
    }

    // Envoyer notification Slack
    const slackMessage = {
      title: `Scan completed for ${scan.domain_url || 'domain'}`,
      text: `Found ${vulns.length} vulnerabilities`,
      fields: [
        { title: 'Critical', value: vulns.filter(v => v.severity === 'critical').length.toString(), short: true },
        { title: 'High', value: vulns.filter(v => v.severity === 'high').length.toString(), short: true },
        { title: 'Medium', value: vulns.filter(v => v.severity === 'medium').length.toString(), short: true },
        { title: 'Low', value: vulns.filter(v => v.severity === 'low').length.toString(), short: true }
      ]
    };

    const slackResult = await this.sendSlackNotification(
      slackMessage,
      vulns.some(v => v.severity === 'critical') ? 'critical' : 'high'
    );
    results.slack_sent = slackResult.sent;

    return results;
  }

  /**
   * Auto-assignment de vulnérabilités aux développeurs
   */
  async autoAssignVulnerabilities(scanId, user) {
    // Logique d'auto-assignment basée sur:
    // - Type de vulnérabilité
    // - Localisation (frontend/backend)
    // - Workload de l'équipe
    // - Expertise

    const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);
    const assignments = [];

    for (const vuln of vulns) {
      const assignedTo = this.determineAssignee(vuln, user);
      
      if (assignedTo) {
        db.prepare(`
          UPDATE vulnerabilities 
          SET assigned_to = ?, assigned_at = ?
          WHERE id = ?
        `).run(assignedTo, Math.floor(Date.now() / 1000), vuln.id);

        assignments.push({
          vulnerability_id: vuln.id,
          assigned_to: assignedTo
        });
      }
    }

    return assignments;
  }

  // ========== HELPER METHODS ==========

  formatJiraDescription(vuln) {
    return `
h2. Vulnerability Details

*Type:* ${vuln.type}
*Severity:* ${vuln.severity}
*URL:* ${vuln.url}

h3. Description
${vuln.description}

h3. Impact
${this.getImpactDescription(vuln.severity)}

h3. Recommended Action
${vuln.recommendation || 'Review and remediate according to security best practices'}

---
_Created automatically by NEXUS Security Platform_
`;
  }

  formatGitHubPRDescription(vuln, fixCode) {
    return `
## Security Fix: ${vuln.title}

### Vulnerability Details
- **Type:** ${vuln.type}
- **Severity:** ${vuln.severity}
- **Location:** ${vuln.url}

### Description
${vuln.description}

### Fix Applied
\`\`\`
${fixCode || 'See code changes in files below'}
\`\`\`

### Testing
- [ ] Vulnerability is no longer exploitable
- [ ] Existing functionality still works
- [ ] Security tests pass
- [ ] Code review completed

### References
- NEXUS Vulnerability ID: ${vuln.id}
- OWASP: ${this.getOWASPReference(vuln.type)}

---
*Auto-generated by NEXUS Security Platform*
`;
  }

  mapSeverityToPriority(severity) {
    const mapping = {
      critical: { name: 'Highest' },
      high: { name: 'High' },
      medium: { name: 'Medium' },
      low: { name: 'Low' }
    };
    return mapping[severity] || { name: 'Medium' };
  }

  getSeverityColor(severity) {
    const colors = {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#3b82f6',
      info: '#94a3b8'
    };
    return colors[severity] || colors.info;
  }

  getImpactDescription(severity) {
    const impacts = {
      critical: 'Complete system compromise possible. Immediate action required.',
      high: 'Significant security risk. Address within 48 hours.',
      medium: 'Moderate risk. Should be fixed within 2 weeks.',
      low: 'Minor risk. Address as part of regular maintenance.'
    };
    return impacts[severity] || 'Security issue requiring attention.';
  }

  getOWASPReference(vulnType) {
    const references = {
      sql_injection: 'https://owasp.org/www-community/attacks/SQL_Injection',
      xss: 'https://owasp.org/www-community/attacks/xss/',
      csrf: 'https://owasp.org/www-community/attacks/csrf',
      authentication: 'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication'
    };
    return references[vulnType] || 'https://owasp.org';
  }

  determineAssignee(vuln, user) {
    // Logique simple d'assignment
    // En production: plus sophistiqué basé sur expertise, workload, etc.
    
    if (vuln.url.includes('/api/')) {
      return 'backend-team';
    } else if (vuln.url.includes('.js')) {
      return 'frontend-team';
    }
    return 'security-team';
  }

  /**
   * Vérifier et activer les intégrations
   */
  checkIntegrations() {
    const status = {};

    // Jira
    status.jira = {
      enabled: !!(this.integrations.jira.baseUrl && this.integrations.jira.apiToken),
      configured: !!(this.integrations.jira.baseUrl && this.integrations.jira.email && this.integrations.jira.apiToken)
    };
    this.integrations.jira.enabled = status.jira.enabled;

    // GitHub
    status.github = {
      enabled: !!(this.integrations.github.token && this.integrations.github.owner && this.integrations.github.repo),
      configured: !!(this.integrations.github.token && this.integrations.github.owner && this.integrations.github.repo)
    };
    this.integrations.github.enabled = status.github.enabled;

    // Slack
    status.slack = {
      enabled: !!this.integrations.slack.webhookUrl,
      configured: !!this.integrations.slack.webhookUrl
    };
    this.integrations.slack.enabled = status.slack.enabled;

    return status;
  }
}

module.exports = new IntegrationService();
