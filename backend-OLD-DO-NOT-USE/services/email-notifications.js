/**
 * EMAIL NOTIFICATIONS SERVICE
 * Envoie des alertes professionnelles aux clients
 */

const { logger } = require('../utils/error-handler');

class EmailNotificationService {
  constructor() {
    this.mailer = null;
    this.from = process.env.FROM_EMAIL || 'noreply@nexus-scanner.com';
    this.enabled = false;
    this.initializeMailer();
  }

  initializeMailer() {
    try {
      if (process.env.SMTP_HOST) {
        const nodemailer = require('nodemailer');
        this.mailer = nodemailer.createTransport({
          host: process.env.SMTP_HOST,
          port: parseInt(process.env.SMTP_PORT) || 587,
          secure: process.env.SMTP_SECURE === 'true',
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASSWORD
          }
        });
        this.enabled = true;
        logger.logInfo('Email notifications enabled');
      } else {
        logger.logWarning('SMTP not configured - email notifications disabled');
      }
    } catch (err) {
      logger.logError(err, { context: 'Email service init' });
      this.enabled = false;
    }
  }

  /**
   * Notifier fin de scan
   */
  async notifyScanComplete(user, domain, scan, stats) {
    if (!this.enabled) return;

    const subject = `NEXUS Scan Complete: ${domain.name || domain.url}`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #6366F1, #8B5CF6); padding: 30px; text-align: center;">
          <h1 style="color: white; margin: 0;">🛡️ NEXUS Security Scanner</h1>
        </div>
        
        <div style="padding: 30px; background: #f8f9fa;">
          <h2 style="color: #1e293b;">Scan Complete</h2>
          <p>Hi ${user.name},</p>
          <p>Your security scan for <strong>${domain.url}</strong> has been completed.</p>
          
          <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0; color: #1e293b;">Results Summary</h3>
            <table style="width: 100%; border-collapse: collapse;">
              <tr>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;"><strong>Security Score</strong></td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; text-align: right;">
                  <span style="font-size: 20px; font-weight: bold; color: ${scan.security_score >= 800 ? '#10b981' : scan.security_score >= 600 ? '#f59e0b' : '#ef4444'}">
                    ${scan.security_score || 0}/1000
                  </span>
                </td>
              </tr>
              <tr>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0;"><strong>Total Vulnerabilities</strong></td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; text-align: right;">${stats.total || 0}</td>
              </tr>
              <tr>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; color: #dc2626;"><strong>Critical</strong></td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; text-align: right; color: #dc2626;">${stats.critical || 0}</td>
              </tr>
              <tr>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; color: #ea580c;"><strong>High</strong></td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; text-align: right; color: #ea580c;">${stats.high || 0}</td>
              </tr>
              <tr>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; color: #d97706;"><strong>Medium</strong></td>
                <td style="padding: 8px; border-bottom: 1px solid #e2e8f0; text-align: right; color: #d97706;">${stats.medium || 0}</td>
              </tr>
              <tr>
                <td style="padding: 8px;"><strong>Low</strong></td>
                <td style="padding: 8px; text-align: right;">${stats.low || 0}</td>
              </tr>
            </table>
          </div>
          
          ${stats.critical > 0 ? `
          <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 15px; margin: 20px 0;">
            <strong style="color: #dc2626;">⚠️ Critical Issues Found</strong>
            <p style="margin: 5px 0 0 0;">Your site has ${stats.critical} critical vulnerabilities that require immediate attention.</p>
          </div>
          ` : ''}
          
          <div style="text-align: center; margin-top: 30px;">
            <a href="${process.env.APP_URL || 'https://nexus-scanner.com'}/dashboard" 
               style="display: inline-block; background: #6366F1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold;">
              View Full Report
            </a>
          </div>
          
          <p style="margin-top: 30px; font-size: 12px; color: #64748b;">
            This is an automated notification from NEXUS Security Scanner.<br>
            Scan ID: ${scan.id} | Completed: ${new Date(scan.completed_at * 1000).toLocaleString()}
          </p>
        </div>
      </div>
    `;

    try {
      await this.mailer.sendMail({
        from: this.from,
        to: user.email,
        subject,
        html
      });
      logger.logInfo('Scan complete notification sent', { userId: user.id, scanId: scan.id });
    } catch (err) {
      logger.logError(err, { context: 'Send scan complete email', userId: user.id });
    }
  }

  /**
   * Alerte critique
   */
  async notifyCriticalVulnerability(user, domain, vulnerability) {
    if (!this.enabled) return;

    const subject = `🚨 Critical Vulnerability Detected: ${domain.url}`;
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: #dc2626; padding: 30px; text-align: center;">
          <h1 style="color: white; margin: 0;">🚨 CRITICAL ALERT</h1>
        </div>
        
        <div style="padding: 30px; background: #fef2f2;">
          <p>Hi ${user.name},</p>
          <p><strong>A critical security vulnerability has been detected on ${domain.url}</strong></p>
          
          <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #dc2626;">
            <h3 style="color: #dc2626; margin-top: 0;">${vulnerability.title}</h3>
            <p><strong>Category:</strong> ${vulnerability.category}</p>
            <p><strong>CVSS Score:</strong> ${vulnerability.cvss_score}/10</p>
            <p><strong>CWE:</strong> ${vulnerability.cwe_id || 'N/A'}</p>
            ${vulnerability.parameter ? `<p><strong>Parameter:</strong> <code>${vulnerability.parameter}</code></p>` : ''}
            
            <div style="margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 4px;">
              <strong>Recommended Action:</strong>
              <p style="margin: 5px 0 0 0;">${vulnerability.remediation_text || 'Review and fix this vulnerability immediately.'}</p>
            </div>
          </div>
          
          <div style="text-align: center; margin-top: 30px;">
            <a href="${process.env.APP_URL || 'https://nexus-scanner.com'}/dashboard" 
               style="display: inline-block; background: #dc2626; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: bold;">
              View Details & Fix
            </a>
          </div>
        </div>
      </div>
    `;

    try {
      await this.mailer.sendMail({
        from: this.from,
        to: user.email,
        subject,
        html,
        priority: 'high'
      });
      logger.logInfo('Critical vulnerability alert sent', { userId: user.id, vulnId: vulnerability.id });
    } catch (err) {
      logger.logError(err, { context: 'Send critical alert', userId: user.id });
    }
  }

  /**
   * Rapport hebdomadaire
   */
  async sendWeeklyReport(user, stats) {
    if (!this.enabled) return;

    const subject = 'Your Weekly Security Report';
    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #6366F1, #8B5CF6); padding: 30px; text-align: center;">
          <h1 style="color: white; margin: 0;">📊 Weekly Security Report</h1>
        </div>
        
        <div style="padding: 30px; background: #f8f9fa;">
          <p>Hi ${user.name},</p>
          <p>Here's your security summary for the past week:</p>
          
          <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3>This Week</h3>
            <ul style="list-style: none; padding: 0;">
              <li style="padding: 10px; border-bottom: 1px solid #e2e8f0;">✅ ${stats.scans_completed || 0} scans completed</li>
              <li style="padding: 10px; border-bottom: 1px solid #e2e8f0;">🔍 ${stats.total_vulns || 0} vulnerabilities found</li>
              <li style="padding: 10px; border-bottom: 1px solid #e2e8f0;">🛠️ ${stats.fixed_vulns || 0} vulnerabilities fixed</li>
              <li style="padding: 10px;">📈 Average security score: ${stats.avg_score || 0}/1000</li>
            </ul>
          </div>
          
          <div style="text-align: center; margin-top: 30px;">
            <a href="${process.env.APP_URL || 'https://nexus-scanner.com'}/dashboard" 
               style="display: inline-block; background: #6366F1; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px;">
              View Dashboard
            </a>
          </div>
        </div>
      </div>
    `;

    try {
      await this.mailer.sendMail({
        from: this.from,
        to: user.email,
        subject,
        html
      });
    } catch (err) {
      logger.logError(err, { context: 'Send weekly report', userId: user.id });
    }
  }
}

module.exports = new EmailNotificationService();
