/**
 * ALERT SYSTEM
 * Real-time security alerts via WebSocket, Email, Slack, PagerDuty
 */

const { EventEmitter } = require('events');
const { logger } = require('../utils/error-handler');

class AlertSystem extends EventEmitter {
  constructor() {
    super();
    this.alertRules = this.loadAlertRules();
    this.channels = {
      websocket: null,
      email: null,
      slack: null,
      pagerduty: null
    };
  }

  loadAlertRules() {
    return {
      criticalVulnerability: {
        condition: (vuln) => vuln.severity === 'critical',
        priority: 'P0',
        channels: ['websocket', 'email', 'slack', 'pagerduty'],
        message: (vuln) => `🚨 CRITICAL: ${vuln.title} detected on ${vuln.url}`,
        escalation: 'immediate'
      },
      highSeverityWithExploit: {
        condition: (vuln) => vuln.severity === 'high' && vuln.knownExploits > 0,
        priority: 'P1',
        channels: ['websocket', 'email', 'slack'],
        message: (vuln) => `⚠️ HIGH: ${vuln.title} with ${vuln.knownExploits} known exploits`,
        escalation: '15 minutes'
      },
      complianceViolation: {
        condition: (scan) => scan.complianceViolations && scan.complianceViolations.length > 0,
        priority: 'P1',
        channels: ['websocket', 'email'],
        message: (scan) => `📋 COMPLIANCE: Violations detected - ${scan.complianceViolations.join(', ')}`,
        escalation: '1 hour'
      },
      scoreDropped: {
        condition: (current, previous) => previous && (previous.security_score - current.security_score) > 100,
        priority: 'P2',
        channels: ['websocket', 'email'],
        message: (current, previous) => `📉 SCORE DROP: Security score decreased from ${previous.security_score} to ${current.security_score}`,
        escalation: '4 hours'
      },
      scheduledScanFailed: {
        condition: (scan) => scan.scan_type === 'scheduled' && scan.status === 'failed',
        priority: 'P2',
        channels: ['websocket', 'email'],
        message: (scan) => `⏰ SCAN FAILED: Scheduled scan for ${scan.domain_url} failed`,
        escalation: 'next business day'
      }
    };
  }

  /**
   * Set alert channels
   */
  setChannels(channels) {
    Object.assign(this.channels, channels);
  }

  /**
   * Process a vulnerability and trigger alerts
   */
  async processVulnerability(vuln, enriched) {
    const triggered = [];

    // Check each alert rule
    for (const [ruleName, rule] of Object.entries(this.alertRules)) {
      if (rule.condition(enriched || vuln)) {
        const alert = {
          id: `alert_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          ruleName,
          priority: rule.priority,
          message: rule.message(enriched || vuln),
          vulnerability: {
            id: vuln.id,
            title: vuln.title,
            severity: vuln.severity,
            category: vuln.category,
            cvss_score: vuln.cvss_score
          },
          businessImpact: enriched?.businessImpact,
          escalation: rule.escalation,
          timestamp: new Date()
        };

        // Send to configured channels
        await this.sendAlert(alert, rule.channels);
        triggered.push(alert);
      }
    }

    return triggered;
  }

  /**
   * Send alert to specified channels
   */
  async sendAlert(alert, channels) {
    const promises = [];

    for (const channel of channels) {
      if (this.channels[channel]) {
        promises.push(this.sendToChannel(channel, alert));
      }
    }

    await Promise.allSettled(promises);
    this.emit('alert_sent', alert);
    logger.logInfo('Alert sent', { alertId: alert.id, channels, priority: alert.priority });
  }

  async sendToChannel(channel, alert) {
    try {
      switch (channel) {
        case 'websocket':
          return this.sendWebSocket(alert);
        case 'email':
          return this.sendEmail(alert);
        case 'slack':
          return this.sendSlack(alert);
        case 'pagerduty':
          return this.sendPagerDuty(alert);
        default:
          logger.logWarning('Unknown alert channel', { channel });
      }
    } catch (err) {
      logger.logError(err, { context: `send${channel}Alert`, alertId: alert.id });
    }
  }

  sendWebSocket(alert) {
    if (!this.channels.websocket) return;
    
    // Send to all connected admins
    this.channels.websocket.broadcast({
      type: 'security_alert',
      alert
    });
  }

  async sendEmail(alert) {
    if (!this.channels.email) return;

    const subject = `${alert.priority} Alert: ${alert.vulnerability.title}`;
    const html = `
      <h2 style="color: ${alert.priority === 'P0' ? '#DC2626' : '#F59E0B'}">
        ${alert.message}
      </h2>
      
      <h3>Vulnerability Details</h3>
      <ul>
        <li><strong>Severity:</strong> ${alert.vulnerability.severity.toUpperCase()}</li>
        <li><strong>Category:</strong> ${alert.vulnerability.category}</li>
        <li><strong>CVSS Score:</strong> ${alert.vulnerability.cvss_score}</li>
      </ul>

      ${alert.businessImpact ? `
        <h3>Business Impact</h3>
        <ul>
          <li><strong>Estimated Cost:</strong> ${alert.businessImpact.estimatedCost}</li>
          <li><strong>Exploitation Speed:</strong> ${alert.businessImpact.exploitationSpeed}</li>
          <li><strong>Compliance Violations:</strong> ${alert.businessImpact.complianceViolations?.join(', ')}</li>
        </ul>
      ` : ''}

      <p><strong>Priority:</strong> ${alert.priority} - ${alert.escalation}</p>
      <p><a href="${process.env.APP_URL || 'https://nexus.local'}/dashboard">View in Dashboard</a></p>
    `;

    await this.channels.email.send({
      to: alert.recipientEmail || process.env.ADMIN_EMAIL,
      subject,
      html
    });
  }

  async sendSlack(alert) {
    if (!this.channels.slack) return;

    const color = alert.priority === 'P0' ? 'danger' : alert.priority === 'P1' ? 'warning' : 'good';
    
    await this.channels.slack.send({
      text: alert.message,
      attachments: [{
        color,
        fields: [
          { title: 'Severity', value: alert.vulnerability.severity, short: true },
          { title: 'CVSS', value: alert.vulnerability.cvss_score.toString(), short: true },
          { title: 'Category', value: alert.vulnerability.category },
          ...(alert.businessImpact ? [
            { title: 'Est. Cost', value: alert.businessImpact.estimatedCost, short: true },
            { title: 'Exploit Speed', value: alert.businessImpact.exploitationSpeed, short: true }
          ] : [])
        ],
        footer: 'NEXUS Security Scanner',
        ts: Math.floor(Date.now() / 1000)
      }]
    });
  }

  async sendPagerDuty(alert) {
    if (!this.channels.pagerduty) return;

    await this.channels.pagerduty.trigger({
      routing_key: process.env.PAGERDUTY_KEY,
      event_action: 'trigger',
      dedup_key: alert.id,
      payload: {
        summary: alert.message,
        severity: alert.priority === 'P0' ? 'critical' : alert.priority === 'P1' ? 'error' : 'warning',
        source: 'NEXUS Security Scanner',
        custom_details: {
          vulnerability: alert.vulnerability,
          businessImpact: alert.businessImpact,
          escalation: alert.escalation
        }
      }
    });
  }

  /**
   * Get alert history
   */
  getAlertHistory(userId, limit = 50) {
    const db = require('../config/database');
    return db.prepare(`
      SELECT a.*, v.title as vuln_title, v.severity
      FROM alerts a
      JOIN vulnerabilities v ON a.vulnerability_id = v.id
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      ORDER BY a.created_at DESC
      LIMIT ?
    `).all(userId, limit);
  }

  /**
   * Configure alert preferences
   */
  setPreferences(userId, preferences) {
    const db = require('../config/database');
    
    // Store as JSON
    db.prepare(`
      INSERT OR REPLACE INTO user_alert_preferences (user_id, preferences, updated_at)
      VALUES (?, ?, ?)
    `).run(userId, JSON.stringify(preferences), Math.floor(Date.now() / 1000));

    logger.logInfo('Alert preferences updated', { userId });
  }

  getPreferences(userId) {
    const db = require('../config/database');
    const row = db.prepare('SELECT preferences FROM user_alert_preferences WHERE user_id = ?').get(userId);
    return row ? JSON.parse(row.preferences) : this.getDefaultPreferences();
  }

  getDefaultPreferences() {
    return {
      channels: {
        email: true,
        websocket: true,
        slack: false,
        pagerduty: false
      },
      thresholds: {
        critical: 'all',
        high: 'all',
        medium: 'daily_digest',
        low: 'weekly_digest',
        info: 'never'
      },
      schedule: {
        quietHours: { enabled: false, start: '22:00', end: '08:00' },
        weekends: { enabled: false }
      }
    };
  }
}

const alertSystem = new AlertSystem();
module.exports = alertSystem;
