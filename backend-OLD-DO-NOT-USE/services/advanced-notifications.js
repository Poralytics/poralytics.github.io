/**
 * ADVANCED PUSH NOTIFICATION SYSTEM
 * 
 * UPGRADE: Notifications push multi-canal
 * 
 * Features:
 * - Web push notifications
 * - Email notifications
 * - Slack/Discord webhooks
 * - SMS (Twilio integration ready)
 * - Priority-based delivery
 * - Delivery confirmation
 * - Notification preferences per user
 */

const db = require('../config/database');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const crypto = require('crypto');

class AdvancedNotificationSystem {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    this.channels = {
      web: true,       // Always available
      email: false,    // Requires SMTP config
      slack: false,    // Requires webhook
      discord: false,  // Requires webhook
      sms: false       // Requires Twilio
    };

    this.priorities = {
      low: { retries: 0, delay: 0 },
      normal: { retries: 1, delay: 5000 },
      high: { retries: 2, delay: 1000 },
      critical: { retries: 3, delay: 0 }
    };

    this.checkAvailableChannels();
  }

  /**
   * Check which notification channels are available
   */
  checkAvailableChannels() {
    // Check email
    if (process.env.SMTP_HOST && process.env.SMTP_USER) {
      this.channels.email = true;
      console.log('✅ Email notifications available');
    }

    // Check Slack
    if (process.env.SLACK_WEBHOOK_URL) {
      this.channels.slack = true;
      console.log('✅ Slack notifications available');
    }

    // Check Discord
    if (process.env.DISCORD_WEBHOOK_URL) {
      this.channels.discord = true;
      console.log('✅ Discord notifications available');
    }

    // Check Twilio SMS
    if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
      this.channels.sms = true;
      console.log('✅ SMS notifications available');
    }
  }

  /**
   * Send notification to user
   */
  async notify(userId, notification) {
    const {
      title,
      message,
      type = 'info',
      priority = 'normal',
      data = {},
      channels = ['web']
    } = notification;

    const notificationId = crypto.randomBytes(8).toString('hex');

    // Get user preferences
    const userPrefs = await this.getUserPreferences(userId);

    // Filter channels based on user preferences
    const enabledChannels = channels.filter(c => 
      userPrefs[`${c}_enabled`] !== false && this.channels[c]
    );

    const results = {
      notificationId,
      userId,
      deliveries: []
    };

    // Store in database
    try {
      db.prepare(`
        INSERT INTO notification_log (
          user_id, type, content, read, priority, created_at
        ) VALUES (?, ?, ?, 0, ?, ?)
      `).run(userId, type, JSON.stringify({ title, message, data }), priority, Math.floor(Date.now() / 1000));
    } catch (error) {
      console.error('Failed to log notification:', error.message);
    }

    // Deliver through each channel
    for (const channel of enabledChannels) {
      try {
        const delivered = await this.deliverToChannel(
          channel,
          userId,
          { title, message, type, priority, data }
        );

        results.deliveries.push({
          channel,
          status: delivered ? 'sent' : 'failed',
          timestamp: Date.now()
        });
      } catch (error) {
        results.deliveries.push({
          channel,
          status: 'error',
          error: error.message,
          timestamp: Date.now()
        });
      }
    }

    // Send to real-time dashboard if available
    try {
      const realtime = require('./realtime-dashboard').getInstance();
      realtime.sendToUser(userId, {
        type: 'notification',
        notification: {
          id: notificationId,
          title,
          message,
          type,
          priority,
          timestamp: Date.now()
        }
      });
    } catch (error) {
      // Real-time not available
    }

    return results;
  }

  /**
   * Deliver notification to specific channel
   */
  async deliverToChannel(channel, userId, notification) {
    switch (channel) {
      case 'web':
        return this.deliverWeb(userId, notification);
      case 'email':
        return this.deliverEmail(userId, notification);
      case 'slack':
        return this.deliverSlack(userId, notification);
      case 'discord':
        return this.deliverDiscord(userId, notification);
      case 'sms':
        return this.deliverSMS(userId, notification);
      default:
        return false;
    }
  }

  /**
   * Web notification (stored in database + real-time)
   */
  async deliverWeb(userId, notification) {
    // Already stored in database in notify() method
    // Real-time push already sent
    return true;
  }

  /**
   * Email notification
   */
  async deliverEmail(userId, notification) {
    if (!this.channels.email) {
      return false;
    }

    try {
      const nodemailer = require('nodemailer');
      
      const transporter = nodemailer.createTransporter({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT || 587,
        secure: false,
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD
        }
      });

      const user = db.prepare('SELECT email, name FROM users WHERE id = ?').get(userId);
      
      if (!user) {
        return false;
      }

      await transporter.sendMail({
        from: process.env.SMTP_FROM || 'NEXUS Security <noreply@nexus-security.com>',
        to: user.email,
        subject: `[NEXUS] ${notification.title}`,
        html: `
          <h2>${notification.title}</h2>
          <p>${notification.message}</p>
          <p style="color: #666; font-size: 12px;">
            Priority: ${notification.priority}<br>
            Type: ${notification.type}
          </p>
          <hr>
          <p style="color: #999; font-size: 11px;">
            Sent by NEXUS Security | Manage notification preferences in your dashboard
          </p>
        `
      });

      return true;
    } catch (error) {
      console.error('Email delivery failed:', error.message);
      return false;
    }
  }

  /**
   * Slack notification
   */
  async deliverSlack(userId, notification) {
    if (!this.channels.slack) {
      return false;
    }

    try {
      const axios = require('axios');
      
      const user = db.prepare('SELECT name, email FROM users WHERE id = ?').get(userId);

      const colorMap = {
        critical: '#dc3545',
        high: '#fd7e14',
        info: '#0dcaf0',
        success: '#198754'
      };

      await this.httpClient.post(process.env.SLACK_WEBHOOK_URL, {
        username: 'NEXUS Security',
        icon_emoji: ':shield:',
        attachments: [{
          color: colorMap[notification.priority] || colorMap.info,
          title: notification.title,
          text: notification.message,
          fields: [
            {
              title: 'User',
              value: user?.name || 'Unknown',
              short: true
            },
            {
              title: 'Priority',
              value: notification.priority.toUpperCase(),
              short: true
            }
          ],
          footer: 'NEXUS Security',
          ts: Math.floor(Date.now() / 1000)
        }]
      });

      return true;
    } catch (error) {
      console.error('Slack delivery failed:', error.message);
      return false;
    }
  }

  /**
   * Discord notification
   */
  async deliverDiscord(userId, notification) {
    if (!this.channels.discord) {
      return false;
    }

    try {
      const axios = require('axios');
      
      const user = db.prepare('SELECT name FROM users WHERE id = ?').get(userId);

      const colorMap = {
        critical: 14495300, // Red
        high: 16743680,     // Orange
        info: 3447003,      // Blue
        success: 5025616    // Green
      };

      await this.httpClient.post(process.env.DISCORD_WEBHOOK_URL, {
        username: 'NEXUS Security',
        avatar_url: 'https://example.com/nexus-logo.png',
        embeds: [{
          title: notification.title,
          description: notification.message,
          color: colorMap[notification.priority] || colorMap.info,
          fields: [
            {
              name: 'User',
              value: user?.name || 'Unknown',
              inline: true
            },
            {
              name: 'Priority',
              value: notification.priority.toUpperCase(),
              inline: true
            }
          ],
          timestamp: new Date().toISOString()
        }]
      });

      return true;
    } catch (error) {
      console.error('Discord delivery failed:', error.message);
      return false;
    }
  }

  /**
   * SMS notification
   */
  async deliverSMS(userId, notification) {
    if (!this.channels.sms) {
      return false;
    }

    try {
      const twilio = require('twilio');
      
      const client = twilio(
        process.env.TWILIO_ACCOUNT_SID,
        process.env.TWILIO_AUTH_TOKEN
      );

      const user = db.prepare('SELECT phone FROM users WHERE id = ?').get(userId);
      
      if (!user || !user.phone) {
        return false;
      }

      await client.messages.create({
        body: `[NEXUS] ${notification.title}: ${notification.message}`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: user.phone
      });

      return true;
    } catch (error) {
      console.error('SMS delivery failed:', error.message);
      return false;
    }
  }

  /**
   * Get user notification preferences
   */
  async getUserPreferences(userId) {
    try {
      const user = db.prepare('SELECT settings FROM users WHERE id = ?').get(userId);
      
      if (!user || !user.settings) {
        return this.getDefaultPreferences();
      }

      const settings = JSON.parse(user.settings);
      return settings.notifications || this.getDefaultPreferences();
    } catch (error) {
      return this.getDefaultPreferences();
    }
  }

  /**
   * Get default notification preferences
   */
  getDefaultPreferences() {
    return {
      web_enabled: true,
      email_enabled: true,
      slack_enabled: false,
      discord_enabled: false,
      sms_enabled: false,
      
      // Notification types
      security_alerts: true,
      scan_completed: true,
      vulnerability_found: true,
      compliance_updates: true,
      team_activity: false,
      marketing: false
    };
  }

  /**
   * Update user notification preferences
   */
  async updatePreferences(userId, preferences) {
    try {
      const user = db.prepare('SELECT settings FROM users WHERE id = ?').get(userId);
      const settings = user?.settings ? JSON.parse(user.settings) : {};
      
      settings.notifications = {
        ...this.getDefaultPreferences(),
        ...preferences
      };

      db.prepare('UPDATE users SET settings = ? WHERE id = ?')
        .run(JSON.stringify(settings), userId);

      return { success: true, preferences: settings.notifications };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  /**
   * Quick notification methods for common scenarios
   */
  async notifyCriticalVulnerability(userId, vulnerability) {
    return this.notify(userId, {
      title: '🚨 Critical Vulnerability Found',
      message: `${vulnerability.title} detected on ${vulnerability.affected_url}`,
      type: 'critical',
      priority: 'critical',
      data: { vulnerabilityId: vulnerability.id },
      channels: ['web', 'email', 'slack', 'sms']
    });
  }

  async notifyScanComplete(userId, scanId, results) {
    return this.notify(userId, {
      title: '✅ Security Scan Complete',
      message: `Found ${results.vulnerabilities} vulnerabilities. Security score: ${results.score}/1000`,
      type: 'success',
      priority: results.critical > 0 ? 'high' : 'normal',
      data: { scanId },
      channels: ['web', 'email']
    });
  }

  async notifyComplianceUpdate(userId, framework, status) {
    return this.notify(userId, {
      title: `📋 ${framework} Compliance Update`,
      message: `Compliance score: ${status.score}/100. ${status.issues} issues found.`,
      type: 'info',
      priority: status.score < 70 ? 'high' : 'normal',
      data: { framework, status },
      channels: ['web', 'email']
    });
  }

  /**
   * Get notification stats
   */
  getStats() {
    try {
      const stats = db.prepare(`
        SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN read = 1 THEN 1 ELSE 0 END) as read,
          SUM(CASE WHEN read = 0 THEN 1 ELSE 0 END) as unread,
          SUM(CASE WHEN priority = 'critical' THEN 1 ELSE 0 END) as critical
        FROM notification_log
        WHERE created_at > ?
      `).get(Math.floor(Date.now() / 1000) - 86400); // Last 24h

      return {
        availableChannels: Object.keys(this.channels).filter(c => this.channels[c]),
        last24Hours: stats || { total: 0, read: 0, unread: 0, critical: 0 }
      };
    } catch (error) {
      return {
        availableChannels: Object.keys(this.channels).filter(c => this.channels[c]),
        last24Hours: { total: 0, read: 0, unread: 0, critical: 0 }
      };
    }
  }
}

module.exports = new AdvancedNotificationSystem();
