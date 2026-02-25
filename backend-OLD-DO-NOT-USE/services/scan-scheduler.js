/**
 * SCAN SCHEDULER SERVICE
 * Automated recurring scans (daily, weekly, monthly)
 */

const db = require('../config/database');
const orchestrator = require('./complete-scan-orchestrator');
const { logger } = require('../utils/error-handler');

class ScanScheduler {
  constructor() {
    this.running = false;
    this.interval = null;
  }

  /**
   * Start the scheduler (polls every 5 minutes)
   */
  start() {
    if (this.running) return;
    this.running = true;
    logger.logInfo('Scan scheduler started');

    // Check immediately
    this.checkScheduledScans();

    // Then every 5 minutes
    this.interval = setInterval(() => {
      this.checkScheduledScans();
    }, 5 * 60 * 1000);
  }

  stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
    this.running = false;
    logger.logInfo('Scan scheduler stopped');
  }

  /**
   * Check for domains that need scheduled scans
   */
  async checkScheduledScans() {
    try {
      const domains = db.prepare(`
        SELECT d.*, u.plan
        FROM domains d
        JOIN users u ON d.user_id = u.id
        WHERE d.scan_schedule IS NOT NULL
      `).all();

      for (const domain of domains) {
        if (this.shouldScanNow(domain)) {
          await this.triggerScheduledScan(domain);
        }
      }
    } catch (err) {
      logger.logError(err, { context: 'checkScheduledScans' });
    }
  }

  /**
   * Determine if a domain should be scanned now
   */
  shouldScanNow(domain) {
    if (!domain.scan_schedule) return false;

    const now = Math.floor(Date.now() / 1000);
    const lastScan = domain.last_scan_at || 0;

    const schedules = {
      'hourly': 3600,
      'daily': 86400,
      'weekly': 604800,
      'monthly': 2592000
    };

    const interval = schedules[domain.scan_schedule];
    if (!interval) return false;

    // Check if enough time has passed since last scan
    return (now - lastScan) >= interval;
  }

  /**
   * Trigger a scheduled scan
   */
  async triggerScheduledScan(domain) {
    try {
      logger.logInfo('Triggering scheduled scan', { 
        domainId: domain.id, 
        url: domain.url,
        schedule: domain.scan_schedule 
      });

      // Create scan record
      const result = db.prepare(`
        INSERT INTO scans (
          domain_id, user_id, status, started_at, progress, scan_type
        ) VALUES (?, ?, 'pending', ?, 0, 'scheduled')
      `).run(domain.id, domain.user_id, Math.floor(Date.now() / 1000));

      // Update domain last_scan_at
      db.prepare('UPDATE domains SET last_scan_at = ? WHERE id = ?')
        .run(Math.floor(Date.now() / 1000), domain.id);

      logger.logInfo('Scheduled scan created', { scanId: result.lastInsertRowid });

    } catch (err) {
      logger.logError(err, { 
        context: 'triggerScheduledScan', 
        domainId: domain.id 
      });
    }
  }

  /**
   * Configure scan schedule for a domain
   */
  setSchedule(domainId, userId, schedule) {
    // Validate schedule
    const validSchedules = ['hourly', 'daily', 'weekly', 'monthly', null];
    if (!validSchedules.includes(schedule)) {
      throw new Error('Invalid schedule. Must be: hourly, daily, weekly, monthly, or null');
    }

    // Check user plan limits
    const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(userId);
    const planLimits = {
      free: null, // No automation
      pro: ['daily', 'weekly', 'monthly'],
      business: ['hourly', 'daily', 'weekly', 'monthly'],
      enterprise: ['hourly', 'daily', 'weekly', 'monthly']
    };

    if (schedule && !planLimits[user.plan]?.includes(schedule)) {
      throw new Error(`Schedule '${schedule}' not available for ${user.plan} plan. Upgrade to access.`);
    }

    // Update domain
    db.prepare('UPDATE domains SET scan_schedule = ? WHERE id = ? AND user_id = ?')
      .run(schedule, domainId, userId);

    logger.logInfo('Scan schedule updated', { domainId, schedule, userId });

    return { success: true, schedule };
  }

  /**
   * Get all scheduled scans status
   */
  getScheduledScans(userId) {
    return db.prepare(`
      SELECT d.id, d.url, d.name, d.scan_schedule, d.last_scan_at,
             COUNT(s.id) as total_scans,
             MAX(s.completed_at) as last_completed
      FROM domains d
      LEFT JOIN scans s ON d.id = s.domain_id AND s.scan_type = 'scheduled'
      WHERE d.user_id = ? AND d.scan_schedule IS NOT NULL
      GROUP BY d.id
      ORDER BY d.last_scan_at DESC
    `).all(userId);
  }
}

const scheduler = new ScanScheduler();
module.exports = scheduler;
