/**
 * Continuous Security Monitoring
 * Real-time monitoring and anomaly detection
 */

const db = require('../config/database');
const LegendaryScanner = require('./legendary-scanner');
const integrations = require('./integrations');

class ContinuousMonitoring {
  constructor() {
    this.monitoringIntervals = new Map();
    this.anomalyThresholds = {
      security_score_drop: 10, // Alert if score drops by 10+
      new_critical_vulns: 1,    // Alert on any new critical
      failed_scans: 3,          // Alert after 3 failed scans
      response_time_spike: 2.0  // Alert if response time 2x normal
    };
  }

  startMonitoring(domainId, frequency = 'daily') {
    const intervals = {
      'hourly': 60 * 60 * 1000,
      'daily': 24 * 60 * 60 * 1000,
      'weekly': 7 * 24 * 60 * 60 * 1000
    };

    const interval = intervals[frequency] || intervals.daily;

    console.log(`📡 Starting continuous monitoring for domain ${domainId} (${frequency})`);

    // Initial scan
    this.performMonitoringScan(domainId);

    // Schedule recurring scans
    const intervalId = setInterval(() => {
      this.performMonitoringScan(domainId);
    }, interval);

    this.monitoringIntervals.set(domainId, {
      intervalId,
      frequency,
      startedAt: new Date()
    });

    // Save monitoring config
    db.prepare(`
      INSERT OR REPLACE INTO monitoring_config (domain_id, frequency, enabled, started_at)
      VALUES (?, ?, 1, ?)
    `).run(domainId, frequency, new Date().toISOString());
  }

  stopMonitoring(domainId) {
    const monitoring = this.monitoringIntervals.get(domainId);
    
    if (monitoring) {
      clearInterval(monitoring.intervalId);
      this.monitoringIntervals.delete(domainId);
      
      db.prepare('UPDATE monitoring_config SET enabled = 0 WHERE domain_id = ?').run(domainId);
      
      console.log(`🛑 Stopped monitoring for domain ${domainId}`);
      return true;
    }
    
    return false;
  }

  async performMonitoringScan(domainId) {
    console.log(`🔍 Performing monitoring scan for domain ${domainId}`);

    try {
      // Create scan entry
      const result = db.prepare(`
        INSERT INTO scans (domain_id, scan_type, status, progress)
        VALUES (?, 'monitoring', 'pending', 0)
      `).run(domainId);

      const scanId = result.lastInsertRowid;

      // Get baseline metrics
      const baseline = this.getBaseline(domainId);

      // Perform scan
      const scanner = new LegendaryScanner(domainId, scanId);
      const scanResults = await scanner.performLegendaryScan();

      // Analyze changes
      const changes = this.detectChanges(domainId, scanResults, baseline);

      // Check for anomalies
      const anomalies = this.detectAnomalies(changes);

      // Alert if anomalies found
      if (anomalies.length > 0) {
        await this.sendAnomalyAlerts(domainId, anomalies, changes);
      }

      // Update baseline
      this.updateBaseline(domainId, scanResults);

      console.log(`✅ Monitoring scan completed for domain ${domainId}`);

      return {scanId, changes, anomalies};

    } catch (error) {
      console.error(`❌ Monitoring scan failed for domain ${domainId}:`, error);
      
      // Track failed scans
      this.trackFailedScan(domainId);
      
      throw error;
    }
  }

  getBaseline(domainId) {
    const latestScan = db.prepare(`
      SELECT * FROM scans 
      WHERE domain_id = ? AND status = 'completed'
      ORDER BY completed_at DESC 
      LIMIT 1
    `).get(domainId);

    if (!latestScan) {
      return {
        security_score: 100,
        vulnerabilities_count: 0,
        critical_count: 0,
        high_count: 0,
        risk_exposure_eur: 0
      };
    }

    const vulnCounts = db.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high
      FROM vulnerabilities
      WHERE scan_id = ? AND status = 'open'
    `).get(latestScan.id);

    return {
      security_score: latestScan.security_score,
      vulnerabilities_count: vulnCounts.total,
      critical_count: vulnCounts.critical,
      high_count: vulnCounts.high,
      risk_exposure_eur: latestScan.risk_exposure_eur || 0
    };
  }

  detectChanges(domainId, currentScan, baseline) {
    const currentVulns = db.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high
      FROM vulnerabilities
      WHERE scan_id = ? AND status = 'open'
    `).get(currentScan.scan.id);

    return {
      security_score_delta: currentScan.score - baseline.security_score,
      vulnerabilities_delta: currentVulns.total - baseline.vulnerabilities_count,
      critical_delta: currentVulns.critical - baseline.critical_count,
      high_delta: currentVulns.high - baseline.high_count,
      risk_exposure_delta: (currentScan.riskMetrics?.total_risk_exposure_eur || 0) - baseline.risk_exposure_eur,
      new_vulnerabilities: this.findNewVulnerabilities(domainId, currentScan.scan.id),
      fixed_vulnerabilities: this.findFixedVulnerabilities(domainId, baseline)
    };
  }

  findNewVulnerabilities(domainId, currentScanId) {
    return db.prepare(`
      SELECT v.* FROM vulnerabilities v
      WHERE v.scan_id = ? 
      AND v.status = 'open'
      AND NOT EXISTS (
        SELECT 1 FROM vulnerabilities v2
        JOIN scans s2 ON v2.scan_id = s2.id
        WHERE s2.domain_id = ?
        AND s2.id != ?
        AND v2.title = v.title
        AND v2.category = v.category
      )
      ORDER BY v.severity DESC
    `).all(currentScanId, domainId, currentScanId);
  }

  findFixedVulnerabilities(domainId, baseline) {
    // Simplified: compare with previous scan
    return db.prepare(`
      SELECT COUNT(*) as count
      FROM vulnerabilities v
      WHERE v.domain_id = ?
      AND v.status = 'fixed'
      AND datetime(v.fixed_at) > datetime('now', '-1 day')
    `).get(domainId).count || 0;
  }

  detectAnomalies(changes) {
    const anomalies = [];

    // Security score drop
    if (changes.security_score_delta < -this.anomalyThresholds.security_score_drop) {
      anomalies.push({
        type: 'security_degradation',
        severity: 'high',
        message: `Security score dropped by ${Math.abs(changes.security_score_delta)} points`,
        delta: changes.security_score_delta
      });
    }

    // New critical vulnerabilities
    if (changes.critical_delta > 0) {
      anomalies.push({
        type: 'new_critical_vulnerabilities',
        severity: 'critical',
        message: `${changes.critical_delta} new critical vulnerabilities detected`,
        count: changes.critical_delta,
        vulnerabilities: changes.new_vulnerabilities.filter(v => v.severity === 'critical')
      });
    }

    // Significant risk increase
    if (changes.risk_exposure_delta > 500000) { // 500K EUR
      anomalies.push({
        type: 'risk_increase',
        severity: 'high',
        message: `Risk exposure increased by €${Math.round(changes.risk_exposure_delta).toLocaleString()}`,
        delta: changes.risk_exposure_delta
      });
    }

    // Mass vulnerability discovery
    if (changes.vulnerabilities_delta > 10) {
      anomalies.push({
        type: 'mass_vulnerability_discovery',
        severity: 'medium',
        message: `${changes.vulnerabilities_delta} new vulnerabilities discovered`,
        count: changes.vulnerabilities_delta
      });
    }

    return anomalies;
  }

  async sendAnomalyAlerts(domainId, anomalies, changes) {
    const domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(domainId);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(domain.user_id);

    console.log(`🚨 Sending ${anomalies.length} anomaly alerts for domain ${domain.url}`);

    // Create alerts in database
    anomalies.forEach(anomaly => {
      db.prepare(`
        INSERT INTO alerts (domain_id, type, severity, message, metadata, is_read)
        VALUES (?, ?, ?, ?, ?, 0)
      `).run(
        domainId,
        anomaly.type,
        anomaly.severity,
        anomaly.message,
        JSON.stringify(anomaly)
      );
    });

    // Send notifications
    const criticalAnomalies = anomalies.filter(a => a.severity === 'critical');

    if (criticalAnomalies.length > 0 && user.email) {
      const emailContent = this.formatAnomalyEmail(domain, criticalAnomalies, changes);
      await integrations.sendEmailAlert(user.email, emailContent, changes);
    }

    // Slack notification
    await integrations.sendSlackNotification({
      domain_url: domain.url,
      anomalies: anomalies.length,
      critical_count: criticalAnomalies.length
    }, changes);
  }

  formatAnomalyEmail(domain, anomalies, changes) {
    return {
      subject: `🚨 Security Alert: ${anomalies.length} Anomalies Detected - ${domain.url}`,
      body: `
Critical security anomalies detected on ${domain.url}:

${anomalies.map((a, i) => `${i + 1}. ${a.message}`).join('\n')}

Changes Detected:
- Security Score: ${changes.security_score_delta > 0 ? '+' : ''}${changes.security_score_delta}
- New Vulnerabilities: ${changes.vulnerabilities_delta}
- Risk Exposure: €${Math.round(Math.abs(changes.risk_exposure_delta)).toLocaleString()}

Please review immediately in the NEXUS dashboard.
      `
    };
  }

  updateBaseline(domainId, scanResults) {
    // Baseline is automatically the latest completed scan
    // No specific action needed - getBaseline() always fetches latest
  }

  trackFailedScan(domainId) {
    const recentFailures = db.prepare(`
      SELECT COUNT(*) as count
      FROM scans
      WHERE domain_id = ?
      AND status = 'failed'
      AND datetime(started_at) > datetime('now', '-24 hours')
    `).get(domainId).count;

    if (recentFailures >= this.anomalyThresholds.failed_scans) {
      // Alert on repeated failures
      db.prepare(`
        INSERT INTO alerts (domain_id, type, severity, message, is_read)
        VALUES (?, 'scan_failures', 'high', ?, 0)
      `).run(
        domainId,
        `${recentFailures} scan failures in last 24 hours`
      );
    }
  }

  getMonitoringStatus(domainId) {
    const config = db.prepare('SELECT * FROM monitoring_config WHERE domain_id = ?').get(domainId);
    const monitoring = this.monitoringIntervals.get(domainId);

    return {
      enabled: config?.enabled || false,
      frequency: config?.frequency,
      started_at: config?.started_at,
      active_in_memory: !!monitoring,
      next_scan: monitoring ? new Date(Date.now() + 
        (monitoring.frequency === 'hourly' ? 3600000 : 
         monitoring.frequency === 'daily' ? 86400000 : 604800000)) : null
    };
  }

  async getAlerts(domainId, unreadOnly = false) {
    let query = 'SELECT * FROM alerts WHERE domain_id = ?';
    if (unreadOnly) {
      query += ' AND is_read = 0';
    }
    query += ' ORDER BY created_at DESC LIMIT 50';

    return db.prepare(query).all(domainId);
  }

  markAlertRead(alertId) {
    db.prepare('UPDATE alerts SET is_read = 1 WHERE id = ?').run(alertId);
  }
}

module.exports = new ContinuousMonitoring();
