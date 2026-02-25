/**
 * COMPLETE SCAN ORCHESTRATOR - PARALLEL v2.1
 * True parallel execution of ALL 23 scanners
 * Handles both class exports and instance exports
 */

const db = require('../config/database');
const EventEmitter = require('events');
const { CircuitBreaker, logger } = require('../utils/error-handler');

class CompleteScanOrchestrator extends EventEmitter {
  constructor() {
    super();
    this.activeScans = new Map();
    this.breaker = new CircuitBreaker({
      name: 'scan-orchestrator',
      failureThreshold: 5,
      timeout: 120000
    });

    // Load all scanners lazily to avoid startup failures
    this.scannerDefs = [
      { name: 'SQL Injection',       path: '../scanners/real-sql-scanner',          weight: 5, isInstance: true },
      { name: 'XSS',                 path: '../scanners/real-xss-scanner',           weight: 5, isInstance: true },
      { name: 'Advanced SQL',        path: '../scanners/advanced-sql-scanner',       weight: 4, isInstance: false },
      { name: 'SQL Injection Alt',   path: '../scanners/sql-injection-scanner',      weight: 3, isInstance: false },
      { name: 'XSS Alt',             path: '../scanners/xss-scanner',                weight: 3, isInstance: false },
      { name: 'CSRF',                path: '../scanners/csrf-scanner',               weight: 3, isInstance: false },
      { name: 'CORS',                path: '../scanners/cors-scanner',               weight: 3, isInstance: false },
      { name: 'Clickjacking',        path: '../scanners/clickjacking-scanner',       weight: 2, isInstance: false },
      { name: 'SSRF',                path: '../scanners/ssrf-scanner',               weight: 5, isInstance: false },
      { name: 'XXE',                 path: '../scanners/xxe-scanner',                weight: 4, isInstance: false },
      { name: 'Command Injection',   path: '../scanners/command-injection-scanner',  weight: 5, isInstance: false },
      { name: 'File Upload',         path: '../scanners/file-upload-scanner',        weight: 4, isInstance: false },
      { name: 'Open Redirect',       path: '../scanners/open-redirect-scanner',      weight: 3, isInstance: false },
      { name: 'Authentication',      path: '../scanners/authentication-scanner',     weight: 5, isInstance: false },
      { name: 'Access Control',      path: '../scanners/access-control-scanner',     weight: 5, isInstance: false },
      { name: 'Info Disclosure',     path: '../scanners/info-disclosure-scanner',    weight: 4, isInstance: false },
      { name: 'Crypto',              path: '../scanners/crypto-scanner',             weight: 4, isInstance: false },
      { name: 'API Security',        path: '../scanners/api-security-scanner',       weight: 4, isInstance: false },
      { name: 'Business Logic',      path: '../scanners/business-logic-scanner',     weight: 3, isInstance: false },
      { name: 'Components',          path: '../scanners/component-scanner',          weight: 3, isInstance: false },
      { name: 'Infrastructure',      path: '../scanners/infrastructure-scanner',     weight: 3, isInstance: false },
      { name: 'Headers',             path: '../scanners/headers-scanner',            weight: 3, isInstance: false },
      { name: 'SSL/TLS',             path: '../scanners/ssl-scanner',               weight: 4, isInstance: false }
    ];
  }

  /**
   * Resolve a scanner to a callable instance
   */
  resolveScanner(def) {
    try {
      const exported = require(def.path);
      if (def.isInstance) {
        // Already an instance (real-sql-scanner, real-xss-scanner)
        return exported;
      } else {
        // It's a class - instantiate it
        return new exported();
      }
    } catch (err) {
      logger.logError(err, { context: `Failed to load scanner: ${def.name}` });
      return null;
    }
  }

  /**
   * Start a full parallel scan
   */
  async startScan(scanId, domainId, userId, url) {
    try {
      logger.logInfo('Starting parallel scan', { scanId, url, scanners: this.scannerDefs.length });

      // Mark scan as running
      db.prepare(`UPDATE scans SET status = 'running', started_at = ?, progress = 0 WHERE id = ?`)
        .run(Math.floor(Date.now() / 1000), scanId);

      this.emit('progress', { scanId, progress: 0, phase: 'Starting 23 parallel scanners' });

      const totalWeight = this.scannerDefs.reduce((s, d) => s + d.weight, 0);
      let completedWeight = 0;
      const allVulnerabilities = [];

      // Build all scanner promises (true parallel)
      const scanPromises = this.scannerDefs.map(async (def) => {
        const scanner = this.resolveScanner(def);

        if (!scanner) {
          return { scanner: def.name, success: false, vulnerabilities: [], errors: ['Failed to load'] };
        }

        try {
          const result = await Promise.race([
            scanner.scan(url),
            new Promise((_, rej) => setTimeout(() => rej(new Error('Scanner timeout')), 120000))
          ]);

          // Normalize result
          let vulns = [];
          if (result && Array.isArray(result.vulnerabilities)) {
            vulns = result.vulnerabilities;
          } else if (result && Array.isArray(result)) {
            vulns = result;
          } else if (result && Array.isArray(result.findings)) {
            vulns = result.findings;
          }

          // Update progress
          completedWeight += def.weight;
          const progress = Math.min(99, Math.floor((completedWeight / totalWeight) * 100));
          this.emit('progress', { scanId, progress, phase: `Completed: ${def.name}` });

          // Save to DB immediately
          for (const vuln of vulns) {
            try {
              db.prepare(`
                INSERT INTO vulnerabilities (
                  scan_id, domain_id, severity, category, type, title, description,
                  parameter, payload, evidence, cvss_score, confidence,
                  remediation_text, remediation_effort_hours, owasp_category, cwe_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `).run(
                scanId, domainId,
                vuln.severity || 'medium',
                vuln.category || 'unknown',
                vuln.type || vuln.category || 'unknown',
                vuln.title || 'Unknown vulnerability',
                vuln.description || '',
                vuln.parameter || null,
                vuln.payload || null,
                JSON.stringify(vuln.evidence || {}),
                parseFloat(vuln.cvss_score) || 0,
                vuln.confidence || 'medium',
                vuln.remediation_text || '',
                parseInt(vuln.remediation_effort_hours) || 0,
                vuln.owasp_category || '',
                vuln.cwe_id || ''
              );
            } catch (dbErr) {
              logger.logError(dbErr, { context: 'Save vuln', scanId, scanner: def.name });
            }
          }

          return { scanner: def.name, success: true, vulnerabilities: vulns, errors: [] };

        } catch (err) {
          logger.logError(err, { context: `Scanner failed: ${def.name}`, scanId, url });
          completedWeight += def.weight;
          return { scanner: def.name, success: false, vulnerabilities: [], errors: [err.message] };
        }
      });

      // Wait for ALL scanners in parallel
      const settled = await Promise.allSettled(scanPromises);

      // Aggregate
      const results = settled.map(r => r.status === 'fulfilled' ? r.value : { success: false, vulnerabilities: [], errors: ['Promise rejected'] });

      // Calculate stats
      const stats = this.calculateStats(scanId);
      const score = this.calculateSecurityScore(stats);
      const now = Math.floor(Date.now() / 1000);

      const scanRow = db.prepare('SELECT started_at FROM scans WHERE id = ?').get(scanId);
      const duration = now - (scanRow?.started_at || now);

      // Final DB update
      db.prepare(`
        UPDATE scans SET
          status = 'completed', completed_at = ?, duration = ?, progress = 100,
          critical_count = ?, high_count = ?, medium_count = ?, low_count = ?,
          info_count = ?, total_vulns = ?
        WHERE id = ?
      `).run(now, duration, stats.critical, stats.high, stats.medium, stats.low, stats.info, stats.total, scanId);

      db.prepare(`
        UPDATE domains SET security_score = ?, risk_level = ?, last_scan_at = ? WHERE id = ?
      `).run(score, this.getRiskLevel(score), now, domainId);

      this.emit('progress', { scanId, progress: 100, phase: 'Scan completed' });
      this.emit('completed', { scanId, stats, securityScore: score, duration });

      logger.logInfo('Parallel scan completed', { scanId, total: stats.total, duration, score });

      return { success: true, stats, securityScore: score, duration };

    } catch (err) {
      logger.logError(err, { context: 'Orchestrator failed', scanId, url });

      try {
        db.prepare(`UPDATE scans SET status = 'failed', completed_at = ?, error_message = ? WHERE id = ?`)
          .run(Math.floor(Date.now() / 1000), err.message, scanId);
      } catch (dbErr) {
        logger.logError(dbErr, { context: 'Update failed scan', scanId });
      }

      this.emit('failed', { scanId, error: err.message });
      return { success: false, error: err.message };
    }
  }

  calculateStats(scanId) {
    const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    try {
      const rows = db.prepare(`
        SELECT severity, COUNT(*) as count FROM vulnerabilities WHERE scan_id = ? GROUP BY severity
      `).all(scanId);
      for (const r of rows) {
        const sev = (r.severity || '').toLowerCase();
        if (stats[sev] !== undefined) stats[sev] = r.count;
      }
      stats.total = stats.critical + stats.high + stats.medium + stats.low + stats.info;
    } catch (e) {
      logger.logError(e, { context: 'calculateStats', scanId });
    }
    return stats;
  }

  calculateSecurityScore(stats) {
    const score = 1000
      - (stats.critical * 200)
      - (stats.high * 100)
      - (stats.medium * 30)
      - (stats.low * 10)
      - (stats.info * 2);
    return Math.max(0, Math.min(1000, score));
  }

  getRiskLevel(score) {
    if (score >= 800) return 'low';
    if (score >= 600) return 'medium';
    if (score >= 400) return 'high';
    return 'critical';
  }
}

module.exports = new CompleteScanOrchestrator();
