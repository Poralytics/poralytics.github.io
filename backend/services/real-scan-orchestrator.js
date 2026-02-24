/**
 * REAL SCAN ORCHESTRATOR
 * Coordinates all scanners and manages real scanning workflow
 */

const db = require('../config/database');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const realSQLScanner = require('../scanners/real-sql-scanner');
const realXSSScanner = require('../scanners/real-xss-scanner');
const csrfScanner = require('../scanners/csrf-scanner');
const corsScanner = require('../scanners/cors-scanner');
const clickjackingScanner = require('../scanners/clickjacking-scanner');
const EventEmitter = require('events');

class RealScanOrchestrator extends EventEmitter {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    super();
    this.activeScanners = new Map(); // scanId -> scanner instance
  }

  /**
   * Start a real scan
   */
  async startScan(scanId, domainId, userId, url) {
    try {
      console.log(`[Orchestrator] Starting REAL scan ${scanId} for ${url}`);

      // Update scan status
      db.prepare(`
        UPDATE scans 
        SET status = 'running', started_at = ?, progress = 0
        WHERE id = ?
      `).run(Math.floor(Date.now() / 1000), scanId);

      // Emit progress
      this.emit('progress', { scanId, progress: 0, phase: 'Initializing' });

      // Phase 1: SQL Injection Scan (0-20%)
      this.emit('progress', { scanId, progress: 5, phase: 'Testing SQL Injection' });
      const sqlResults = await realSQLScanner.scan(url);
      await this.saveScanResults(scanId, domainId, sqlResults.vulnerabilities);
      
      console.log(`[Orchestrator] SQL scan complete: ${sqlResults.vulnerabilities.length} vulns`);

      // Phase 2: XSS Scan (20-40%)
      this.emit('progress', { scanId, progress: 25, phase: 'Testing XSS' });
      const xssResults = await realXSSScanner.scan(url);
      await this.saveScanResults(scanId, domainId, xssResults.vulnerabilities);
      
      console.log(`[Orchestrator] XSS scan complete: ${xssResults.vulnerabilities.length} vulns`);

      // Phase 3: CSRF Scan (40-50%)
      this.emit('progress', { scanId, progress: 45, phase: 'Testing CSRF' });
      const csrfResults = await csrfScanner.scan(url);
      await this.saveScanResults(scanId, domainId, csrfResults.vulnerabilities);
      
      console.log(`[Orchestrator] CSRF scan complete: ${csrfResults.vulnerabilities.length} vulns`);

      // Phase 4: CORS Scan (50-60%)
      this.emit('progress', { scanId, progress: 55, phase: 'Testing CORS' });
      const corsResults = await corsScanner.scan(url);
      await this.saveScanResults(scanId, domainId, corsResults.vulnerabilities);
      
      console.log(`[Orchestrator] CORS scan complete: ${corsResults.vulnerabilities.length} vulns`);

      // Phase 5: Clickjacking Scan (60-70%)
      this.emit('progress', { scanId, progress: 65, phase: 'Testing Clickjacking' });
      const clickjackingResults = await clickjackingScanner.scan(url);
      await this.saveScanResults(scanId, domainId, clickjackingResults.vulnerabilities);
      
      console.log(`[Orchestrator] Clickjacking scan complete: ${clickjackingResults.vulnerabilities.length} vulns`);

      // Phase 6: Security Headers (70-85%)
      this.emit('progress', { scanId, progress: 75, phase: 'Checking Security Headers' });
      const headerResults = await this.scanSecurityHeaders(url);
      await this.saveScanResults(scanId, domainId, headerResults);

      // Phase 7: SSL/TLS (85-100%)
      this.emit('progress', { scanId, progress: 90, phase: 'Testing SSL/TLS' });
      const sslResults = await this.scanSSL(url);
      await this.saveScanResults(scanId, domainId, sslResults);

      // Calculate final stats
      const stats = await this.calculateStats(scanId);

      // Update scan as completed
      db.prepare(`
        UPDATE scans 
        SET status = 'completed', 
            completed_at = ?,
            duration = ? - started_at,
            progress = 100,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            total_vulns = ?
        WHERE id = ?
      `).run(
        Math.floor(Date.now() / 1000),
        Math.floor(Date.now() / 1000),
        stats.critical,
        stats.high,
        stats.medium,
        stats.low,
        stats.total,
        scanId
      );

      // Update domain security score
      const securityScore = this.calculateSecurityScore(stats);
      db.prepare(`
        UPDATE domains 
        SET security_score = ?, 
            risk_level = ?,
            last_scan_at = ?
        WHERE id = ?
      `).run(
        securityScore,
        this.getRiskLevel(securityScore),
        Math.floor(Date.now() / 1000),
        domainId
      );

      this.emit('progress', { scanId, progress: 100, phase: 'Completed' });
      this.emit('completed', { scanId, stats, securityScore });

      console.log(`[Orchestrator] Scan ${scanId} completed successfully`);

      return { success: true, stats, securityScore };

    } catch (error) {
      console.error(`[Orchestrator] Scan error:`, error);
      
      // Mark scan as failed
      db.prepare(`
        UPDATE scans 
        SET status = 'failed', 
            completed_at = ?,
            error_message = ?
        WHERE id = ?
      `).run(Math.floor(Date.now() / 1000), error.message, scanId);

      this.emit('failed', { scanId, error: error.message });

      return { success: false, error: error.message };
    }
  }

  /**
   * Save scan results to database
   */
  async saveScanResults(scanId, domainId, vulnerabilities) {
    for (const vuln of vulnerabilities) {
      try {
        db.prepare(`
          INSERT INTO vulnerabilities (
            scan_id, domain_id, severity, category, title, description,
            affected_url, cvss_score, status, discovered_at, evidence, remediation
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)
        `).run(
          scanId,
          domainId,
          vuln.severity,
          vuln.type || vuln.category || 'unknown',
          vuln.title,
          vuln.description,
          vuln.affected_url || '',
          vuln.cvss_score || 0,
          Math.floor(Date.now() / 1000),
          vuln.evidence || '',
          vuln.remediation || ''
        );
      } catch (error) {
        console.error('[Orchestrator] Error saving vulnerability:', error.message);
      }
    }
  }

  /**
   * Scan security headers
   */
  async scanSecurityHeaders(url) {
    const vulnerabilities = [];
    
    try {
      const axios = require('axios');
      const response = await this.httpClient.get(url, {
        timeout: 10000,
        validateStatus: () => true
      });

      const headers = response.headers;

      // Check for missing security headers
      const requiredHeaders = {
        'x-frame-options': {
          severity: 'medium',
          title: 'Missing X-Frame-Options Header',
          cvss: 5.3
        },
        'x-content-type-options': {
          severity: 'medium',
          title: 'Missing X-Content-Type-Options Header',
          cvss: 5.0
        },
        'strict-transport-security': {
          severity: 'high',
          title: 'Missing HSTS Header',
          cvss: 6.5
        },
        'content-security-policy': {
          severity: 'medium',
          title: 'Missing Content-Security-Policy Header',
          cvss: 5.5
        },
        'x-xss-protection': {
          severity: 'low',
          title: 'Missing X-XSS-Protection Header',
          cvss: 4.0
        }
      };

      for (const [header, config] of Object.entries(requiredHeaders)) {
        if (!headers[header] && !headers[header.toLowerCase()]) {
          vulnerabilities.push({
            type: 'security_headers',
            severity: config.severity,
            title: config.title,
            description: `The ${header} security header is not set, which may expose the application to certain attacks.`,
            affected_url: url,
            cvss_score: config.cvss,
            remediation: `Add the ${header} header to your web server configuration.`,
            evidence: 'Header not present in response'
          });
        }
      }

      // Check for information disclosure
      if (headers['server']) {
        vulnerabilities.push({
          type: 'info_disclosure',
          severity: 'low',
          title: 'Server Version Disclosure',
          description: 'The server version is exposed in the Server header.',
          affected_url: url,
          cvss_score: 3.5,
          remediation: 'Remove or obfuscate the Server header.',
          evidence: `Server: ${headers['server']}`
        });
      }

      if (headers['x-powered-by']) {
        vulnerabilities.push({
          type: 'info_disclosure',
          severity: 'low',
          title: 'Technology Stack Disclosure',
          description: 'The technology stack is exposed in the X-Powered-By header.',
          affected_url: url,
          cvss_score: 3.2,
          remediation: 'Remove the X-Powered-By header.',
          evidence: `X-Powered-By: ${headers['x-powered-by']}`
        });
      }

    } catch (error) {
      console.error('[Headers Scanner] Error:', error.message);
    }

    return vulnerabilities;
  }

  /**
   * Scan SSL/TLS configuration
   */
  async scanSSL(url) {
    const vulnerabilities = [];

    try {
      const urlObj = new URL(url);
      
      if (urlObj.protocol === 'http:') {
        vulnerabilities.push({
          type: 'ssl',
          severity: 'high',
          title: 'Unencrypted HTTP Connection',
          description: 'The website is accessible over unencrypted HTTP protocol.',
          affected_url: url,
          cvss_score: 7.4,
          remediation: 'Implement HTTPS with a valid SSL/TLS certificate and redirect all HTTP traffic to HTTPS.',
          evidence: 'URL uses http:// protocol'
        });
      } else if (urlObj.protocol === 'https:') {
        // Check certificate (basic check)
        const https = require('https');
        const checkCert = () => {
          return new Promise((resolve) => {
            const req = https.get(url, { rejectUnauthorized: false }, (res) => {
              const cert = res.socket.getPeerCertificate();
              resolve(cert);
            });
            req.on('error', () => resolve(null));
            req.end();
          });
        };

        const cert = await checkCert();
        
        if (!cert || cert.valid_to) {
          const validTo = new Date(cert.valid_to);
          const daysUntilExpiry = Math.floor((validTo - new Date()) / (1000 * 60 * 60 * 24));
          
          if (daysUntilExpiry < 30) {
            vulnerabilities.push({
              type: 'ssl',
              severity: daysUntilExpiry < 7 ? 'high' : 'medium',
              title: 'SSL Certificate Expiring Soon',
              description: `SSL certificate expires in ${daysUntilExpiry} days.`,
              affected_url: url,
              cvss_score: daysUntilExpiry < 7 ? 6.5 : 5.0,
              remediation: 'Renew your SSL certificate before it expires.',
              evidence: `Certificate expires: ${validTo.toISOString()}`
            });
          }
        }
      }

    } catch (error) {
      console.error('[SSL Scanner] Error:', error.message);
    }

    return vulnerabilities;
  }

  /**
   * Calculate statistics
   */
  async calculateStats(scanId) {
    const vulns = db.prepare(`
      SELECT severity, COUNT(*) as count
      FROM vulnerabilities
      WHERE scan_id = ?
      GROUP BY severity
    `).all(scanId);

    const stats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: 0
    };

    vulns.forEach(v => {
      stats[v.severity] = v.count;
      stats.total += v.count;
    });

    return stats;
  }

  /**
   * Calculate security score (0-1000)
   */
  calculateSecurityScore(stats) {
    let score = 1000;
    
    score -= stats.critical * 100;
    score -= stats.high * 30;
    score -= stats.medium * 10;
    score -= stats.low * 2;

    return Math.max(0, Math.min(1000, score));
  }

  /**
   * Get risk level from score
   */
  getRiskLevel(score) {
    if (score >= 900) return 'low';
    if (score >= 700) return 'medium';
    if (score >= 500) return 'high';
    return 'critical';
  }

  /**
   * Get scan progress
   */
  getScanProgress(scanId) {
    const scan = db.prepare('SELECT status, progress FROM scans WHERE id = ?').get(scanId);
    return scan;
  }
}

module.exports = new RealScanOrchestrator();
