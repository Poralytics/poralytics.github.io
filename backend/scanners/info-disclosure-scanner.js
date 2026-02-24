/**
 * Information Disclosure Scanner
 * Checks for sensitive data exposure
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class InfoDisclosureScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });

    this.sensitiveFiles = [
      { path: '/.env', severity: 'critical', desc: 'Environment file with secrets' },
      { path: '/.git/config', severity: 'high', desc: 'Git config file' },
      { path: '/.git/HEAD', severity: 'high', desc: 'Git HEAD file' },
      { path: '/config.php', severity: 'high', desc: 'PHP config file' },
      { path: '/config.js', severity: 'high', desc: 'JS config file' },
      { path: '/wp-config.php', severity: 'critical', desc: 'WordPress config with DB credentials' },
      { path: '/web.config', severity: 'high', desc: 'IIS config file' },
      { path: '/phpinfo.php', severity: 'medium', desc: 'PHP info disclosure' },
      { path: '/server-status', severity: 'medium', desc: 'Apache server status' },
      { path: '/api/v1/config', severity: 'high', desc: 'API config endpoint' },
      { path: '/actuator', severity: 'high', desc: 'Spring Boot actuator' },
      { path: '/actuator/env', severity: 'critical', desc: 'Spring Boot env with secrets' },
      { path: '/api-docs', severity: 'low', desc: 'API documentation' },
      { path: '/swagger-ui.html', severity: 'low', desc: 'Swagger UI' },
      { path: '/swagger.json', severity: 'low', desc: 'Swagger spec' },
      { path: '/robots.txt', severity: 'info', desc: 'Robots.txt may reveal paths' },
      { path: '/sitemap.xml', severity: 'info', desc: 'Sitemap may reveal structure' },
      { path: '/package.json', severity: 'medium', desc: 'Node.js package file' },
      { path: '/composer.json', severity: 'medium', desc: 'PHP composer file' },
      { path: '/.htaccess', severity: 'medium', desc: 'Apache htaccess' },
      { path: '/backup.sql', severity: 'critical', desc: 'Database backup' },
      { path: '/dump.sql', severity: 'critical', desc: 'Database dump' },
      { path: '/.DS_Store', severity: 'low', desc: 'MacOS directory listing' }
    ];

    this.sensitivePatterns = [
      { pattern: /password\s*=\s*["']?[^'"\s]{4,}/i, name: 'Password in response', severity: 'critical' },
      { pattern: /api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9]{16,}/i, name: 'API key exposure', severity: 'critical' },
      { pattern: /secret\s*[:=]\s*["']?[A-Za-z0-9]{8,}/i, name: 'Secret key exposure', severity: 'critical' },
      { pattern: /aws_access_key_id\s*[:=]\s*AKIA[0-9A-Z]{16}/i, name: 'AWS Access Key', severity: 'critical' },
      { pattern: /sk_live_[A-Za-z0-9]{24,}/i, name: 'Stripe Live Secret Key', severity: 'critical' },
      { pattern: /-----BEGIN [A-Z]+ PRIVATE KEY-----/, name: 'Private key in response', severity: 'critical' },
      { pattern: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, name: 'JWT token exposed', severity: 'high' },
      { pattern: /mysql:\/\/[^@]+@[^/]+\/\w+/i, name: 'Database connection string', severity: 'critical' },
      { pattern: /Exception|Stack trace|at java\.|at System\./i, name: 'Stack trace disclosure', severity: 'medium' },
      { pattern: /SQL syntax|mysql_fetch|ORA-\d{5}/i, name: 'Database error disclosure', severity: 'medium' }
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting Information Disclosure scan', { url });
      const base = new URL(url).origin;

      // 1. Check for sensitive files
      const fileChecks = this.sensitiveFiles.map(async (file) => {
        if (file.severity === 'info') return null; // Skip info level for speed
        try {
          const resp = await this.httpClient.get(base + file.path, { timeout: 5000 });
          if (resp.status === 200 && resp.data && typeof resp.data === 'string' && resp.data.length > 10) {
            return {
              severity: file.severity,
              category: 'information_disclosure',
              type: 'sensitive_file_exposed',
              title: `Sensitive File Accessible: ${file.path}`,
              description: `${file.desc} is publicly accessible.`,
              evidence: {
                url: base + file.path,
                status: resp.status,
                size: resp.data.length,
                preview: resp.data.substring(0, 100)
              },
              cvss_score: file.severity === 'critical' ? 9.8 : file.severity === 'high' ? 7.5 : 5.3,
              confidence: 'high',
              remediation_text: `Restrict access to ${file.path}. Remove from public web root. Add to .gitignore.`,
              remediation_effort_hours: 1,
              owasp_category: 'A02:2021 – Cryptographic Failures',
              cwe_id: 'CWE-538'
            };
          }
        } catch (e) {}
        return null;
      });

      const fileResults = await Promise.all(fileChecks);
      findings.push(...fileResults.filter(Boolean));

      // 2. Check main page for sensitive patterns
      try {
        const mainResp = await this.httpClient.get(url, { timeout: 8000 });
        if (mainResp.data && typeof mainResp.data === 'string') {
          for (const check of this.sensitivePatterns) {
            if (check.pattern.test(mainResp.data)) {
              findings.push({
                severity: check.severity,
                category: 'information_disclosure',
                type: 'sensitive_data_in_response',
                title: `Sensitive Data Exposure: ${check.name}`,
                description: `The application response contains ${check.name} which may expose sensitive information.`,
                evidence: {
                  url,
                  pattern: check.pattern.toString().substring(0, 50)
                },
                cvss_score: check.severity === 'critical' ? 9.1 : 6.5,
                confidence: 'medium',
                remediation_text: 'Remove sensitive data from API responses. Implement proper secret management.',
                remediation_effort_hours: 3,
                owasp_category: 'A02:2021 – Cryptographic Failures',
                cwe_id: 'CWE-200'
              });
            }
          }
        }
      } catch (e) {}

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'Info disclosure scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}

module.exports = InfoDisclosureScanner;
