/**
 * XSS Scanner Alternative - DOM-focused
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class XSSScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
    this.payloads = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '"><script>alert(1)</script>',
      "'><script>alert(1)</script>",
      '<svg/onload=alert(1)>',
      '"><img src=x onerror=alert(1)>'
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting XSS scan (alt)', { url });
      const urlObj = new URL(url);
      const params = [];
      urlObj.searchParams.forEach((_, k) => params.push(k));

      for (const param of params.slice(0, 6)) {
        for (const payload of this.payloads.slice(0, 4)) {
          try {
            const t = new URL(url);
            t.searchParams.set(param, payload);
            const resp = await this.httpClient.get(t.toString(), { timeout: 8000 });
            const body = typeof resp.data === 'string' ? resp.data : '';

            if (body.includes(payload) || (body.includes('<script>') && body.includes('alert'))) {
              findings.push({
                severity: 'high',
                category: 'xss',
                type: 'reflected_xss',
                title: `Reflected XSS in '${param}'`,
                description: `XSS payload is reflected unsanitized in parameter '${param}'.`,
                parameter: param,
                payload,
                evidence: { url: t.toString() },
                cvss_score: 7.3,
                confidence: 'high',
                remediation_text: 'HTML-encode all output. Implement CSP. Use safe templating.',
                remediation_effort_hours: 4,
                owasp_category: 'A03:2021 – Injection',
                cwe_id: 'CWE-79'
              });
              break;
            }
          } catch (e) {}
          await this.sleep(150);
        }
      }
    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}
module.exports = XSSScanner;
