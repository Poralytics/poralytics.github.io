/**
 * CORS Scanner - Cross-Origin Resource Sharing misconfiguration
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class CORSScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 1 * 1024 * 1024 });
    this.testOrigins = [
      'https://evil.com',
      'null',
      'https://attacker.example.com'
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting CORS scan', { url });

      for (const origin of this.testOrigins) {
        try {
          const resp = await this.httpClient.get(url, {
            headers: { 'Origin': origin },
            timeout: 8000
          });

          const acao = resp.headers?.['access-control-allow-origin'];
          const acac = resp.headers?.['access-control-allow-credentials'];

          if (!acao) continue;

          // Wildcard with credentials
          if (acao === '*' && acac === 'true') {
            findings.push({
              severity: 'critical',
              category: 'cors',
              type: 'cors_wildcard_with_credentials',
              title: 'CORS: Wildcard Origin with Allow-Credentials',
              description: 'The application allows any origin AND allows credentials. This is a browser-rejected but dangerously misconfigured CORS policy.',
              evidence: { url, origin, acao, acac },
              cvss_score: 9.1,
              confidence: 'high',
              remediation_text: 'Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Explicitly whitelist trusted origins.',
              remediation_effort_hours: 2,
              owasp_category: 'A01:2021 – Broken Access Control',
              cwe_id: 'CWE-942'
            });
          }

          // Reflected origin with credentials
          if (acao === origin && acac === 'true' && origin !== 'null') {
            findings.push({
              severity: 'high',
              category: 'cors',
              type: 'cors_reflected_origin',
              title: `CORS: Arbitrary Origin Reflected with Credentials Allowed`,
              description: `The server reflects the Origin header back (${origin}) and allows credentials. Attackers can make authenticated cross-origin requests.`,
              payload: origin,
              evidence: { url, reflected_origin: acao, credentials: acac },
              cvss_score: 8.8,
              confidence: 'high',
              remediation_text: 'Implement an explicit whitelist of trusted origins. Do not dynamically reflect Origin headers.',
              remediation_effort_hours: 2,
              owasp_category: 'A01:2021 – Broken Access Control',
              cwe_id: 'CWE-942'
            });
            break; // One finding is enough
          }

          // Null origin accepted
          if (origin === 'null' && acao === 'null') {
            findings.push({
              severity: 'high',
              category: 'cors',
              type: 'cors_null_origin',
              title: 'CORS: Null Origin Accepted',
              description: 'The server accepts null origin which can be exploited via sandboxed iframes or redirected requests.',
              evidence: { url, acao, acac },
              cvss_score: 7.5,
              confidence: 'high',
              remediation_text: 'Do not allow null origin. Restrict to explicitly trusted domains.',
              remediation_effort_hours: 1,
              owasp_category: 'A01:2021 – Broken Access Control',
              cwe_id: 'CWE-942'
            });
          }

        } catch (e) {}
        await this.sleep(150);
      }

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'CORS scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = CORSScanner;
