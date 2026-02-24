/**
 * Open Redirect Scanner
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class OpenRedirectScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 1 * 1024 * 1024, maxRedirects: 0 });
    this.redirectParams = ['redirect', 'url', 'next', 'return', 'goto', 'dest', 'destination', 'redir', 'redirect_uri', 'callback', 'continue', 'r', 'u', 'link'];
    this.testUrls = ['https://evil.com', '//evil.com', '/\\evil.com', 'https:evil.com'];
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Open Redirect scan', { url });
      const urlObj = new URL(url);

      for (const param of this.redirectParams) {
        for (const testUrl of this.testUrls.slice(0, 2)) {
          try {
            urlObj.searchParams.set(param, testUrl);
            const resp = await this.httpClient.get(urlObj.toString(), { timeout: 5000 });
            
            if (resp.status >= 300 && resp.status < 400) {
              const location = resp.headers?.location || '';
              if (location.includes('evil.com') || location.startsWith('//evil')) {
                findings.push({
                  severity: 'medium',
                  category: 'open_redirect',
                  type: 'open_redirect',
                  title: `Open Redirect via '${param}' parameter`,
                  description: `The application redirects to attacker-controlled URLs via the '${param}' parameter.`,
                  parameter: param,
                  payload: testUrl,
                  evidence: { url: urlObj.toString(), location, status: resp.status },
                  cvss_score: 6.1,
                  confidence: 'high',
                  remediation_text: 'Validate redirect URLs against a whitelist of allowed destinations.',
                  remediation_effort_hours: 2,
                  owasp_category: 'A01:2021 – Broken Access Control',
                  cwe_id: 'CWE-601'
                });
                break;
              }
            }
          } catch (e) {}
          await this.sleep(150);
        }
        urlObj.searchParams.delete(param);
      }
    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}
module.exports = OpenRedirectScanner;
