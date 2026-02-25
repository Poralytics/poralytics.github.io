/**
 * Clickjacking Scanner
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class ClickjackingScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 1 * 1024 * 1024 });
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Clickjacking scan', { url });
      const resp = await this.httpClient.get(url, { timeout: 8000 });
      const h = resp.headers || {};
      const xfo = h['x-frame-options'];
      const csp = h['content-security-policy'] || '';
      const hasFrameAncestors = csp.includes('frame-ancestors');

      if (!xfo && !hasFrameAncestors) {
        findings.push({
          severity: 'medium',
          category: 'clickjacking',
          type: 'missing_clickjacking_protection',
          title: 'Clickjacking Protection Missing',
          description: 'Page can be embedded in iframes, allowing clickjacking attacks.',
          evidence: { url, x_frame_options: 'missing', csp_frame_ancestors: 'missing' },
          cvss_score: 4.3,
          confidence: 'high',
          remediation_text: "Add 'X-Frame-Options: DENY' or 'frame-ancestors none' in CSP.",
          remediation_effort_hours: 1,
          owasp_category: 'A01:2021 – Broken Access Control',
          cwe_id: 'CWE-1021'
        });
      } else if (xfo && !['DENY', 'SAMEORIGIN'].includes(xfo.toUpperCase().trim())) {
        findings.push({
          severity: 'low',
          category: 'clickjacking',
          type: 'weak_clickjacking_protection',
          title: `Weak X-Frame-Options Value: ${xfo}`,
          description: 'X-Frame-Options uses a non-standard or weak value.',
          evidence: { url, x_frame_options: xfo },
          cvss_score: 2.6,
          confidence: 'high',
          remediation_text: "Use 'X-Frame-Options: DENY' for most applications.",
          remediation_effort_hours: 1,
          owasp_category: 'A01:2021 – Broken Access Control',
          cwe_id: 'CWE-1021'
        });
      }
    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}
module.exports = ClickjackingScanner;
