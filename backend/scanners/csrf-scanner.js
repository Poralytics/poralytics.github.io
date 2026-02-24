/**
 * CSRF Scanner - Cross-Site Request Forgery
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class CSRFScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting CSRF scan', { url });
      
      const resp = await this.httpClient.get(url, { timeout: 8000 });
      if (!resp.data) return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };

      const $ = cheerio.load(resp.data);

      // Check each form for CSRF protection
      $('form').each((i, form) => {
        const method = ($(form).attr('method') || 'get').toLowerCase();
        if (method === 'get') return; // GET forms don't need CSRF

        const inputs = $(form).find('input, textarea, select').toArray();
        const formAction = $(form).attr('action') || url;

        // Check for CSRF token
        const csrfInputs = inputs.filter(inp => {
          const name = ($(inp).attr('name') || '').toLowerCase();
          const id = ($(inp).attr('id') || '').toLowerCase();
          return name.includes('csrf') || name.includes('token') || name.includes('_token') ||
            name.includes('nonce') || id.includes('csrf') || id.includes('token');
        });

        // Check for hidden inputs that could be tokens
        const hiddenInputs = inputs.filter(inp => $(inp).attr('type') === 'hidden');

        if (csrfInputs.length === 0 && hiddenInputs.length === 0) {
          findings.push({
            severity: 'high',
            category: 'csrf',
            type: 'missing_csrf_token',
            title: `CSRF Token Missing in Form (${formAction})`,
            description: `A POST form does not include a CSRF token. Attackers can forge requests on behalf of authenticated users.`,
            parameter: `form[${i}]`,
            evidence: {
              url,
              form_action: formAction,
              method,
              form_index: i,
              inputs: inputs.length
            },
            cvss_score: 8.8,
            confidence: 'high',
            remediation_text: 'Implement CSRF tokens (synchronizer token pattern) in all state-changing forms. Consider using SameSite cookie attribute as additional protection.',
            remediation_effort_hours: 4,
            owasp_category: 'A01:2021 – Broken Access Control',
            cwe_id: 'CWE-352'
          });
        }
      });

      // Check for SameSite cookie
      const cookies = resp.headers?.['set-cookie'] || [];
      const hasSameSite = (Array.isArray(cookies) ? cookies : [cookies])
        .some(c => c && c.toLowerCase().includes('samesite'));

      if ($('form[method="post"], form[method="POST"]').length > 0 && !hasSameSite) {
        findings.push({
          severity: 'low',
          category: 'csrf',
          type: 'no_samesite_cookie',
          title: 'No SameSite Cookie Protection',
          description: 'Session cookies lack SameSite attribute which provides additional CSRF protection.',
          evidence: { url },
          cvss_score: 3.1,
          confidence: 'medium',
          remediation_text: 'Set SameSite=Strict or SameSite=Lax on session cookies.',
          remediation_effort_hours: 1,
          owasp_category: 'A01:2021 – Broken Access Control',
          cwe_id: 'CWE-352'
        });
      }

      // Check for Referer/Origin header validation
      const refererCheck = await this.checkRefererValidation(url);
      if (refererCheck) findings.push(refererCheck);

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'CSRF scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  async checkRefererValidation(url) {
    try {
      // Test if the server checks the Referer/Origin header
      const resp = await this.httpClient.post(url, {}, {
        headers: {
          'Referer': 'https://evil.com',
          'Origin': 'https://evil.com',
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 5000
      });

      // If 200 with no redirect, might not check origin
      if (resp.status === 200) {
        return {
          severity: 'low',
          category: 'csrf',
          type: 'no_origin_check',
          title: 'No Origin/Referer Validation',
          description: 'Server may not validate Origin or Referer headers for state-changing requests.',
          evidence: { url, status: resp.status },
          cvss_score: 3.1,
          confidence: 'low',
          remediation_text: 'Validate Origin and Referer headers as part of CSRF defense in depth.',
          remediation_effort_hours: 2,
          owasp_category: 'A01:2021 – Broken Access Control',
          cwe_id: 'CWE-352'
        };
      }
    } catch (e) {}
    return null;
  }
}

module.exports = CSRFScanner;
