/**
 * Security Headers Scanner
 * Checks for missing or misconfigured security headers
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class HeadersScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 1 * 1024 * 1024 });

    this.requiredHeaders = [
      {
        header: 'strict-transport-security',
        name: 'HSTS',
        severity: 'high',
        description: 'Missing HTTP Strict Transport Security header allows downgrade attacks.',
        remediation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        cvss: 7.4,
        cwe: 'CWE-319'
      },
      {
        header: 'content-security-policy',
        name: 'CSP',
        severity: 'high',
        description: 'Missing Content Security Policy allows XSS and injection attacks.',
        remediation: 'Add a Content-Security-Policy header restricting sources.',
        cvss: 6.1,
        cwe: 'CWE-79'
      },
      {
        header: 'x-frame-options',
        name: 'X-Frame-Options',
        severity: 'medium',
        description: 'Missing X-Frame-Options allows clickjacking attacks.',
        remediation: 'Add: X-Frame-Options: DENY or SAMEORIGIN',
        cvss: 4.3,
        cwe: 'CWE-1021'
      },
      {
        header: 'x-content-type-options',
        name: 'X-Content-Type-Options',
        severity: 'low',
        description: 'Missing X-Content-Type-Options allows MIME sniffing attacks.',
        remediation: 'Add: X-Content-Type-Options: nosniff',
        cvss: 3.1,
        cwe: 'CWE-116'
      },
      {
        header: 'referrer-policy',
        name: 'Referrer-Policy',
        severity: 'low',
        description: 'Missing Referrer-Policy may leak sensitive URLs.',
        remediation: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        cvss: 3.1,
        cwe: 'CWE-116'
      },
      {
        header: 'permissions-policy',
        name: 'Permissions-Policy',
        severity: 'low',
        description: 'Missing Permissions-Policy allows unrestricted browser feature access.',
        remediation: 'Add Permissions-Policy header restricting features.',
        cvss: 2.6,
        cwe: 'CWE-732'
      }
    ];

    this.dangerousHeaders = [
      { header: 'server', name: 'Server disclosure', severity: 'low' },
      { header: 'x-powered-by', name: 'Technology disclosure', severity: 'low' },
      { header: 'x-aspnet-version', name: 'ASP.NET version disclosure', severity: 'low' }
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting Headers scan', { url });

      const resp = await this.httpClient.get(url, { timeout: 8000 });
      const headers = resp.headers || {};

      // Check for missing security headers
      for (const check of this.requiredHeaders) {
        if (!headers[check.header]) {
          findings.push({
            severity: check.severity,
            category: 'security_misconfiguration',
            type: 'missing_security_header',
            title: `Missing ${check.name} Header`,
            description: check.description,
            parameter: check.header,
            evidence: {
              url,
              missing_header: check.header,
              status_code: resp.status
            },
            cvss_score: check.cvss,
            confidence: 'high',
            remediation_text: check.remediation,
            remediation_effort_hours: 1,
            owasp_category: 'A05:2021 – Security Misconfiguration',
            cwe_id: check.cwe
          });
        }
      }

      // Check for dangerous headers that reveal info
      for (const check of this.dangerousHeaders) {
        if (headers[check.header]) {
          findings.push({
            severity: check.severity,
            category: 'information_disclosure',
            type: 'server_header_disclosure',
            title: `${check.name}: ${headers[check.header]}`,
            description: `Server discloses technology/version information via the ${check.header} header.`,
            parameter: check.header,
            evidence: {
              url,
              header: check.header,
              value: headers[check.header]
            },
            cvss_score: 3.1,
            confidence: 'high',
            remediation_text: `Remove or mask the ${check.header} header in your server configuration.`,
            remediation_effort_hours: 1,
            owasp_category: 'A05:2021 – Security Misconfiguration',
            cwe_id: 'CWE-200'
          });
        }
      }

      // Check HSTS details if present
      const hsts = headers['strict-transport-security'];
      if (hsts) {
        if (!hsts.includes('includeSubDomains')) {
          findings.push({
            severity: 'low',
            category: 'security_misconfiguration',
            type: 'weak_hsts',
            title: 'HSTS missing includeSubDomains',
            description: 'HSTS is configured but does not include subdomains.',
            evidence: { url, hsts_value: hsts },
            cvss_score: 2.6,
            confidence: 'high',
            remediation_text: 'Add includeSubDomains to your HSTS header.',
            remediation_effort_hours: 1,
            owasp_category: 'A05:2021 – Security Misconfiguration',
            cwe_id: 'CWE-319'
          });
        }
      }

      // Check CSP quality if present
      const csp = headers['content-security-policy'];
      if (csp && (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'"))) {
        findings.push({
          severity: 'medium',
          category: 'security_misconfiguration',
          type: 'weak_csp',
          title: "CSP uses 'unsafe-inline' or 'unsafe-eval'",
          description: 'Content Security Policy is weakened by unsafe directives.',
          parameter: 'content-security-policy',
          evidence: { url, csp_value: csp.substring(0, 200) },
          cvss_score: 5.4,
          confidence: 'high',
          remediation_text: "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes instead.",
          remediation_effort_hours: 4,
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cwe_id: 'CWE-79'
        });
      }

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'Headers scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}

module.exports = HeadersScanner;
