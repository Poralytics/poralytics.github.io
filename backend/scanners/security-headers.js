/**
 * SECURITY HEADERS SCANNER
 * Vérifie la présence et la configuration des headers de sécurité
 */

const axios = require('axios');

class SecurityHeadersScanner {
  constructor() {
    this.name = 'Security Headers Scanner';
    this.severity = 'low';
  }

  async scan(url) {
    const vulnerabilities = [];
    const startTime = Date.now();

    try {
      const response = await axios.get(url, {
        timeout: 5000,
        validateStatus: () => true
      });

      const headers = response.headers;

      // Check X-Frame-Options
      if (!headers['x-frame-options']) {
        vulnerabilities.push({
          type: 'security_headers',
          severity: 'medium',
          title: 'Missing X-Frame-Options Header',
          description: 'The X-Frame-Options header is not set. This could allow clickjacking attacks.',
          url,
          evidence: 'X-Frame-Options header not found',
          recommendation: 'Set X-Frame-Options: DENY or SAMEORIGIN',
          cvss_score: 4.3,
          cwe: 'CWE-1021'
        });
      }

      // Check X-Content-Type-Options
      if (!headers['x-content-type-options']) {
        vulnerabilities.push({
          type: 'security_headers',
          severity: 'low',
          title: 'Missing X-Content-Type-Options Header',
          description: 'The X-Content-Type-Options header is not set. Browser may MIME-sniff responses.',
          url,
          evidence: 'X-Content-Type-Options header not found',
          recommendation: 'Set X-Content-Type-Options: nosniff',
          cvss_score: 3.7,
          cwe: 'CWE-693'
        });
      }

      // Check Strict-Transport-Security (HSTS)
      if (url.startsWith('https://')) {
        if (!headers['strict-transport-security']) {
          vulnerabilities.push({
            type: 'security_headers',
            severity: 'medium',
            title: 'Missing Strict-Transport-Security Header',
            description: 'HSTS header not set on HTTPS site. Users may be vulnerable to downgrade attacks.',
            url,
            evidence: 'Strict-Transport-Security header not found',
            recommendation: 'Set Strict-Transport-Security: max-age=31536000; includeSubDomains',
            cvss_score: 5.3,
            cwe: 'CWE-523'
          });
        }
      }

      // Check Content-Security-Policy
      if (!headers['content-security-policy']) {
        vulnerabilities.push({
          type: 'security_headers',
          severity: 'medium',
          title: 'Missing Content-Security-Policy Header',
          description: 'CSP header not set. Application is more vulnerable to XSS and injection attacks.',
          url,
          evidence: 'Content-Security-Policy header not found',
          recommendation: 'Implement a Content-Security-Policy that restricts script sources.',
          cvss_score: 5.0,
          cwe: 'CWE-693'
        });
      }

      // Check X-XSS-Protection (deprecated but still useful)
      if (!headers['x-xss-protection']) {
        vulnerabilities.push({
          type: 'security_headers',
          severity: 'low',
          title: 'Missing X-XSS-Protection Header',
          description: 'X-XSS-Protection header not set (legacy protection).',
          url,
          evidence: 'X-XSS-Protection header not found',
          recommendation: 'Set X-XSS-Protection: 1; mode=block (though CSP is preferred)',
          cvss_score: 3.0,
          cwe: 'CWE-79'
        });
      }

      // Check Referrer-Policy
      if (!headers['referrer-policy']) {
        vulnerabilities.push({
          type: 'security_headers',
          severity: 'low',
          title: 'Missing Referrer-Policy Header',
          description: 'Referrer-Policy not set. Referrer information may leak.',
          url,
          evidence: 'Referrer-Policy header not found',
          recommendation: 'Set Referrer-Policy: no-referrer-when-downgrade or strict-origin-when-cross-origin',
          cvss_score: 2.5,
          cwe: 'CWE-200'
        });
      }

      // Check Permissions-Policy
      if (!headers['permissions-policy'] && !headers['feature-policy']) {
        vulnerabilities.push({
          type: 'security_headers',
          severity: 'low',
          title: 'Missing Permissions-Policy Header',
          description: 'Permissions-Policy (formerly Feature-Policy) not set.',
          url,
          evidence: 'Permissions-Policy header not found',
          recommendation: 'Set Permissions-Policy to control browser features',
          cvss_score: 2.0,
          cwe: 'CWE-693'
        });
      }

      // Check Server header disclosure
      if (headers['server']) {
        const serverHeader = headers['server'];
        if (serverHeader.match(/\d+\.\d+/)) { // Contains version number
          vulnerabilities.push({
            type: 'info_disclosure',
            severity: 'low',
            title: 'Server Version Disclosure',
            description: `Server header reveals software version: ${serverHeader}`,
            url,
            evidence: `Server: ${serverHeader}`,
            recommendation: 'Remove or obfuscate the Server header to not reveal version information',
            cvss_score: 2.0,
            cwe: 'CWE-200'
          });
        }
      }

      // Check X-Powered-By header disclosure
      if (headers['x-powered-by']) {
        vulnerabilities.push({
          type: 'info_disclosure',
          severity: 'low',
          title: 'Technology Stack Disclosure',
          description: `X-Powered-By header reveals technology: ${headers['x-powered-by']}`,
          url,
          evidence: `X-Powered-By: ${headers['x-powered-by']}`,
          recommendation: 'Remove X-Powered-By header',
          cvss_score: 2.0,
          cwe: 'CWE-200'
        });
      }

    } catch (error) {
      console.error('Security Headers Scanner error:', error.message);
    }

    const duration = Date.now() - startTime;
    return {
      scanner: this.name,
      vulnerabilities,
      duration_ms: duration,
      status: 'completed'
    };
  }
}

module.exports = SecurityHeadersScanner;
