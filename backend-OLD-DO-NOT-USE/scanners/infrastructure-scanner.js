/**
 * Infrastructure Scanner - Server-level checks
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class InfrastructureScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 1 * 1024 * 1024 });
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Infrastructure scan', { url });
      const resp = await this.httpClient.get(url, { timeout: 8000 });
      const headers = resp.headers || {};

      // Server version disclosure
      if (headers['server']) {
        const serverHeader = headers['server'];
        const versionPattern = /[0-9]+\.[0-9]+/;
        if (versionPattern.test(serverHeader)) {
          findings.push({
            severity: 'low',
            category: 'infrastructure',
            type: 'server_version_disclosure',
            title: `Server Version Disclosed: ${serverHeader}`,
            description: 'Server discloses version information which helps attackers find known vulnerabilities.',
            evidence: { url, server: serverHeader },
            cvss_score: 3.1,
            confidence: 'high',
            remediation_text: 'Configure web server to suppress version information.',
            remediation_effort_hours: 1,
            owasp_category: 'A05:2021 – Security Misconfiguration',
            cwe_id: 'CWE-200'
          });
        }
      }

      // X-Powered-By disclosure
      if (headers['x-powered-by']) {
        findings.push({
          severity: 'low',
          category: 'infrastructure',
          type: 'technology_disclosure',
          title: `Technology Disclosed: X-Powered-By: ${headers['x-powered-by']}`,
          description: 'Server reveals backend technology via X-Powered-By header.',
          evidence: { url, header: 'X-Powered-By', value: headers['x-powered-by'] },
          cvss_score: 2.6,
          confidence: 'high',
          remediation_text: 'Remove X-Powered-By header in framework/server configuration.',
          remediation_effort_hours: 1,
          owasp_category: 'A05:2021 – Security Misconfiguration',
          cwe_id: 'CWE-200'
        });
      }

      // Check for common debug endpoints
      const base = new URL(url).origin;
      const debugPaths = ['/debug', '/test', '/dev', '/console', '/shell', '/eval'];
      for (const path of debugPaths) {
        try {
          const debugResp = await this.httpClient.get(base + path, { timeout: 3000 });
          if (debugResp.status === 200) {
            findings.push({
              severity: 'high',
              category: 'infrastructure',
              type: 'debug_endpoint_exposed',
              title: `Debug Endpoint Exposed: ${path}`,
              description: 'Debug/development endpoint is accessible in production.',
              evidence: { url: base + path, status: debugResp.status },
              cvss_score: 8.6,
              confidence: 'medium',
              remediation_text: 'Remove debug endpoints from production environment.',
              remediation_effort_hours: 1,
              owasp_category: 'A05:2021 – Security Misconfiguration',
              cwe_id: 'CWE-489'
            });
          }
        } catch (e) {}
      }

    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}
module.exports = InfrastructureScanner;
