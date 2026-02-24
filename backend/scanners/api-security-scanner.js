/**
 * API Security Scanner
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class APISecurityScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
    this.apiPaths = ['/api', '/api/v1', '/api/v2', '/graphql', '/api/graphql', '/rest'];
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting API Security scan', { url });
      const base = new URL(url).origin;

      // 1. Check for GraphQL introspection
      for (const path of ['/graphql', '/api/graphql', '/graphql/v1']) {
        try {
          const resp = await this.httpClient.post(base + path, {
            query: '{ __schema { types { name } } }'
          }, { headers: { 'Content-Type': 'application/json' }, timeout: 5000 });

          if (resp.status === 200 && resp.data?.data?.__schema) {
            findings.push({
              severity: 'medium',
              category: 'api_security',
              type: 'graphql_introspection_enabled',
              title: 'GraphQL Introspection Enabled',
              description: 'GraphQL introspection is enabled in production, revealing the full API schema to attackers.',
              evidence: { endpoint: base + path, introspection: true },
              cvss_score: 5.3,
              confidence: 'high',
              remediation_text: 'Disable GraphQL introspection in production environments.',
              remediation_effort_hours: 1,
              owasp_category: 'A01:2021 – Broken Access Control',
              cwe_id: 'CWE-200'
            });
          }
        } catch (e) {}
      }

      // 2. Check for API without versioning
      try {
        const resp = await this.httpClient.get(base + '/api', { timeout: 5000 });
        if (resp.status === 200) {
          const hasVersion = resp.headers?.['api-version'] || resp.data?.version;
          if (!hasVersion) {
            findings.push({
              severity: 'low',
              category: 'api_security',
              type: 'no_api_versioning',
              title: 'API Without Versioning',
              description: 'API endpoint lacks version identifier, complicating future security updates.',
              evidence: { url: base + '/api', status: resp.status },
              cvss_score: 2.6,
              confidence: 'low',
              remediation_text: 'Implement API versioning (e.g., /api/v1/).',
              remediation_effort_hours: 8,
              owasp_category: 'A05:2021 – Security Misconfiguration',
              cwe_id: 'CWE-1059'
            });
          }
        }
      } catch (e) {}

      // 3. Check for unauthenticated API access
      const sensitiveEndpoints = [
        '/api/users', '/api/v1/users', '/api/accounts', '/api/admin',
        '/api/settings', '/api/keys', '/api/v1/config'
      ];
      
      for (const ep of sensitiveEndpoints.slice(0, 4)) {
        try {
          const resp = await this.httpClient.get(base + ep, { timeout: 3000 });
          if (resp.status === 200 && resp.data) {
            const isUserData = JSON.stringify(resp.data).includes('email') ||
              JSON.stringify(resp.data).includes('password') ||
              JSON.stringify(resp.data).includes('token');
            if (isUserData) {
              findings.push({
                severity: 'critical',
                category: 'api_security',
                type: 'unauthenticated_api_access',
                title: `Sensitive API Endpoint Accessible Without Auth: ${ep}`,
                description: 'API endpoint returns sensitive data without authentication.',
                evidence: { endpoint: base + ep, status: resp.status },
                cvss_score: 9.1,
                confidence: 'high',
                remediation_text: 'Implement authentication on all sensitive API endpoints.',
                remediation_effort_hours: 4,
                owasp_category: 'A01:2021 – Broken Access Control',
                cwe_id: 'CWE-306'
              });
            }
          }
        } catch (e) {}
      }

      // 4. Check for mass assignment via large payload acceptance
      try {
        const resp = await this.httpClient.post(base + '/api/v1/users', {
          email: 'test@test.com',
          password: 'test',
          role: 'admin',          // Should not be accepted
          is_admin: true,         // Should not be accepted
          permissions: ['all']    // Should not be accepted
        }, { timeout: 5000 });

        if (resp.status < 400) {
          findings.push({
            severity: 'high',
            category: 'api_security',
            type: 'potential_mass_assignment',
            title: 'Potential Mass Assignment Vulnerability',
            description: 'API accepts requests with sensitive fields (role, is_admin) without filtering.',
            evidence: { endpoint: base + '/api/v1/users', status: resp.status },
            cvss_score: 8.1,
            confidence: 'low',
            remediation_text: 'Use allowlists to restrict which fields can be set via API. Never bind user input directly to model properties.',
            remediation_effort_hours: 6,
            owasp_category: 'A01:2021 – Broken Access Control',
            cwe_id: 'CWE-915'
          });
        }
      } catch (e) {}

    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}
module.exports = APISecurityScanner;
