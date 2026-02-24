/**
 * Access Control Scanner - Broken Access Control detection
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class AccessControlScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
    this.adminPaths = ['/admin', '/admin/', '/admin/dashboard', '/administrator', '/manager',
      '/management', '/api/admin', '/api/v1/admin', '/backend', '/control', '/controlpanel'];
    this.privilegedPaths = ['/api/users', '/api/v1/users', '/api/accounts', '/api/settings',
      '/api/config', '/api/keys', '/api/tokens', '/api/secrets'];
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Access Control scan', { url });
      const base = new URL(url).origin;

      // 1. Check for exposed admin interfaces
      const adminChecks = this.adminPaths.map(async (path) => {
        try {
          const resp = await this.httpClient.get(base + path, { timeout: 5000 });
          if (resp.status === 200) {
            const body = resp.data || '';
            const isAdminContent = typeof body === 'string' && 
              (body.includes('admin') || body.includes('dashboard') || body.includes('management'));
            if (isAdminContent) {
              return {
                severity: 'critical',
                category: 'access_control',
                type: 'exposed_admin_interface',
                title: `Admin Interface Accessible Without Authentication: ${path}`,
                description: 'Administrative interface is publicly accessible without authentication.',
                evidence: { url: base + path, status: resp.status },
                cvss_score: 9.8,
                confidence: 'high',
                remediation_text: 'Restrict admin interfaces with authentication and network access controls.',
                remediation_effort_hours: 4,
                owasp_category: 'A01:2021 – Broken Access Control',
                cwe_id: 'CWE-284'
              };
            }
          }
        } catch (e) {}
        return null;
      });
      const adminResults = (await Promise.all(adminChecks)).filter(Boolean);
      findings.push(...adminResults);

      // 2. Check for directory listing
      const dirListPaths = ['/uploads/', '/files/', '/images/', '/static/', '/assets/'];
      for (const path of dirListPaths) {
        try {
          const resp = await this.httpClient.get(base + path, { timeout: 3000 });
          if (resp.status === 200 && typeof resp.data === 'string' &&
            (resp.data.includes('Index of') || resp.data.includes('Parent Directory'))) {
            findings.push({
              severity: 'medium',
              category: 'access_control',
              type: 'directory_listing',
              title: `Directory Listing Enabled: ${path}`,
              description: 'Server exposes directory contents, potentially revealing sensitive files.',
              evidence: { url: base + path, status: resp.status },
              cvss_score: 5.3,
              confidence: 'high',
              remediation_text: 'Disable directory listing in web server configuration.',
              remediation_effort_hours: 1,
              owasp_category: 'A01:2021 – Broken Access Control',
              cwe_id: 'CWE-548'
            });
          }
        } catch (e) {}
      }

      // 3. Test IDOR with numeric IDs if present
      const urlObj = new URL(url);
      let hasIdParam = false;
      urlObj.searchParams.forEach((val, key) => {
        if (/^[0-9]+$/.test(val) && parseInt(val) > 1) {
          hasIdParam = true;
        }
      });

      if (hasIdParam) {
        findings.push({
          severity: 'medium',
          category: 'access_control',
          type: 'potential_idor',
          title: 'Potential Insecure Direct Object Reference (IDOR)',
          description: 'URL contains numeric IDs that may be vulnerable to IDOR attacks.',
          evidence: { url },
          cvss_score: 5.4,
          confidence: 'low',
          remediation_text: 'Implement proper authorization checks. Use UUIDs instead of sequential IDs. Verify user has access to requested resource.',
          remediation_effort_hours: 8,
          owasp_category: 'A01:2021 – Broken Access Control',
          cwe_id: 'CWE-639'
        });
      }

    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}
module.exports = AccessControlScanner;
