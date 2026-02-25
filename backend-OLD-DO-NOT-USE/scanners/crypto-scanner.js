/**
 * Cryptography Scanner - Weak crypto detection
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class CryptoScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Crypto scan', { url });
      const resp = await this.httpClient.get(url, { timeout: 8000 });
      const body = resp.data || '';
      const headers = resp.headers || {};

      // Check for MD5 or SHA1 in response
      if (/\bmd5\b/i.test(body) && typeof body === 'string') {
        findings.push({
          severity: 'medium',
          category: 'cryptography',
          type: 'weak_hash',
          title: 'Possible MD5 Hash Usage',
          description: 'Application may use MD5 for hashing, which is cryptographically broken.',
          evidence: { url, pattern: 'md5' },
          cvss_score: 5.9,
          confidence: 'low',
          remediation_text: 'Replace MD5 with SHA-256 or bcrypt for password hashing.',
          remediation_effort_hours: 4,
          owasp_category: 'A02:2021 – Cryptographic Failures',
          cwe_id: 'CWE-328'
        });
      }

      // Check if HTTP (no encryption)
      if (url.startsWith('http://')) {
        findings.push({
          severity: 'high',
          category: 'cryptography',
          type: 'no_encryption',
          title: 'Data Transmitted Over Unencrypted HTTP',
          description: 'Application uses HTTP instead of HTTPS, exposing all data to interception.',
          evidence: { url, protocol: 'http' },
          cvss_score: 7.5,
          confidence: 'high',
          remediation_text: 'Enable HTTPS with a valid TLS certificate. Redirect all HTTP to HTTPS.',
          remediation_effort_hours: 4,
          owasp_category: 'A02:2021 – Cryptographic Failures',
          cwe_id: 'CWE-319'
        });
      }

      // Check for weak TLS in response headers
      const tlsVersion = resp.socket?.getProtocol?.() || '';
      if (tlsVersion && (tlsVersion.includes('TLSv1.0') || tlsVersion.includes('TLSv1.1'))) {
        findings.push({
          severity: 'high',
          category: 'cryptography',
          type: 'weak_tls',
          title: `Weak TLS Version: ${tlsVersion}`,
          description: 'Server supports outdated TLS versions with known vulnerabilities.',
          evidence: { url, tls_version: tlsVersion },
          cvss_score: 7.4,
          confidence: 'high',
          remediation_text: 'Disable TLS 1.0 and 1.1. Only allow TLS 1.2 and TLS 1.3.',
          remediation_effort_hours: 2,
          owasp_category: 'A02:2021 – Cryptographic Failures',
          cwe_id: 'CWE-326'
        });
      }

    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}
module.exports = CryptoScanner;
