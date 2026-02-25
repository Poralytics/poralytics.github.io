/**
 * SSL/TLS Scanner - Checks SSL configuration and certificate
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const https = require('https');

class SSLScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 1 * 1024 * 1024 });
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting SSL scan', { url });
      const parsed = new URL(url);

      // 1. Check if HTTPS is used
      if (parsed.protocol !== 'https:') {
        findings.push({
          severity: 'high',
          category: 'ssl',
          type: 'no_https',
          title: 'Site Does Not Use HTTPS',
          description: 'All communication is unencrypted. Credentials, session tokens, and data can be intercepted.',
          evidence: { url, protocol: parsed.protocol },
          cvss_score: 7.5,
          confidence: 'high',
          remediation_text: 'Deploy a valid SSL/TLS certificate and redirect all HTTP to HTTPS. Configure HSTS.',
          remediation_effort_hours: 4,
          owasp_category: 'A02:2021 – Cryptographic Failures',
          cwe_id: 'CWE-319'
        });
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      // 2. Check certificate details
      const certInfo = await this.getCertificateInfo(parsed.hostname, parseInt(parsed.port) || 443);

      if (certInfo.error) {
        errors.push(certInfo.error);
      } else {
        // Check expiry
        if (certInfo.daysToExpiry < 30) {
          findings.push({
            severity: certInfo.daysToExpiry < 0 ? 'critical' : 'high',
            category: 'ssl',
            type: certInfo.daysToExpiry < 0 ? 'certificate_expired' : 'certificate_expiring',
            title: certInfo.daysToExpiry < 0 ? 'SSL Certificate Expired' : `SSL Certificate Expiring in ${certInfo.daysToExpiry} Days`,
            description: certInfo.daysToExpiry < 0 
              ? 'SSL certificate has expired. Browsers will show security warnings.'
              : `SSL certificate expires in ${certInfo.daysToExpiry} days.`,
            evidence: { url, expires: certInfo.validTo, days_remaining: certInfo.daysToExpiry },
            cvss_score: certInfo.daysToExpiry < 0 ? 7.5 : 3.7,
            confidence: 'high',
            remediation_text: 'Renew the SSL certificate immediately. Set up auto-renewal.',
            remediation_effort_hours: 2,
            owasp_category: 'A02:2021 – Cryptographic Failures',
            cwe_id: 'CWE-298'
          });
        }

        // Check if self-signed
        if (certInfo.selfSigned) {
          findings.push({
            severity: 'medium',
            category: 'ssl',
            type: 'self_signed_certificate',
            title: 'Self-Signed SSL Certificate',
            description: 'The site uses a self-signed certificate which browsers do not trust.',
            evidence: { url, issuer: certInfo.issuer, subject: certInfo.subject },
            cvss_score: 5.9,
            confidence: 'high',
            remediation_text: 'Use a certificate from a trusted CA. Consider Let\'s Encrypt for free trusted certificates.',
            remediation_effort_hours: 2,
            owasp_category: 'A02:2021 – Cryptographic Failures',
            cwe_id: 'CWE-295'
          });
        }
      }

      // 3. Check HTTP to HTTPS redirect
      const httpUrl = url.replace('https://', 'http://');
      try {
        const httpResp = await this.httpClient.get(httpUrl, { timeout: 5000, maxRedirects: 0 });
        if (httpResp.status !== 301 && httpResp.status !== 302) {
          findings.push({
            severity: 'medium',
            category: 'ssl',
            type: 'no_http_redirect',
            title: 'No HTTP to HTTPS Redirect',
            description: 'The site does not redirect HTTP requests to HTTPS.',
            evidence: { url: httpUrl, status: httpResp.status },
            cvss_score: 5.4,
            confidence: 'high',
            remediation_text: 'Configure a 301 redirect from HTTP to HTTPS and enable HSTS.',
            remediation_effort_hours: 1,
            owasp_category: 'A02:2021 – Cryptographic Failures',
            cwe_id: 'CWE-319'
          });
        }
      } catch (e) {
        // HTTP might be completely blocked - that's fine
      }

      // 4. Check HSTS
      const resp = await this.httpClient.get(url, { timeout: 8000 });
      const hsts = resp.headers?.['strict-transport-security'];
      if (!hsts) {
        findings.push({
          severity: 'medium',
          category: 'ssl',
          type: 'missing_hsts',
          title: 'Missing HSTS Header',
          description: 'HTTP Strict Transport Security is not configured, allowing SSL stripping attacks.',
          evidence: { url },
          cvss_score: 4.3,
          confidence: 'high',
          remediation_text: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
          remediation_effort_hours: 1,
          owasp_category: 'A02:2021 – Cryptographic Failures',
          cwe_id: 'CWE-319'
        });
      }

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'SSL scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  getCertificateInfo(hostname, port) {
    return new Promise((resolve) => {
      const req = https.request({ hostname, port, method: 'GET', path: '/', rejectUnauthorized: false, timeout: 8000 }, (res) => {
        const cert = res.socket?.getPeerCertificate();
        if (!cert || !cert.subject) {
          resolve({ error: 'No certificate found' });
          return;
        }

        const now = new Date();
        const expires = new Date(cert.valid_to);
        const daysToExpiry = Math.floor((expires - now) / (1000 * 60 * 60 * 24));
        const selfSigned = cert.issuer?.CN === cert.subject?.CN;

        resolve({
          subject: cert.subject?.CN || 'unknown',
          issuer: cert.issuer?.CN || 'unknown',
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          daysToExpiry,
          selfSigned
        });
      });

      req.on('error', (e) => resolve({ error: e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ error: 'timeout' }); });
      req.end();
    });
  }
}

module.exports = SSLScanner;
