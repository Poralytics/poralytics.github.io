/**
 * SSL/TLS SCANNER
 * Vérifie la configuration SSL/TLS et les certificats
 */

const https = require('https');
const tls = require('tls');
const { URL } = require('url');

class SSLScanner {
  constructor() {
    this.name = 'SSL/TLS Scanner';
    this.severity = 'medium';
  }

  async scan(url) {
    const vulnerabilities = [];
    const startTime = Date.now();

    try {
      const parsedUrl = new URL(url);
      
      // Only scan HTTPS URLs
      if (parsedUrl.protocol !== 'https:') {
        vulnerabilities.push({
          type: 'ssl_tls',
          severity: 'high',
          title: 'HTTPS Not Enabled',
          description: 'Site is not using HTTPS. All traffic is unencrypted.',
          url,
          evidence: 'URL uses HTTP protocol',
          recommendation: 'Enable HTTPS with a valid SSL/TLS certificate',
          cvss_score: 7.5,
          cwe: 'CWE-319'
        });
        
        const duration = Date.now() - startTime;
        return {
          scanner: this.name,
          vulnerabilities,
          duration_ms: duration,
          status: 'completed'
        };
      }

      const hostname = parsedUrl.hostname;
      const port = parsedUrl.port || 443;

      // Get certificate and connection info
      const certInfo = await this.getCertificateInfo(hostname, port);

      if (!certInfo) {
        vulnerabilities.push({
          type: 'ssl_tls',
          severity: 'high',
          title: 'SSL/TLS Connection Failed',
          description: 'Unable to establish SSL/TLS connection',
          url,
          evidence: 'Connection failed',
          recommendation: 'Check SSL/TLS configuration',
          cvss_score: 7.0,
          cwe: 'CWE-295'
        });
      } else {
        // Check certificate expiration
        const daysUntilExpiry = this.getDaysUntilExpiry(certInfo.validTo);
        
        if (daysUntilExpiry < 0) {
          vulnerabilities.push({
            type: 'ssl_tls',
            severity: 'critical',
            title: 'SSL Certificate Expired',
            description: `Certificate expired on ${certInfo.validTo}`,
            url,
            evidence: `Certificate valid until: ${certInfo.validTo}`,
            recommendation: 'Renew SSL certificate immediately',
            cvss_score: 9.0,
            cwe: 'CWE-295'
          });
        } else if (daysUntilExpiry < 30) {
          vulnerabilities.push({
            type: 'ssl_tls',
            severity: 'medium',
            title: 'SSL Certificate Expiring Soon',
            description: `Certificate expires in ${daysUntilExpiry} days`,
            url,
            evidence: `Certificate valid until: ${certInfo.validTo}`,
            recommendation: 'Renew SSL certificate before expiration',
            cvss_score: 5.0,
            cwe: 'CWE-295'
          });
        }

        // Check for self-signed certificate
        if (certInfo.issuer === certInfo.subject) {
          vulnerabilities.push({
            type: 'ssl_tls',
            severity: 'medium',
            title: 'Self-Signed SSL Certificate',
            description: 'Certificate is self-signed and not from a trusted CA',
            url,
            evidence: 'Issuer and subject are identical',
            recommendation: 'Use a certificate from a trusted Certificate Authority',
            cvss_score: 5.5,
            cwe: 'CWE-295'
          });
        }

        // Check TLS version
        if (certInfo.protocol) {
          if (certInfo.protocol.includes('TLSv1.0') || certInfo.protocol.includes('TLSv1.1')) {
            vulnerabilities.push({
              type: 'ssl_tls',
              severity: 'high',
              title: 'Weak TLS Version',
              description: `Site supports weak TLS version: ${certInfo.protocol}`,
              url,
              evidence: `Protocol: ${certInfo.protocol}`,
              recommendation: 'Disable TLS 1.0 and 1.1. Use TLS 1.2 or 1.3 only',
              cvss_score: 6.5,
              cwe: 'CWE-326'
            });
          }
        }

        // Check certificate signature algorithm
        if (certInfo.signatureAlgorithm && certInfo.signatureAlgorithm.includes('sha1')) {
          vulnerabilities.push({
            type: 'ssl_tls',
            severity: 'medium',
            title: 'Weak Certificate Signature Algorithm',
            description: 'Certificate uses SHA-1 signature algorithm',
            url,
            evidence: `Signature algorithm: ${certInfo.signatureAlgorithm}`,
            recommendation: 'Use certificates with SHA-256 or stronger',
            cvss_score: 5.0,
            cwe: 'CWE-327'
          });
        }
      }

    } catch (error) {
      console.error('SSL Scanner error:', error.message);
    }

    const duration = Date.now() - startTime;
    return {
      scanner: this.name,
      vulnerabilities,
      duration_ms: duration,
      status: 'completed'
    };
  }

  getCertificateInfo(hostname, port) {
    return new Promise((resolve) => {
      const options = {
        host: hostname,
        port: port,
        method: 'GET',
        rejectUnauthorized: false // Allow self-signed certs for testing
      };

      const req = https.get(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        
        if (cert && Object.keys(cert).length > 0) {
          resolve({
            subject: cert.subject ? cert.subject.CN : 'Unknown',
            issuer: cert.issuer ? cert.issuer.CN : 'Unknown',
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            protocol: res.socket.getProtocol ? res.socket.getProtocol() : 'Unknown',
            signatureAlgorithm: cert.signatureAlgorithm
          });
        } else {
          resolve(null);
        }
      });

      req.on('error', () => {
        resolve(null);
      });

      req.setTimeout(5000, () => {
        req.destroy();
        resolve(null);
      });
    });
  }

  getDaysUntilExpiry(validToDate) {
    const expiry = new Date(validToDate);
    const now = new Date();
    const diff = expiry - now;
    return Math.floor(diff / (1000 * 60 * 60 * 24));
  }
}

module.exports = SSLScanner;
