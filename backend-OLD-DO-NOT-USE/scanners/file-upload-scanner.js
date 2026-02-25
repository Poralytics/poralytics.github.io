/**
 * File Upload Scanner
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class FileUploadScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 5 * 1024 * 1024 });
    this.dangerousTypes = [
      { name: 'PHP webshell', filename: 'test.php', content: '<?php echo "nexus_test_" . phpversion(); ?>', contentType: 'application/x-php' },
      { name: 'PHP with image magic bytes', filename: 'image.php.jpg', content: '\xFF\xD8\xFF<?php echo "nexus"; ?>', contentType: 'image/jpeg' },
      { name: 'SVG with XSS', filename: 'test.svg', content: '<svg><script>alert(1)</script></svg>', contentType: 'image/svg+xml' },
      { name: 'HTML file upload', filename: 'test.html', content: '<script>alert(1)</script>', contentType: 'text/html' }
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting File Upload scan', { url });
      const resp = await this.httpClient.get(url, { timeout: 8000 });
      
      if (!resp.data || typeof resp.data !== 'string') {
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      const $ = cheerio.load(resp.data);
      const uploadForms = $('form').filter((_, form) => $(form).find('input[type="file"]').length > 0);

      if (uploadForms.length === 0) {
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      // Check for missing accept attribute (no client-side restriction)
      uploadForms.each((i, form) => {
        const fileInput = $(form).find('input[type="file"]');
        const accept = fileInput.attr('accept');
        const formAction = $(form).attr('action') || url;

        if (!accept) {
          findings.push({
            severity: 'medium',
            category: 'file_upload',
            type: 'unrestricted_file_type_client',
            title: 'File Upload Without Type Restriction (Client Side)',
            description: 'File upload form has no client-side file type restriction.',
            evidence: { url, form_action: formAction },
            cvss_score: 5.3,
            confidence: 'medium',
            remediation_text: 'Add accept attribute to file input AND validate file types server-side.',
            remediation_effort_hours: 2,
            owasp_category: 'A04:2021 – Insecure Design',
            cwe_id: 'CWE-434'
          });
        }
      });

      // Note: We don't actually upload files to avoid causing damage
      // Instead we note the presence of upload functionality as a risk
      if (uploadForms.length > 0) {
        findings.push({
          severity: 'info',
          category: 'file_upload',
          type: 'file_upload_detected',
          title: 'File Upload Functionality Detected',
          description: `${uploadForms.length} file upload form(s) detected. Manual testing required to verify server-side validation.`,
          evidence: { url, upload_forms: uploadForms.length },
          cvss_score: 0,
          confidence: 'high',
          remediation_text: 'Ensure server-side file type validation, virus scanning, secure storage, and renamed files.',
          remediation_effort_hours: 8,
          owasp_category: 'A04:2021 – Insecure Design',
          cwe_id: 'CWE-434'
        });
      }

    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}
module.exports = FileUploadScanner;
