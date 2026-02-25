/**
 * Component Scanner - Outdated/vulnerable components
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class ComponentScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
    this.knownVulnerablePatterns = [
      { pattern: /jquery[/-]([0-9.]+)/, name: 'jQuery', minSafe: '3.7.0' },
      { pattern: /angular[.-]([0-9.]+)/, name: 'AngularJS', minSafe: '1.8.3' },
      { pattern: /bootstrap[/-]([0-9.]+)/, name: 'Bootstrap', minSafe: '5.3.0' },
      { pattern: /lodash[/-]([0-9.]+)/, name: 'Lodash', minSafe: '4.17.21' },
      { pattern: /moment[/-]([0-9.]+)/, name: 'Moment.js', minSafe: null }  // Deprecated
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Component scan', { url });
      const resp = await this.httpClient.get(url, { timeout: 8000 });
      if (!resp.data || typeof resp.data !== 'string') {
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      const body = resp.data;
      const $ = cheerio.load(body);

      // Check script sources
      const scripts = [];
      $('script[src]').each((_, el) => scripts.push($(el).attr('src') || ''));

      // Check for known components
      for (const comp of this.knownVulnerablePatterns) {
        for (const src of scripts) {
          const match = src.match(comp.pattern);
          if (match) {
            const version = match[1];
            if (!comp.minSafe) {
              findings.push({
                severity: 'medium',
                category: 'components',
                type: 'deprecated_component',
                title: `Deprecated Component: ${comp.name} ${version}`,
                description: `${comp.name} is deprecated and no longer receives security updates.`,
                evidence: { url, src, version },
                cvss_score: 5.4,
                confidence: 'high',
                remediation_text: `Replace ${comp.name} with a maintained alternative.`,
                remediation_effort_hours: 8,
                owasp_category: 'A06:2021 – Vulnerable and Outdated Components',
                cwe_id: 'CWE-1104'
              });
            }
          }
        }

        // Also check inline body
        const bodyMatch = body.match(comp.pattern);
        if (bodyMatch) {
          const version = bodyMatch[1];
          findings.push({
            severity: 'low',
            category: 'components',
            type: 'component_version_disclosure',
            title: `Component Version Disclosed: ${comp.name} ${version}`,
            description: `${comp.name} version ${version} is disclosed in page source.`,
            evidence: { url, component: comp.name, version },
            cvss_score: 3.1,
            confidence: 'medium',
            remediation_text: `Remove version numbers from component includes.`,
            remediation_effort_hours: 1,
            owasp_category: 'A06:2021 – Vulnerable and Outdated Components',
            cwe_id: 'CWE-200'
          });
        }
      }

      // Check for exposed package.json or similar
      try {
        const pkgResp = await this.httpClient.get(new URL(url).origin + '/package.json', { timeout: 3000 });
        if (pkgResp.status === 200 && pkgResp.data?.dependencies) {
          findings.push({
            severity: 'medium',
            category: 'components',
            type: 'package_json_exposed',
            title: 'package.json Publicly Accessible',
            description: 'package.json is publicly accessible, revealing all dependency names and versions.',
            evidence: { url: new URL(url).origin + '/package.json', status: pkgResp.status },
            cvss_score: 5.3,
            confidence: 'high',
            remediation_text: 'Block access to package.json in web server configuration.',
            remediation_effort_hours: 1,
            owasp_category: 'A06:2021 – Vulnerable and Outdated Components',
            cwe_id: 'CWE-200'
          });
        }
      } catch (e) {}

    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }
}
module.exports = ComponentScanner;
