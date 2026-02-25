/**
 * Business Logic Scanner
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class BusinessLogicScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Business Logic scan', { url });

      // 1. Check for negative price/quantity in e-commerce
      const urlObj = new URL(url);
      const ecomParams = ['price', 'amount', 'quantity', 'qty', 'total', 'cost'];
      for (const param of ecomParams) {
        urlObj.searchParams.set(param, '-1');
        try {
          const resp = await this.httpClient.get(urlObj.toString(), { timeout: 5000 });
          if (resp.status === 200) {
            const body = JSON.stringify(resp.data || '');
            if (body.includes('-1') || body.includes('success')) {
              findings.push({
                severity: 'high',
                category: 'business_logic',
                type: 'negative_value_accepted',
                title: `Negative Value Accepted in '${param}'`,
                description: `The application accepts negative values for '${param}', potentially allowing price manipulation.`,
                parameter: param,
                payload: '-1',
                evidence: { url: urlObj.toString(), status: resp.status },
                cvss_score: 7.5,
                confidence: 'low',
                remediation_text: 'Validate all numeric inputs server-side. Reject negative values for prices, quantities, etc.',
                remediation_effort_hours: 4,
                owasp_category: 'A04:2021 – Insecure Design',
                cwe_id: 'CWE-20'
              });
            }
          }
        } catch (e) {}
        urlObj.searchParams.delete(param);
        await this.sleep(100);
      }

      // 2. Check for parameter pollution
      const paramPollutionUrl = url + (url.includes('?') ? '&id=1&id=2' : '?id=1&id=2');
      try {
        const resp1 = await this.httpClient.get(url, { timeout: 5000 });
        const resp2 = await this.httpClient.get(paramPollutionUrl, { timeout: 5000 });
        if (resp2.status === 200 && resp1.data !== resp2.data) {
          findings.push({
            severity: 'medium',
            category: 'business_logic',
            type: 'http_parameter_pollution',
            title: 'HTTP Parameter Pollution',
            description: 'Application behaves differently with duplicate parameters.',
            evidence: { url: paramPollutionUrl },
            cvss_score: 5.4,
            confidence: 'low',
            remediation_text: 'Define explicit behavior for duplicate parameters.',
            remediation_effort_hours: 2,
            owasp_category: 'A04:2021 – Insecure Design',
            cwe_id: 'CWE-20'
          });
        }
      } catch (e) {}

    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}
module.exports = BusinessLogicScanner;
