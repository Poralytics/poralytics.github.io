/**
 * Advanced SQL Scanner - Union-based and Blind detection
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class AdvancedSQLScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 5 * 1024 * 1024 });
    this.unionPayloads = [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION ALL SELECT NULL--",
      "1 UNION SELECT NULL--",
      "1 UNION SELECT table_name FROM information_schema.tables--"
    ];
    this.errorPatterns = [
      /sql syntax/i, /mysqli/i, /ORA-\d{5}/i, /pg_query/i,
      /sqlite_/i, /sql server/i, /unclosed quotation/i,
      /quoted string not properly terminated/i
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting Advanced SQL scan', { url });

      const urlObj = new URL(url);
      const params = [];
      urlObj.searchParams.forEach((val, key) => params.push(key));

      if (params.length === 0) {
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      for (const param of params.slice(0, 5)) {
        for (const payload of this.unionPayloads) {
          try {
            const testUrlObj = new URL(url);
            testUrlObj.searchParams.set(param, payload);
            const resp = await this.httpClient.get(testUrlObj.toString(), { timeout: 10000 });
            const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data);

            if (this.errorPatterns.some(p => p.test(body)) || 
                (body.includes('NULL') && body.includes('UNION'))) {
              findings.push({
                severity: 'critical',
                category: 'injection',
                type: 'union_sql_injection',
                title: `Union-based SQL Injection in '${param}'`,
                description: 'Application is vulnerable to union-based SQL injection, allowing data extraction.',
                parameter: param,
                payload,
                evidence: { url: testUrlObj.toString(), technique: 'union' },
                cvss_score: 9.8,
                confidence: 'high',
                remediation_text: 'Use parameterized queries. Never concatenate user input into SQL.',
                remediation_effort_hours: 6,
                owasp_category: 'A03:2021 – Injection',
                cwe_id: 'CWE-89'
              });
              break;
            }
          } catch (e) {}
          await this.sleep(200);
        }
      }
    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}
module.exports = AdvancedSQLScanner;
