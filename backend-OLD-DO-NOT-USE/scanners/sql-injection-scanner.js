/**
 * SQL Injection Scanner - Alternative implementation focusing on error patterns
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class SQLInjectionScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 12000, maxContentLength: 5 * 1024 * 1024 });
    this.payloads = ["'", '"', "1'", "1\"", "\\", "1\\", "--", "#", "/*", "';--", "'/*"];
    this.errorSignatures = {
      mysql: [/you have an error in your sql syntax/i, /mysql_fetch/i, /warning.*mysql/i],
      mssql: [/microsoft sql server/i, /odbc sql server driver/i, /unclosed quotation mark/i],
      oracle: [/ora-\d{5}/i, /oracle error/i],
      postgres: [/postgresql error/i, /pg_query/i, /unterminated quoted string/i],
      sqlite: [/sqlite_/i, /sql logic error/i]
    };
  }

  async scan(url) {
    const findings = [];
    const errors = [];
    try {
      logger.logInfo('Starting SQLi scan (alt)', { url });
      const urlObj = new URL(url);
      const params = [];
      urlObj.searchParams.forEach((_, k) => params.push(k));

      for (const param of params.slice(0, 8)) {
        for (const payload of this.payloads) {
          try {
            const t = new URL(url);
            t.searchParams.set(param, (t.searchParams.get(param) || '') + payload);
            const resp = await this.httpClient.get(t.toString(), { timeout: 8000 });
            const body = typeof resp.data === 'string' ? resp.data : JSON.stringify(resp.data || '');

            for (const [dbType, patterns] of Object.entries(this.errorSignatures)) {
              if (patterns.some(p => p.test(body))) {
                findings.push({
                  severity: 'critical',
                  category: 'injection',
                  type: 'sql_injection',
                  title: `SQL Injection (${dbType.toUpperCase()}) in '${param}'`,
                  description: `${dbType.toUpperCase()} error detected when injecting into '${param}'. Application constructs SQL queries from user input.`,
                  parameter: param,
                  payload,
                  evidence: { url: t.toString(), db_type: dbType },
                  cvss_score: 9.8,
                  confidence: 'high',
                  remediation_text: 'Use parameterized queries or prepared statements. Never build SQL with string concatenation.',
                  remediation_effort_hours: 6,
                  owasp_category: 'A03:2021 – Injection',
                  cwe_id: 'CWE-89'
                });
                return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
              }
            }
          } catch (e) {}
          await this.sleep(150);
        }
      }
    } catch (err) {
      errors.push(err.message);
    }
    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}
module.exports = SQLInjectionScanner;
