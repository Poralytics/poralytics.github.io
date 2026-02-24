/**
 * Command Injection Scanner
 * Tests OS command injection via time-based and error-based detection
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class CommandInjectionScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 5 * 1024 * 1024 });
    
    this.payloads = {
      errorBased: [
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '`cat /etc/passwd`',
        '$(cat /etc/passwd)',
        '; id',
        '| id',
        '`id`',
        '$(id)',
        '; whoami',
        '| whoami'
      ],
      timeBased: [
        '; sleep 5',
        '| sleep 5',
        '`sleep 5`',
        '$(sleep 5)',
        '; ping -c 3 127.0.0.1',
        '& ping -n 3 127.0.0.1',
        '| timeout 5 bash'
      ],
      windows: [
        '& dir',
        '| dir',
        '&& dir',
        '|| dir',
        '; type C:\\Windows\\win.ini',
        '& type C:\\Windows\\win.ini'
      ]
    };

    this.indicators = [
      /^root:/m, /uid=\d+/i, /gid=\d+/i, /bin\/bash/i,
      /\/etc\/passwd/i, /nobody:/m, /daemon:/m, /www-data:/m,
      /\[boot loader\]/i, /\[operating systems\]/i  // Windows
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting Command Injection scan', { url });

      // Get baseline response and timing
      const baselineStart = Date.now();
      let baseline;
      try {
        baseline = await this.httpClient.get(url, { timeout: 5000 });
      } catch (e) {
        errors.push('Cannot reach target: ' + e.message);
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }
      const baselineDuration = Date.now() - baselineStart;

      // Get input points
      const params = await this.getInputPoints(url, baseline);

      for (const param of params.slice(0, 10)) { // Limit to first 10 params
        // 1. Error-based detection
        for (const payload of this.payloads.errorBased.slice(0, 5)) {
          try {
            const testUrl = this.injectParam(url, param, payload);
            const resp = await this.httpClient.get(testUrl);
            
            if (this.detectErrorOutput(resp.data)) {
              findings.push({
                severity: 'critical',
                category: 'injection',
                type: 'command_injection',
                title: `OS Command Injection in parameter '${param}'`,
                description: `The application executes OS commands constructed from user input in parameter '${param}'. Attackers can execute arbitrary commands on the server.`,
                parameter: param,
                payload: payload,
                evidence: {
                  url: testUrl,
                  method: 'GET',
                  detection: 'error_based',
                  response_contains: this.getMatchedIndicator(resp.data)
                },
                cvss_score: 10.0,
                confidence: 'high',
                remediation_text: 'Never pass user input to OS commands. Use safe APIs instead. If unavoidable, whitelist allowed characters strictly.',
                remediation_effort_hours: 8,
                owasp_category: 'A03:2021 – Injection',
                cwe_id: 'CWE-78'
              });
              break;
            }
          } catch (e) {}
          await this.sleep(200);
        }

        if (findings.find(f => f.parameter === param)) continue; // Already found for this param

        // 2. Time-based detection
        for (const payload of this.payloads.timeBased.slice(0, 3)) {
          try {
            const testUrl = this.injectParam(url, param, payload);
            const start = Date.now();
            await this.httpClient.get(testUrl, { timeout: 12000 });
            const duration = Date.now() - start;

            if (duration > baselineDuration + 4000) {
              findings.push({
                severity: 'critical',
                category: 'injection',
                type: 'command_injection',
                title: `Time-based Command Injection in '${param}'`,
                description: `The application appears to execute the injected sleep command, indicating OS command injection vulnerability.`,
                parameter: param,
                payload: payload,
                evidence: {
                  url: testUrl,
                  detection: 'time_based',
                  baseline_ms: baselineDuration,
                  injected_ms: duration,
                  delay_ms: duration - baselineDuration
                },
                cvss_score: 9.8,
                confidence: 'medium',
                remediation_text: 'Do not construct OS commands from user input. Use parameterized APIs.',
                remediation_effort_hours: 8,
                owasp_category: 'A03:2021 – Injection',
                cwe_id: 'CWE-78'
              });
              break;
            }
          } catch (e) {}
          await this.sleep(200);
        }
      }

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'Command injection scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  async getInputPoints(url, baseline) {
    const params = [];
    try {
      const u = new URL(url);
      u.searchParams.forEach((_, k) => params.push(k));
      
      if (baseline?.data) {
        const $ = cheerio.load(baseline.data);
        $('input[name], textarea[name], select[name]').each((_, el) => {
          const name = $(el).attr('name');
          if (name && !params.includes(name)) params.push(name);
        });
      }
    } catch (e) {}
    return params.length > 0 ? params : ['q', 'search', 'input', 'cmd', 'exec'];
  }

  injectParam(baseUrl, param, payload) {
    try {
      const u = new URL(baseUrl);
      u.searchParams.set(param, payload);
      return u.toString();
    } catch (e) {
      return `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
    }
  }

  detectErrorOutput(body) {
    if (!body || typeof body !== 'string') return false;
    return this.indicators.some(pattern => pattern.test(body));
  }

  getMatchedIndicator(body) {
    if (!body) return '';
    for (const pattern of this.indicators) {
      const m = body.match(pattern);
      if (m) return m[0].substring(0, 50);
    }
    return '';
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = CommandInjectionScanner;
