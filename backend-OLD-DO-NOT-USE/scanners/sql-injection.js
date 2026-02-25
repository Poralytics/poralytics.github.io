/**
 * SQL INJECTION SCANNER
 * Détecte les vulnérabilités SQL injection basiques
 */

const axios = require('axios');

class SQLInjectionScanner {
  constructor() {
    this.name = 'SQL Injection Scanner';
    this.severity = 'critical';
    this.payloads = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "admin' --",
      "admin' #",
      "' UNION SELECT NULL--",
      "1' AND '1'='1",
      "1' AND '1'='2"
    ];
    this.errorPatterns = [
      /SQL syntax.*?error/i,
      /mysql_fetch/i,
      /PostgreSQL.*?ERROR/i,
      /Warning.*?mysql/i,
      /ORA-\d{5}/i,
      /SQL Server.*?error/i,
      /unclosed quotation mark/i,
      /quoted string not properly terminated/i
    ];
  }

  async scan(url) {
    const vulnerabilities = [];
    const startTime = Date.now();

    try {
      // Test différents endpoints avec payloads
      const testUrls = this.generateTestUrls(url);

      for (const testUrl of testUrls) {
        for (const payload of this.payloads) {
          try {
            const response = await axios.get(testUrl + payload, {
              timeout: 5000,
              validateStatus: () => true // Accept all status codes
            });

            // Check pour erreurs SQL dans la réponse
            if (this.detectSQLError(response.data)) {
              vulnerabilities.push({
                type: 'sql_injection',
                severity: 'critical',
                title: 'SQL Injection Vulnerability Detected',
                description: `SQL error message found in response when testing URL with payload: "${payload}"`,
                url: testUrl,
                evidence: this.extractEvidence(response.data),
                payload_used: payload,
                recommendation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
                cvss_score: 9.8,
                cwe: 'CWE-89'
              });
              break; // Un payload suffit pour confirmer la vuln
            }

            // Check temps de réponse anormal (possible blind SQL injection)
            const responseTime = Date.now() - startTime;
            if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
              if (responseTime > 5000) {
                vulnerabilities.push({
                  type: 'sql_injection',
                  severity: 'high',
                  title: 'Possible Blind SQL Injection (Time-Based)',
                  description: 'Response time increased significantly with time-based payload',
                  url: testUrl,
                  evidence: `Response time: ${responseTime}ms`,
                  payload_used: payload,
                  recommendation: 'Investigate time-based blind SQL injection. Use parameterized queries.',
                  cvss_score: 8.5,
                  cwe: 'CWE-89'
                });
              }
            }

          } catch (error) {
            // Timeout ou erreur réseau = pas de vulnérabilité
            continue;
          }
        }
      }

    } catch (error) {
      console.error('SQL Scanner error:', error.message);
    }

    const duration = Date.now() - startTime;
    return {
      scanner: this.name,
      vulnerabilities,
      duration_ms: duration,
      tested_payloads: this.payloads.length,
      status: 'completed'
    };
  }

  generateTestUrls(baseUrl) {
    // Génère des URLs de test avec paramètres
    const urls = [
      baseUrl + '?id=1',
      baseUrl + '?user=admin',
      baseUrl + '?search=test',
      baseUrl + '/api/user?id=1',
      baseUrl + '/login?username=test'
    ];
    return urls;
  }

  detectSQLError(responseText) {
    if (typeof responseText !== 'string') {
      responseText = String(responseText);
    }
    
    return this.errorPatterns.some(pattern => pattern.test(responseText));
  }

  extractEvidence(responseText) {
    const match = responseText.match(/(?:SQL|MySQL|PostgreSQL|ORA-)[^\n]{0,200}/i);
    return match ? match[0].substring(0, 200) : 'SQL error detected in response';
  }
}

module.exports = SQLInjectionScanner;
