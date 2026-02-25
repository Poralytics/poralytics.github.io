/**
 * REAL SQL Injection Scanner
 * Tests actual SQL injection vulnerabilities
 */

const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class RealSQLScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
    this.payloads = [
      // Basic SQL injection payloads
      "' OR '1'='1",
      "' OR '1'='1' --",
      "' OR '1'='1' /*",
      "admin' --",
      "admin' #",
      "' or 1=1--",
      "' or 1=1#",
      "' or 1=1/*",
      "') or ('1'='1",
      
      // Union-based payloads
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      
      // Error-based payloads
      "' AND 1=CONVERT(int, (SELECT @@version))--",
      "' AND extractvalue(1,concat(0x7e,version()))--",
      
      // Time-based blind payloads
      "' AND SLEEP(5)--",
      "' OR SLEEP(5)--",
      "'; WAITFOR DELAY '0:0:5'--",
      
      // Boolean-based payloads
      "' AND 1=1--",
      "' AND 1=2--"
    ];

    this.sqlErrors = [
      'sql syntax',
      'mysql_fetch',
      'mysql_num_rows',
      'mysqli',
      'pg_query',
      'pg_exec',
      'sqlite_',
      'ora-',
      'postgresql',
      'odbc',
      'jdbc',
      'driver',
      'database error',
      'syntax error',
      'unclosed quotation',
      'quoted string',
      'sql command',
      'mysql error',
      'you have an error in your sql',
      'warning: mysql',
      'warning: pg_',
      'valid mysql result',
      'postgresql query failed',
      'sqlite3::'
    ];

    this.timeout = 10000; // 10 seconds
  }

  /**
   * Scan URL for SQL injection
   */
  async scan(url, options = {}) {
    const results = {
      url,
      vulnerabilities: [],
      tested: 0,
      scanned: new Date().toISOString()
    };

    try {
      // Step 1: Discover input points
      console.log(`[SQL Scanner] Discovering input points for ${url}`);
      const inputPoints = await this.discoverInputPoints(url);
      console.log(`[SQL Scanner] Found ${inputPoints.length} potential input points`);

      // Step 2: Test each input point
      for (const point of inputPoints) {
        results.tested++;
        
        const vulns = await this.testInputPoint(url, point);
        if (vulns.length > 0) {
          results.vulnerabilities.push(...vulns);
        }

        // Rate limiting - don't hammer the server
        await this.sleep(500);
      }

      console.log(`[SQL Scanner] Completed. Found ${results.vulnerabilities.length} vulnerabilities`);
      
    } catch (error) {
      console.error('[SQL Scanner] Error:', error.message);
    }

    return results;
  }

  /**
   * Discover input points (query params, forms)
   */
  async discoverInputPoints(url) {
    const points = [];

    try {
      // Test URL query parameters
      const urlObj = new URL(url);
      const params = Array.from(urlObj.searchParams.keys());
      
      if (params.length > 0) {
        params.forEach(param => {
          points.push({
            type: 'query',
            name: param,
            location: url
          });
        });
      }

      // Fetch page and discover forms
      const response = await this.httpClient.get(url, {
        timeout: this.timeout,
        maxRedirects: 3,
        validateStatus: () => true
      });

      if (response.data) {
        const $ = cheerio.load(response.data);
        
        // Find all forms
        $('form').each((i, form) => {
          const action = $(form).attr('action') || url;
          const method = $(form).attr('method') || 'GET';
          
          // Find all inputs in form
          $(form).find('input, textarea, select').each((j, input) => {
            const name = $(input).attr('name');
            const type = $(input).attr('type') || 'text';
            
            if (name && type !== 'submit' && type !== 'button') {
              points.push({
                type: 'form',
                name,
                formAction: action,
                method: method.toUpperCase(),
                location: url
              });
            }
          });
        });

        // Common parameter names to test
        const commonParams = ['id', 'user', 'username', 'search', 'q', 'page', 'category', 'sort'];
        commonParams.forEach(param => {
          points.push({
            type: 'common',
            name: param,
            location: url
          });
        });
      }

    } catch (error) {
      console.error('[SQL Scanner] Discovery error:', error.message);
    }

    return points;
  }

  /**
   * Test specific input point
   */
  async testInputPoint(baseUrl, point) {
    const vulnerabilities = [];

    for (const payload of this.payloads.slice(0, 10)) { // Test first 10 payloads
      try {
        let testUrl = baseUrl;
        
        if (point.type === 'query' || point.type === 'common') {
          const url = new URL(baseUrl);
          url.searchParams.set(point.name, payload);
          testUrl = url.toString();
        }

        // Make request with payload
        const startTime = Date.now();
        const response = await this.httpClient.get(testUrl, {
          timeout: this.timeout,
          maxRedirects: 3,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'Mozilla/5.0 (NEXUS Security Scanner)'
          }
        }).catch(err => {
          // Handle network errors gracefully
          console.log(`[SQL Scanner] Network error for ${testUrl}: ${err.message}`);
          return null;
        });

        if (!response) continue;

        const responseTime = Date.now() - startTime;

        const body = response.data ? response.data.toString().toLowerCase() : '';
        
        // Check for SQL errors in response
        const foundError = this.sqlErrors.find(error => body.includes(error));
        
        if (foundError) {
          vulnerabilities.push({
            type: 'sql_injection',
            severity: 'critical',
            title: 'SQL Injection Vulnerability',
            description: `SQL injection found in parameter '${point.name}'. SQL error detected in response.`,
            affected_url: testUrl,
            parameter: point.name,
            payload: payload,
            evidence: `SQL error keyword found: ${foundError}`,
            cvss_score: 9.8,
            remediation: 'Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.',
            references: [
              'https://owasp.org/www-community/attacks/SQL_Injection',
              'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
            ]
          });
          
          console.log(`[SQL Scanner] ✓ Found SQL injection in ${point.name}`);
          break; // Found vulnerability, no need to test more payloads for this point
        }

        // Check for time-based blind SQL injection
        if (payload.includes('SLEEP') || payload.includes('WAITFOR')) {
          if (responseTime > 4000) { // Response took > 4 seconds
            vulnerabilities.push({
              type: 'sql_injection',
              severity: 'high',
              title: 'Time-Based Blind SQL Injection',
              description: `Time-based SQL injection found in parameter '${point.name}'. Server delayed response indicating successful injection.`,
              affected_url: testUrl,
              parameter: point.name,
              payload: payload,
              evidence: `Response time: ${responseTime}ms (expected delay: 5000ms)`,
              cvss_score: 8.5,
              remediation: 'Use parameterized queries. Implement input validation.',
              references: [
                'https://owasp.org/www-community/attacks/Blind_SQL_Injection'
              ]
            });
            
            console.log(`[SQL Scanner] ✓ Found time-based SQL injection in ${point.name}`);
            break;
          }
        }

      } catch (error) {
        // Request failed - might be due to WAF or error
        if (error.code === 'ECONNABORTED') {
          // Timeout might indicate time-based injection worked
          console.log(`[SQL Scanner] Timeout on ${point.name} - potential blind SQLi`);
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Sleep helper
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = new RealSQLScanner();
