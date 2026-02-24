/**
 * REAL XSS Scanner
 * Tests actual Cross-Site Scripting vulnerabilities
 */

const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class RealXSSScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
    this.payloads = [
      // Basic XSS payloads
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      '<iframe src="javascript:alert(1)">',
      '<body onload=alert(1)>',
      '<input onfocus=alert(1) autofocus>',
      '<select onfocus=alert(1) autofocus>',
      '<textarea onfocus=alert(1) autofocus>',
      '<marquee onstart=alert(1)>',
      
      // Event handlers
      '<img src=x onerror="alert(String.fromCharCode(88,83,83))">',
      '<iframe src="data:text/html,<script>alert(1)</script>">',
      
      // Encoded payloads
      '%3Cscript%3Ealert(1)%3C/script%3E',
      '&lt;script&gt;alert(1)&lt;/script&gt;',
      
      // DOM-based
      'javascript:alert(1)',
      'data:text/html,<script>alert(1)</script>',
      
      // Filter bypass
      '<scr<script>ipt>alert(1)</scr</script>ipt>',
      '<<SCRIPT>alert(1)//<</SCRIPT>',
      '<img src="x` `onerror=alert(1)>',
      
      // Attribute breaking
      '" onmouseover="alert(1)',
      '\' onmouseover=\'alert(1)',
      '></script><script>alert(1)</script>',
      
      // Polyglot
      'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//'
    ];

    this.xssIndicators = [
      '<script>',
      'onerror',
      'onload',
      'onfocus',
      'alert(',
      'javascript:',
      '<img',
      '<iframe',
      '<svg'
    ];

    this.timeout = 10000;
  }

  /**
   * Scan for XSS
   */
  async scan(url, options = {}) {
    const results = {
      url,
      vulnerabilities: [],
      tested: 0,
      scanned: new Date().toISOString()
    };

    try {
      console.log(`[XSS Scanner] Scanning ${url}`);
      
      // Discover input points
      const inputPoints = await this.discoverInputPoints(url);
      console.log(`[XSS Scanner] Found ${inputPoints.length} input points`);

      // Test each point
      for (const point of inputPoints) {
        results.tested++;
        
        const vulns = await this.testInputPoint(url, point);
        if (vulns.length > 0) {
          results.vulnerabilities.push(...vulns);
        }

        await this.sleep(500);
      }

      console.log(`[XSS Scanner] Found ${results.vulnerabilities.length} XSS vulnerabilities`);

    } catch (error) {
      console.error('[XSS Scanner] Error:', error.message);
    }

    return results;
  }

  /**
   * Discover input points
   */
  async discoverInputPoints(url) {
    const points = [];

    try {
      // URL parameters
      const urlObj = new URL(url);
      Array.from(urlObj.searchParams.keys()).forEach(param => {
        points.push({
          type: 'query',
          name: param,
          location: url
        });
      });

      // Fetch page
      const response = await this.httpClient.get(url, {
        timeout: this.timeout,
        validateStatus: () => true
      });

      if (response.data) {
        const $ = cheerio.load(response.data);

        // Forms
        $('form').each((i, form) => {
          const action = $(form).attr('action') || url;
          const method = $(form).attr('method') || 'GET';

          $(form).find('input, textarea').each((j, input) => {
            const name = $(input).attr('name');
            const type = $(input).attr('type') || 'text';

            if (name && type !== 'submit' && type !== 'hidden') {
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

        // Common XSS parameters
        const commonParams = ['q', 'search', 'query', 'keyword', 'name', 'comment', 'message', 'text'];
        commonParams.forEach(param => {
          points.push({
            type: 'common',
            name: param,
            location: url
          });
        });
      }

    } catch (error) {
      console.error('[XSS Scanner] Discovery error:', error.message);
    }

    return points;
  }

  /**
   * Test input point for XSS
   */
  async testInputPoint(baseUrl, point) {
    const vulnerabilities = [];

    // Test first 8 payloads
    for (const payload of this.payloads.slice(0, 8)) {
      try {
        let testUrl = baseUrl;

        if (point.type === 'query' || point.type === 'common') {
          const url = new URL(baseUrl);
          url.searchParams.set(point.name, payload);
          testUrl = url.toString();
        }

        const response = await this.httpClient.get(testUrl, {
          timeout: this.timeout,
          validateStatus: () => true,
          headers: {
            'User-Agent': 'NEXUS Security Scanner'
          }
        });

        const body = response.data ? response.data.toString() : '';

        // Check if payload is reflected in response
        const isReflected = body.includes(payload) || 
                          this.checkPartialReflection(body, payload);

        if (isReflected) {
          // Check if it's in dangerous context
          const context = this.detectContext(body, payload);

          if (context.vulnerable) {
            vulnerabilities.push({
              type: 'xss',
              severity: context.severity,
              title: `${context.type} XSS Vulnerability`,
              description: `XSS found in parameter '${point.name}'. Payload reflected in ${context.type}.`,
              affected_url: testUrl,
              parameter: point.name,
              payload: payload,
              evidence: `Payload reflected in: ${context.location}`,
              context: context.type,
              cvss_score: context.cvss,
              remediation: 'Encode all user input before displaying. Use Content Security Policy. Implement output encoding.',
              references: [
                'https://owasp.org/www-community/attacks/xss/',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
              ]
            });

            console.log(`[XSS Scanner] ✓ Found ${context.type} XSS in ${point.name}`);
            break;
          }
        }

      } catch (error) {
        // Continue testing
      }
    }

    return vulnerabilities;
  }

  /**
   * Check if payload is partially reflected
   */
  checkPartialReflection(body, payload) {
    // Check for key parts of payload
    for (const indicator of this.xssIndicators) {
      if (payload.includes(indicator) && body.includes(indicator)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Detect context of reflection
   */
  detectContext(body, payload) {
    const bodyLower = body.toLowerCase();
    const payloadLower = payload.toLowerCase();

    // Check different contexts
    if (bodyLower.includes('<script') && bodyLower.includes(payloadLower)) {
      return {
        vulnerable: true,
        type: 'Script Context',
        location: 'Inside <script> tag',
        severity: 'critical',
        cvss: 9.6
      };
    }

    if (bodyLower.includes('onerror') || bodyLower.includes('onload')) {
      return {
        vulnerable: true,
        type: 'Event Handler',
        location: 'HTML event handler',
        severity: 'critical',
        cvss: 9.3
      };
    }

    if (bodyLower.includes('<img') && bodyLower.includes(payloadLower)) {
      return {
        vulnerable: true,
        type: 'HTML Tag',
        location: 'HTML tag attribute',
        severity: 'high',
        cvss: 8.8
      };
    }

    if (bodyLower.includes('href') || bodyLower.includes('src')) {
      return {
        vulnerable: true,
        type: 'URL Context',
        location: 'URL attribute',
        severity: 'high',
        cvss: 8.5
      };
    }

    // Check if reflected but encoded
    if (body.includes('&lt;') || body.includes('&gt;')) {
      return {
        vulnerable: false,
        type: 'Encoded',
        location: 'HTML encoded',
        severity: 'info',
        cvss: 0
      };
    }

    // Reflected in HTML body
    if (body.includes(payload)) {
      return {
        vulnerable: true,
        type: 'Reflected XSS',
        location: 'HTML body',
        severity: 'high',
        cvss: 7.5
      };
    }

    return {
      vulnerable: false,
      type: 'Not vulnerable',
      location: 'N/A',
      severity: 'info',
      cvss: 0
    };
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = new RealXSSScanner();
