/**
 * XSS (Cross-Site Scripting) SCANNER
 * Détecte les vulnérabilités XSS reflected et stored
 */

const axios = require('axios');

class XSSScanner {
  constructor() {
    this.name = 'XSS Scanner';
    this.severity = 'high';
    this.payloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      '"><script>alert("XSS")</script>',
      "'><script>alert('XSS')</script>",
      '<iframe src="javascript:alert(\'XSS\')">',
      '<body onload=alert("XSS")>',
      '<input onfocus=alert("XSS") autofocus>',
      'javascript:alert("XSS")',
      '<a href="javascript:alert(\'XSS\')">Click</a>'
    ];
  }

  async scan(url) {
    const vulnerabilities = [];
    const startTime = Date.now();

    try {
      const testUrls = this.generateTestUrls(url);

      for (const testUrl of testUrls) {
        for (const payload of this.payloads) {
          try {
            // Test GET request avec payload
            const response = await axios.get(testUrl + encodeURIComponent(payload), {
              timeout: 5000,
              validateStatus: () => true
            });

            // Check si le payload est reflected dans la réponse
            if (this.isPayloadReflected(response.data, payload)) {
              vulnerabilities.push({
                type: 'xss',
                severity: 'high',
                title: 'Reflected XSS Vulnerability',
                description: `User input is reflected in the response without proper encoding. Payload "${payload}" was found in the HTML response.`,
                url: testUrl,
                evidence: this.extractEvidence(response.data, payload),
                payload_used: payload,
                recommendation: 'Encode all user input before displaying it. Use Content Security Policy (CSP) headers. Sanitize HTML input.',
                cvss_score: 7.5,
                cwe: 'CWE-79'
              });
              break;
            }

            // Test POST request pour stored XSS
            try {
              const postResponse = await axios.post(testUrl, {
                comment: payload,
                message: payload,
                content: payload
              }, {
                timeout: 5000,
                validateStatus: () => true
              });

              if (this.isPayloadReflected(postResponse.data, payload)) {
                vulnerabilities.push({
                  type: 'xss',
                  severity: 'critical',
                  title: 'Stored XSS Vulnerability',
                  description: 'User input is stored and displayed without encoding, allowing persistent XSS attacks.',
                  url: testUrl,
                  evidence: 'Payload stored and reflected in POST response',
                  payload_used: payload,
                  recommendation: 'Sanitize and encode all stored user content. Use CSP headers. Validate input on both client and server.',
                  cvss_score: 8.5,
                  cwe: 'CWE-79'
                });
                break;
              }
            } catch (postError) {
              // POST failed, continue
            }

          } catch (error) {
            continue;
          }
        }
      }

      // Check pour absence de CSP header
      try {
        const response = await axios.get(url, { timeout: 5000 });
        if (!response.headers['content-security-policy']) {
          vulnerabilities.push({
            type: 'xss',
            severity: 'medium',
            title: 'Missing Content Security Policy',
            description: 'No Content-Security-Policy header found. CSP helps prevent XSS attacks.',
            url,
            evidence: 'Content-Security-Policy header not present',
            recommendation: 'Implement Content-Security-Policy header to restrict script sources.',
            cvss_score: 5.0,
            cwe: 'CWE-693'
          });
        }
      } catch (error) {
        // Ignore
      }

    } catch (error) {
      console.error('XSS Scanner error:', error.message);
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
    return [
      baseUrl + '?q=',
      baseUrl + '?search=',
      baseUrl + '?name=',
      baseUrl + '?message=',
      baseUrl + '?comment='
    ];
  }

  isPayloadReflected(responseText, payload) {
    if (typeof responseText !== 'string') {
      responseText = String(responseText);
    }

    // Check si le payload exact est dans la réponse
    if (responseText.includes(payload)) {
      return true;
    }

    // Check si une version décodée est présente
    const decoded = this.decodeHtml(payload);
    if (responseText.includes(decoded)) {
      return true;
    }

    return false;
  }

  decodeHtml(html) {
    const entities = {
      '&lt;': '<',
      '&gt;': '>',
      '&quot;': '"',
      '&#x27;': "'",
      '&#x2F;': '/'
    };
    return html.replace(/&[^;]+;/g, entity => entities[entity] || entity);
  }

  extractEvidence(responseText, payload) {
    const index = responseText.indexOf(payload);
    if (index === -1) return 'Payload reflected in response';
    
    const start = Math.max(0, index - 50);
    const end = Math.min(responseText.length, index + payload.length + 50);
    return '...' + responseText.substring(start, end) + '...';
  }
}

module.exports = XSSScanner;
