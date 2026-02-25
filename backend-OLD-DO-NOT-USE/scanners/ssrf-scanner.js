/**
 * SSRF Scanner - Server-Side Request Forgery
 * Detects SSRF vulnerabilities using SecureHttpClient
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class SSRFScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });
    this.ssrfPayloads = [
      'http://169.254.169.254/latest/meta-data/',  // AWS metadata
      'http://metadata.google.internal/',           // GCP metadata
      'http://169.254.169.254/metadata/v1/',        // DO metadata
      'http://100.100.100.200/latest/meta-data/',   // Alibaba metadata
      'http://[::1]/',                              // IPv6 localhost
      'http://0/',                                  // 0 = localhost on some systems
      'dict://127.0.0.1:6379/',                     // Redis
      'gopher://127.0.0.1:6379/',                   // Redis via gopher
      'file:///etc/passwd',                         // Local file
      'http://2130706433/',                         // 127.0.0.1 decimal
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting SSRF scan', { url });

      // 1. Find URL parameters that might fetch external resources
      const urlParams = await this.findUrlFetchingParams(url);
      
      // 2. Test each parameter with SSRF payloads
      for (const param of urlParams) {
        for (const payload of this.ssrfPayloads.slice(0, 5)) { // Top 5 payloads
          try {
            const testUrl = this.buildTestUrl(url, param, payload);
            // Use our own client - the SSRF is about the TARGET server fetching internal URLs
            // We send the payload as a parameter value
            const resp = await this.httpClient.get(testUrl);
            
            // If we get back content that looks like metadata or internal data
            if (this.detectSSRFResponse(resp.data, payload)) {
              findings.push({
                severity: 'critical',
                category: 'ssrf',
                type: 'server_side_request_forgery',
                title: `SSRF via parameter '${param}'`,
                description: `The application appears to fetch the URL specified in the '${param}' parameter. This could allow an attacker to make requests to internal services.`,
                parameter: param,
                payload: payload,
                evidence: {
                  url: testUrl,
                  payload: payload,
                  response_size: resp.data?.length
                },
                cvss_score: 9.1,
                confidence: 'high',
                remediation_text: 'Validate and whitelist URLs. Block requests to private IP ranges. Use a DNS resolver to check target IPs before making requests.',
                remediation_effort_hours: 3,
                owasp_category: 'A10:2021 – Server-Side Request Forgery',
                cwe_id: 'CWE-918'
              });
              break; // One finding per parameter
            }
          } catch (e) {
            // SSRF blocked or network error - expected
          }
          await this.sleep(150);
        }
      }

      // 3. Check for open redirect that could lead to SSRF
      const redirectVulns = await this.checkOpenRedirectSSRF(url);
      findings.push(...redirectVulns);

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'SSRF scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  async findUrlFetchingParams(url) {
    const suspectParams = ['url', 'uri', 'link', 'src', 'source', 'path', 'dest',
      'destination', 'redirect', 'return', 'next', 'continue', 'site', 'fetch',
      'request', 'proxy', 'forward', 'host', 'webhook', 'callback', 'endpoint'];
    
    const found = [];
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.forEach((_, key) => {
        if (suspectParams.some(p => key.toLowerCase().includes(p))) {
          found.push(key);
        } else {
          found.push(key); // Test all params
        }
      });

      // Also parse page for forms
      const resp = await this.httpClient.get(url, { timeout: 5000 });
      if (resp.data) {
        const $ = cheerio.load(resp.data);
        $('form input[name], form textarea[name]').each((_, el) => {
          const name = $(el).attr('name');
          if (name && !found.includes(name)) {
            if (suspectParams.some(p => name.toLowerCase().includes(p))) {
              found.push(name);
            }
          }
        });
      }
    } catch (e) {}
    
    return found.length > 0 ? found : ['url', 'link', 'src']; // Default params to test
  }

  buildTestUrl(baseUrl, param, payload) {
    try {
      const u = new URL(baseUrl);
      u.searchParams.set(param, payload);
      return u.toString();
    } catch (e) {
      return `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
    }
  }

  detectSSRFResponse(body, payload) {
    if (!body || typeof body !== 'string') return false;
    const indicators = ['ami-id', 'instance-id', 'meta-data', 'internal-ip',
      'root:', '/bin/bash', 'instance-type', 'local-ipv4'];
    return indicators.some(ind => body.toLowerCase().includes(ind));
  }

  async checkOpenRedirectSSRF(url) {
    const findings = [];
    try {
      const testUrl = this.buildTestUrl(url, 'redirect', 'http://evil.com');
      const resp = await this.httpClient.get(testUrl);
      // If 3xx pointing to external - open redirect
      if (resp.status >= 300 && resp.status < 400) {
        const location = resp.headers?.location || '';
        if (location.includes('evil.com')) {
          findings.push({
            severity: 'medium',
            category: 'ssrf',
            type: 'open_redirect',
            title: 'Open Redirect (potential SSRF enabler)',
            description: 'Application redirects to attacker-controlled URLs, which can be chained with SSRF attacks.',
            parameter: 'redirect',
            payload: 'http://evil.com',
            cvss_score: 6.1,
            confidence: 'high',
            remediation_text: 'Validate redirect destinations against a whitelist of allowed URLs.',
            remediation_effort_hours: 2,
            owasp_category: 'A01:2021 – Broken Access Control',
            cwe_id: 'CWE-601'
          });
        }
      }
    } catch (e) {}
    return findings;
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = SSRFScanner;
