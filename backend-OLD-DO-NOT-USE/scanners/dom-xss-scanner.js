/**
 * DOM XSS SCANNER
 * Détecte les XSS côté client (DOM-based)
 */

const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class DOMXSSScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000 });
    this.name = 'DOM-based XSS';
    
    // Sinks JavaScript dangereux
    this.dangerousSinks = [
      'eval(', 'setTimeout(', 'setInterval(', 'Function(',
      'innerHTML', 'outerHTML', 'document.write(', 'document.writeln(',
      '.html(', // jQuery
      'insertAdjacentHTML(', 'createContextualFragment(',
      'location.href', 'location.replace(', 'location.assign(',
      'window.location'
    ];

    // Sources utilisateur
    this.userSources = [
      'location.hash', 'location.search', 'location.href',
      'document.URL', 'document.documentURI', 'document.referrer',
      'window.name', 'document.cookie',
      'localStorage', 'sessionStorage'
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting DOM XSS scan', { url });

      let response;
      try {
        response = await this.httpClient.get(url);
      } catch (e) {
        errors.push('Target unreachable: ' + e.message);
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      if (!response.data) {
        return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
      }

      // Analyse statique du JavaScript
      await this.analyzeJavaScript(url, response.data, findings);

      // Test avec payloads DOM XSS
      await this.testDOMXSSPayloads(url, findings);

      logger.logInfo('DOM XSS scan completed', { url, found: findings.length });

    } catch (err) {
      logger.logError(err, { context: 'DOMXSSScanner', url });
      errors.push(err.message);
    }

    return {
      vulnerabilities: findings,
      errors,
      url,
      scanned: new Date().toISOString()
    };
  }

  async analyzeJavaScript(url, html, findings) {
    const $ = cheerio.load(html);
    
    // Extraire tout le JavaScript inline et externe
    const scripts = [];
    $('script').each((i, el) => {
      const src = $(el).attr('src');
      const inline = $(el).html();
      if (inline) scripts.push({ type: 'inline', code: inline });
      if (src) scripts.push({ type: 'external', src });
    });

    // Analyser chaque script
    for (const script of scripts) {
      if (script.type === 'inline') {
        this.analyzeScriptCode(url, script.code, findings);
      }
    }
  }

  analyzeScriptCode(url, code, findings) {
    // Chercher patterns dangereux: source → sink
    const patterns = [
      {
        regex: /(location\.hash|location\.search|document\.URL).*(?:innerHTML|eval|document\.write)/s,
        desc: 'User-controlled data flows to dangerous sink',
        severity: 'high'
      },
      {
        regex: /(?:location\.hash|location\.search).*?(?:=|innerHTML|eval)/,
        desc: 'URL parameter directly used in sink',
        severity: 'high'
      },
      {
        regex: /eval\s*\(\s*(?:location|document\.URL|window\.name)/,
        desc: 'eval() with user-controlled input',
        severity: 'critical'
      },
      {
        regex: /innerHTML\s*=.*?location/,
        desc: 'innerHTML set from location object',
        severity: 'high'
      },
      {
        regex: /\$\([^)]*\)\.html\(.*?location/,
        desc: 'jQuery .html() with location data',
        severity: 'high'
      }
    ];

    for (const pattern of patterns) {
      if (pattern.regex.test(code)) {
        const match = code.match(pattern.regex);
        const evidence = match ? match[0].substring(0, 150) : 'Pattern matched';
        
        findings.push({
          severity: pattern.severity,
          category: 'Cross-Site Scripting (XSS)',
          title: `DOM-based XSS: ${pattern.desc}`,
          description: `Static analysis detected potential DOM XSS vulnerability. ${pattern.desc}. This allows attacker to inject malicious JavaScript via URL fragments or parameters.`,
          evidence: evidence,
          cvss_score: pattern.severity === 'critical' ? 8.8 : 7.5,
          cwe_id: 'CWE-79',
          owasp_category: 'A03:2021 - Injection',
          confidence: 'medium',
          remediation_text: 'Sanitize all user input before using in DOM manipulation. Use textContent instead of innerHTML, or use a safe HTML sanitizer library like DOMPurify.'
        });
      }
    }

    // Chercher sources et sinks séparément
    let foundSource = false;
    let foundSink = false;
    let sourceDetails = '';
    let sinkDetails = '';

    for (const source of this.userSources) {
      if (code.includes(source)) {
        foundSource = true;
        sourceDetails = source;
        break;
      }
    }

    for (const sink of this.dangerousSinks) {
      if (code.includes(sink)) {
        foundSink = true;
        sinkDetails = sink;
        break;
      }
    }

    if (foundSource && foundSink) {
      findings.push({
        severity: 'medium',
        category: 'Cross-Site Scripting (XSS)',
        title: `Potential DOM XSS: Source and Sink Present`,
        description: `Code contains user-controllable source (${sourceDetails}) and dangerous sink (${sinkDetails}). Manual review recommended to confirm if there's a direct data flow.`,
        evidence: `Source: ${sourceDetails}, Sink: ${sinkDetails}`,
        cvss_score: 6.5,
        cwe_id: 'CWE-79',
        confidence: 'low',
        remediation_text: 'Review data flow from source to sink. Implement input validation and output encoding.'
      });
    }
  }

  async testDOMXSSPayloads(url, findings) {
    // Payloads DOM XSS qui s'exécutent dans le contexte client
    const payloads = [
      '#<img src=x onerror=alert(document.domain)>',
      '#<svg onload=alert(1)>',
      '?q=<script>alert(1)</script>',
      '#javascript:alert(1)'
    ];

    for (const payload of payloads) {
      try {
        const testUrl = url.includes('#') || url.includes('?') 
          ? url + payload.replace(/^[#?]/, '&')
          : url + payload;
        
        const response = await this.httpClient.get(testUrl, { timeout: 5000 });
        
        // Vérifier si le payload est reflété sans encoding dans le HTML
        if (response.data) {
          const unencoded = payload.substring(1).replace(/</g, '').replace(/>/g, '');
          
          if (response.data.includes(payload.substring(1)) && 
              !response.data.includes(payload.substring(1).replace(/</g, '&lt;'))) {
            findings.push({
              severity: 'high',
              category: 'Cross-Site Scripting (XSS)',
              title: `Reflected DOM XSS`,
              description: `DOM XSS payload was reflected in the response without proper encoding. This allows JavaScript execution in victim's browser.`,
              parameter: 'URL fragment/query',
              payload,
              evidence: `Payload reflected unencoded in response`,
              cvss_score: 7.8,
              cwe_id: 'CWE-79',
              confidence: 'high',
              remediation_text: 'Encode all output. Use textContent or innerText instead of innerHTML when displaying user data.'
            });
            return; // Found one, stop testing
          }
        }
      } catch (e) {
        // Errors are normal for XSS testing
      }
    }
  }
}

module.exports = DOMXSSScanner;
