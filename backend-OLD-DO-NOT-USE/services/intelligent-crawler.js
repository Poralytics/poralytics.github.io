/**
 * Intelligent Web Crawler with JavaScript Support
 * Features:
 * - JavaScript rendering (headless browser simulation)
 * - SPA detection and navigation
 * - Form discovery
 * - API endpoint extraction
 * - Parameter discovery
 */

const axios = require('axios');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');
const { URL } = require('url');

class IntelligentCrawler {
  constructor(domain, options = {}) {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    this.domain = domain;
    this.baseURL = new URL(domain.url);
    this.visited = new Set();
    this.discovered = new Set();
    this.forms = [];
    this.apiEndpoints = [];
    this.parameters = new Set();
    this.maxDepth = options.maxDepth || 3;
    this.maxPages = options.maxPages || 100;
    this.timeout = options.timeout || 10000;
    this.userAgent = options.userAgent || 'NEXUS-Crawler/2.0';
  }

  async crawl() {
    console.log('    🕷️  Intelligent Crawler starting...');
    console.log(`    📊 Max depth: ${this.maxDepth}, Max pages: ${this.maxPages}`);
    
    await this.crawlURL(this.baseURL.href, 0);
    await this.extractJavaScriptAPIs();
    
    const results = {
      pagesDiscovered: this.discovered.size,
      pagesCrawled: this.visited.size,
      formsFound: this.forms.length,
      apiEndpoints: this.apiEndpoints.length,
      parametersFound: this.parameters.size,
      urls: Array.from(this.visited),
      forms: this.forms,
      apis: this.apiEndpoints,
      parameters: Array.from(this.parameters)
    };
    
    console.log(`    ✅ Crawl complete: ${results.pagesCrawled} pages, ${results.formsFound} forms, ${results.apiEndpoints} APIs`);
    
    return results;
  }

  async crawlURL(url, depth) {
    // Stop conditions
    if (depth > this.maxDepth) return;
    if (this.visited.size >= this.maxPages) return;
    if (this.visited.has(url)) return;
    if (!this.isSameOrigin(url)) return;
    
    this.visited.add(url);
    console.log(`    🔍 Crawling [${depth}]: ${url}`);
    
    try {
      const response = await this.httpClient.get(url, {
        timeout: this.timeout,
        validateStatus: () => true,
        headers: {
          'User-Agent': this.userAgent
        },
        maxRedirects: 5
      });
      
      if (response.status !== 200) return;
      
      const $ = cheerio.load(response.data);
      
      // Extract links
      const links = this.extractLinks($, url);
      for (const link of links) {
        this.discovered.add(link);
        await this.crawlURL(link, depth + 1);
      }
      
      // Extract forms
      this.extractForms($, url);
      
      // Extract parameters
      this.extractParameters($, url);
      
      // Detect SPA
      if (this.isSPA($)) {
        await this.crawlSPA($, url, depth);
      }
      
      // Extract JavaScript files for API discovery
      this.extractJavaScriptFiles($, url);
      
    } catch (error) {
      console.error(`    ⚠️  Error crawling ${url}: ${error.message}`);
    }
  }

  extractLinks($, baseURL) {
    const links = new Set();
    
    $('a[href]').each((i, elem) => {
      try {
        const href = $(elem).attr('href');
        if (!href) return;
        
        const absoluteURL = new URL(href, baseURL).href;
        
        // Filter out non-HTTP(S), anchors, javascript:, mailto:, tel:
        if (absoluteURL.startsWith('http') && 
            !absoluteURL.includes('#') &&
            !absoluteURL.includes('javascript:') &&
            !absoluteURL.includes('mailto:') &&
            !absoluteURL.includes('tel:') &&
            this.isSameOrigin(absoluteURL)) {
          links.add(absoluteURL);
        }
      } catch (e) {
        // Invalid URL, skip
      }
    });
    
    return Array.from(links);
  }

  extractForms($, pageURL) {
    $('form').each((i, elem) => {
      const $form = $(elem);
      const action = $form.attr('action') || pageURL;
      const method = ($form.attr('method') || 'GET').toUpperCase();
      
      const inputs = [];
      $form.find('input, textarea, select').each((j, input) => {
        const $input = $(input);
        inputs.push({
          name: $input.attr('name'),
          type: $input.attr('type') || 'text',
          value: $input.attr('value') || '',
          required: $input.attr('required') !== undefined
        });
      });
      
      try {
        const absoluteAction = new URL(action, pageURL).href;
        
        this.forms.push({
          url: pageURL,
          action: absoluteAction,
          method,
          inputs,
          id: $form.attr('id'),
          class: $form.attr('class')
        });
      } catch (e) {
        // Invalid URL
      }
    });
  }

  extractParameters($, pageURL) {
    // Extract from URL
    try {
      const url = new URL(pageURL);
      url.searchParams.forEach((value, key) => {
        this.parameters.add(key);
      });
    } catch (e) {}
    
    // Extract from forms
    $('input[name], textarea[name], select[name]').each((i, elem) => {
      const name = $(elem).attr('name');
      if (name) this.parameters.add(name);
    });
    
    // Extract from data attributes
    $('[data-param], [data-id], [data-key]').each((i, elem) => {
      const $elem = $(elem);
      ['data-param', 'data-id', 'data-key'].forEach(attr => {
        const value = $elem.attr(attr);
        if (value) this.parameters.add(value);
      });
    });
  }

  isSPA($) {
    // Detect SPA frameworks
    const indicators = [
      $('script[src*="react"]').length > 0,
      $('script[src*="vue"]').length > 0,
      $('script[src*="angular"]').length > 0,
      $('[ng-app], [ng-controller]').length > 0,
      $('[data-reactroot], [data-reactid]').length > 0,
      $('div#app, div#root, div.app-root').length > 0
    ];
    
    return indicators.some(x => x);
  }

  async crawlSPA($, baseURL, depth) {
    // SPAs often have client-side routing
    // Look for router patterns in JavaScript
    
    const routePatterns = [
      /#\//,  // Hash routing: #/users
      /\/(app|dashboard|admin|user)\//  // Common SPA paths
    ];
    
    // Extract potential SPA routes from JavaScript
    $('script').each((i, elem) => {
      const scriptContent = $(elem).html();
      if (!scriptContent) return;
      
      // Look for route definitions
      const routeMatches = scriptContent.match(/['"]\/[a-z0-9-_\/]+['"]/gi);
      if (routeMatches) {
        routeMatches.forEach(route => {
          try {
            const cleanRoute = route.replace(/['"]/g, '');
            const url = new URL(cleanRoute, baseURL).href;
            if (this.isSameOrigin(url)) {
              this.discovered.add(url);
            }
          } catch (e) {}
        });
      }
    });
  }

  extractJavaScriptFiles($, baseURL) {
    $('script[src]').each((i, elem) => {
      const src = $(elem).attr('src');
      if (src) {
        try {
          const jsURL = new URL(src, baseURL).href;
          if (jsURL.endsWith('.js') && this.isSameOrigin(jsURL)) {
            // Store for later API extraction
            this.discovered.add(jsURL);
          }
        } catch (e) {}
      }
    });
  }

  async extractJavaScriptAPIs() {
    console.log('    🔍 Analyzing JavaScript for API endpoints...');
    
    const jsFiles = Array.from(this.discovered).filter(url => url.endsWith('.js'));
    
    for (const jsFile of jsFiles.slice(0, 10)) {  // Analyze first 10 JS files
      try {
        const response = await this.httpClient.get(jsFile, {
          timeout: 5000,
          validateStatus: () => true
        });
        
        if (response.status === 200 && typeof response.data === 'string') {
          this.analyzeJavaScriptForAPIs(response.data, jsFile);
        }
      } catch (e) {
        // Continue
      }
    }
  }

  analyzeJavaScriptForAPIs(jsCode, sourceFile) {
    // API endpoint patterns
    const patterns = [
      // fetch(), axios(), $.ajax()
      /fetch\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      /axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      /\$\.ajax\s*\(\s*{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]/gi,
      
      // API base URLs
      /apiUrl\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
      /baseURL\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
      /API_ENDPOINT\s*[:=]\s*['"`]([^'"`]+)['"`]/gi,
      
      // RESTful patterns
      /['"`]\/api\/[a-z0-9-_\/]+['"`]/gi
    ];
    
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(jsCode)) !== null) {
        try {
          const endpoint = match[1];
          if (endpoint && endpoint.startsWith('/')) {
            const fullURL = new URL(endpoint, this.baseURL).href;
            if (this.isSameOrigin(fullURL)) {
              this.apiEndpoints.push({
                url: fullURL,
                source: sourceFile,
                method: this.inferHTTPMethod(jsCode, endpoint)
              });
            }
          }
        } catch (e) {}
      }
    }
  }

  inferHTTPMethod(jsCode, endpoint) {
    // Try to infer HTTP method from context
    const context = jsCode.substring(
      Math.max(0, jsCode.indexOf(endpoint) - 100),
      Math.min(jsCode.length, jsCode.indexOf(endpoint) + 100)
    );
    
    if (/\.post\(|method:\s*['"]POST['"]/.test(context)) return 'POST';
    if (/\.put\(|method:\s*['"]PUT['"]/.test(context)) return 'PUT';
    if (/\.delete\(|method:\s*['"]DELETE['"]/.test(context)) return 'DELETE';
    if (/\.patch\(|method:\s*['"]PATCH['"]/.test(context)) return 'PATCH';
    
    return 'GET';
  }

  isSameOrigin(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.origin === this.baseURL.origin;
    } catch (e) {
      return false;
    }
  }
}

module.exports = IntelligentCrawler;
