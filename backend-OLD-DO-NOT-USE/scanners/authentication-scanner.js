/**
 * Authentication Scanner
 * Tests for authentication weaknesses
 */
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');

class AuthenticationScanner {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 10000, maxContentLength: 5 * 1024 * 1024 });

    this.weakCredentials = [
      { user: 'admin', pass: 'admin' },
      { user: 'admin', pass: 'password' },
      { user: 'admin', pass: '123456' },
      { user: 'admin', pass: 'admin123' },
      { user: 'root', pass: 'root' },
      { user: 'test', pass: 'test' },
      { user: 'guest', pass: 'guest' },
      { user: 'user', pass: 'user' },
      { user: 'administrator', pass: 'administrator' },
      { user: 'admin', pass: '' }
    ];
  }

  async scan(url) {
    const findings = [];
    const errors = [];

    try {
      logger.logInfo('Starting Authentication scan', { url });

      // 1. Check for login forms
      const loginEndpoints = await this.findLoginEndpoints(url);

      // 2. Test for weak credentials
      for (const endpoint of loginEndpoints.slice(0, 3)) {
        const weakCreds = await this.testWeakCredentials(endpoint);
        findings.push(...weakCreds);
      }

      // 3. Check for account enumeration
      const enumVulns = await this.testAccountEnumeration(url, loginEndpoints);
      findings.push(...enumVulns);

      // 4. Check for rate limiting
      const rateLimitVulns = await this.testRateLimiting(loginEndpoints[0]);
      findings.push(...rateLimitVulns);

      // 5. Check for secure cookie attributes
      const cookieVulns = await this.testCookieSecurity(url);
      findings.push(...cookieVulns);

    } catch (err) {
      errors.push(err.message);
      logger.logError(err, { context: 'Authentication scan', url });
    }

    return { vulnerabilities: findings, errors, url, scanned: new Date().toISOString() };
  }

  async findLoginEndpoints(url) {
    const endpoints = [];
    const base = new URL(url).origin;

    // Common login paths
    const paths = ['/login', '/signin', '/auth', '/api/auth/login', '/api/login',
      '/admin', '/admin/login', '/user/login', '/account/login'];

    try {
      const resp = await this.httpClient.get(url, { timeout: 5000 });
      if (resp.data) {
        const $ = cheerio.load(resp.data);
        $('form').each((_, form) => {
          const action = $(form).attr('action') || '';
          const hasPassword = $(form).find('input[type="password"]').length > 0;
          if (hasPassword) {
            const formUrl = action.startsWith('http') ? action : base + action;
            endpoints.push(formUrl);
          }
        });
      }
    } catch (e) {}

    // Add common paths if none found
    if (endpoints.length === 0) {
      for (const p of paths.slice(0, 3)) {
        try {
          const resp = await this.httpClient.get(base + p, { timeout: 3000 });
          if (resp.status === 200) endpoints.push(base + p);
        } catch (e) {}
      }
    }

    return endpoints.length > 0 ? endpoints : [url];
  }

  async testWeakCredentials(endpoint) {
    const findings = [];
    for (const cred of this.weakCredentials.slice(0, 5)) {
      try {
        const resp = await this.httpClient.post(endpoint, {
          username: cred.user,
          email: cred.user,
          password: cred.pass,
          login: cred.user
        }, { timeout: 5000 });

        // Success indicators
        if (resp.status === 200 &&
          (resp.data?.token || resp.data?.access_token ||
           (typeof resp.data === 'string' && resp.data.includes('dashboard')))) {
          findings.push({
            severity: 'critical',
            category: 'authentication',
            type: 'weak_credentials',
            title: `Default/Weak Credentials: ${cred.user}/${cred.pass}`,
            description: `Application accepts weak default credentials. This allows unauthorized access.`,
            parameter: 'credentials',
            payload: `${cred.user}:${cred.pass}`,
            evidence: { endpoint, username: cred.user, status: resp.status },
            cvss_score: 9.8,
            confidence: 'high',
            remediation_text: 'Enforce strong password policy. Change default credentials immediately. Implement multi-factor authentication.',
            remediation_effort_hours: 4,
            owasp_category: 'A07:2021 – Identification and Authentication Failures',
            cwe_id: 'CWE-521'
          });
          break;
        }
      } catch (e) {}
      await this.sleep(300);
    }
    return findings;
  }

  async testAccountEnumeration(url, loginEndpoints) {
    const findings = [];
    if (loginEndpoints.length === 0) return findings;

    try {
      const endpoint = loginEndpoints[0];

      // Test with valid-looking email vs invalid
      const respValid = await this.httpClient.post(endpoint, {
        email: 'admin@test.com', password: 'wrongpassword123!'
      }, { timeout: 5000 });

      const respInvalid = await this.httpClient.post(endpoint, {
        email: 'nonexistent@invalid-domain-xyz.com', password: 'wrongpassword123!'
      }, { timeout: 5000 });

      // Check if error messages differ
      const body1 = JSON.stringify(respValid.data || '');
      const body2 = JSON.stringify(respInvalid.data || '');

      const enumPhrases = ['user not found', 'account does not exist', 'no account',
        'email not found', 'invalid email', 'incorrect password'];
      
      const hasEnum = enumPhrases.some(p =>
        (body1.toLowerCase().includes(p) || body2.toLowerCase().includes(p)) &&
        body1 !== body2
      );

      if (hasEnum || (body1.length !== body2.length && Math.abs(body1.length - body2.length) > 20)) {
        findings.push({
          severity: 'medium',
          category: 'authentication',
          type: 'account_enumeration',
          title: 'Account Enumeration via Login Error Messages',
          description: 'The login page returns different responses for valid vs invalid usernames, allowing attackers to enumerate valid accounts.',
          evidence: {
            endpoint,
            response_diff: Math.abs(body1.length - body2.length) + ' bytes'
          },
          cvss_score: 5.3,
          confidence: 'medium',
          remediation_text: 'Return identical error messages for invalid username and invalid password. Use generic: "Invalid credentials."',
          remediation_effort_hours: 2,
          owasp_category: 'A07:2021 – Identification and Authentication Failures',
          cwe_id: 'CWE-204'
        });
      }
    } catch (e) {}

    return findings;
  }

  async testRateLimiting(endpoint) {
    const findings = [];
    if (!endpoint) return findings;

    try {
      const requests = [];
      for (let i = 0; i < 10; i++) {
        requests.push(
          this.httpClient.post(endpoint, {
            email: 'test@test.com', password: 'wrong' + i
          }, { timeout: 3000 }).catch(() => null)
        );
      }

      const results = await Promise.all(requests);
      const successCount = results.filter(r => r && r.status !== 429 && r.status !== 423).length;

      if (successCount === 10) {
        findings.push({
          severity: 'high',
          category: 'authentication',
          type: 'no_rate_limiting',
          title: 'No Rate Limiting on Login Endpoint',
          description: 'The login endpoint does not implement rate limiting, allowing brute force attacks.',
          evidence: {
            endpoint,
            requests_sent: 10,
            all_accepted: true
          },
          cvss_score: 7.5,
          confidence: 'medium',
          remediation_text: 'Implement rate limiting (e.g., 5 attempts per 15 minutes per IP). Add account lockout after repeated failures. Use CAPTCHA.',
          remediation_effort_hours: 4,
          owasp_category: 'A07:2021 – Identification and Authentication Failures',
          cwe_id: 'CWE-307'
        });
      }
    } catch (e) {}

    return findings;
  }

  async testCookieSecurity(url) {
    const findings = [];
    try {
      const resp = await this.httpClient.get(url, { timeout: 5000 });
      const cookies = resp.headers?.['set-cookie'] || [];

      const cookieList = Array.isArray(cookies) ? cookies : [cookies];

      for (const cookie of cookieList) {
        if (!cookie) continue;

        // Check HttpOnly
        if (!cookie.toLowerCase().includes('httponly')) {
          findings.push({
            severity: 'medium',
            category: 'authentication',
            type: 'cookie_no_httponly',
            title: 'Session Cookie Missing HttpOnly Flag',
            description: 'Session cookie lacks HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS-based session theft.',
            evidence: { url, cookie: cookie.split(';')[0].substring(0, 50) },
            cvss_score: 4.3,
            confidence: 'high',
            remediation_text: 'Add HttpOnly flag to all session cookies.',
            remediation_effort_hours: 1,
            owasp_category: 'A07:2021 – Identification and Authentication Failures',
            cwe_id: 'CWE-1004'
          });
        }

        // Check Secure flag
        if (!cookie.toLowerCase().includes('secure') && url.startsWith('https')) {
          findings.push({
            severity: 'medium',
            category: 'authentication',
            type: 'cookie_no_secure',
            title: 'Session Cookie Missing Secure Flag',
            description: 'Session cookie lacks Secure flag, allowing transmission over unencrypted HTTP.',
            evidence: { url, cookie: cookie.split(';')[0].substring(0, 50) },
            cvss_score: 4.3,
            confidence: 'high',
            remediation_text: 'Add Secure flag to all session cookies on HTTPS sites.',
            remediation_effort_hours: 1,
            owasp_category: 'A07:2021 – Identification and Authentication Failures',
            cwe_id: 'CWE-614'
          });
        }

        // Check SameSite
        if (!cookie.toLowerCase().includes('samesite')) {
          findings.push({
            severity: 'low',
            category: 'authentication',
            type: 'cookie_no_samesite',
            title: 'Session Cookie Missing SameSite Attribute',
            description: 'Cookie lacks SameSite attribute, potentially vulnerable to CSRF attacks.',
            evidence: { url, cookie: cookie.split(';')[0].substring(0, 50) },
            cvss_score: 3.1,
            confidence: 'high',
            remediation_text: 'Add SameSite=Strict or SameSite=Lax to session cookies.',
            remediation_effort_hours: 1,
            owasp_category: 'A07:2021 – Identification and Authentication Failures',
            cwe_id: 'CWE-1275'
          });
        }
      }
    } catch (e) {}

    return findings;
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = AuthenticationScanner;
