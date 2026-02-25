/**
 * REMEDIATION CODE GENERATOR
 * Génère du code de correction automatique pour les vulnérabilités
 */

class RemediationGenerator {
  /**
   * Génère du code de correction pour une vulnérabilité
   */
  generateFix(vulnerability) {
    const generators = {
      'SQL Injection': this.generateSQLiFix.bind(this),
      'Cross-Site Scripting (XSS)': this.generateXSSFix.bind(this),
      'CSRF': this.generateCSRFFix.bind(this),
      'SSRF': this.generateSSRFFix.bind(this),
      'Command Injection': this.generateCommandInjectionFix.bind(this),
      'XXE': this.generateXXEFix.bind(this),
      'Insecure Headers': this.generateHeadersFix.bind(this),
      'Weak SSL/TLS': this.generateSSLFix.bind(this)
    };

    const generator = generators[vulnerability.category];
    if (!generator) {
      return { message: 'No automated fix available', manualSteps: this.getManualSteps(vulnerability) };
    }

    return generator(vulnerability);
  }

  generateSQLiFix(vuln) {
    const param = vuln.parameter || 'id';
    return {
      language: 'javascript',
      framework: 'Node.js + better-sqlite3',
      before: `// ❌ VULNERABLE CODE
const userId = req.query.${param};
const sql = 'SELECT * FROM users WHERE id = ' + userId;
const user = db.prepare(sql).get();`,
      after: `// ✅ SECURE CODE - Parameterized query
const userId = req.query.${param};
const sql = 'SELECT * FROM users WHERE id = ?';
const user = db.prepare(sql).get(userId);`,
      explanation: 'Use parameterized queries (prepared statements) to separate SQL code from data. Never concatenate user input into SQL strings.',
      alternatives: [
        {
          name: 'ORM (Sequelize)',
          code: `const user = await User.findByPk(req.query.${param});`
        },
        {
          name: 'Query Builder (Knex)',
          code: `const user = await knex('users').where('id', req.query.${param}).first();`
        }
      ],
      testCode: `// Validation test
describe('SQL Injection protection', () => {
  it('should reject malicious input', () => {
    const malicious = "1' OR '1'='1";
    expect(() => getUser(malicious)).not.toThrow();
    // Query returns null for non-existent ID, not all users
  });
});`
    };
  }

  generateXSSFix(vuln) {
    return {
      language: 'javascript',
      framework: 'React',
      before: `// ❌ VULNERABLE CODE
<div dangerouslySetInnerHTML={{__html: userInput}} />

// or in vanilla JS:
element.innerHTML = userInput;`,
      after: `// ✅ SECURE CODE - Auto-escaped
<div>{userInput}</div>

// or use DOMPurify for HTML content:
import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}} />`,
      explanation: 'React automatically escapes values in JSX. For HTML content, use DOMPurify to sanitize. Never use dangerouslySetInnerHTML with unsanitized input.',
      npmPackages: ['dompurify'],
      cspHeader: `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'`,
      testCode: `// XSS test
it('should escape XSS payload', () => {
  const xss = '<script>alert("XSS")</script>';
  render(<UserComment comment={xss} />);
  expect(screen.queryByText(/alert/)).toBeNull();
});`
    };
  }

  generateCSRFFix(vuln) {
    return {
      language: 'javascript',
      framework: 'Express',
      before: `// ❌ NO CSRF PROTECTION
app.post('/api/transfer', (req, res) => {
  transfer(req.body.amount, req.body.to);
});`,
      after: `// ✅ CSRF TOKEN PROTECTION
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.post('/api/transfer', csrfProtection, (req, res) => {
  // Token verified automatically
  transfer(req.body.amount, req.body.to);
});

// In HTML form:
<input type="hidden" name="_csrf" value="<%= csrfToken %>" />`,
      explanation: 'Use CSRF tokens for state-changing operations. For APIs, use custom headers (X-Requested-With) or SameSite cookies.',
      npmPackages: ['csurf'],
      alternativeSameSite: `// SameSite cookie (modern browsers)
res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});`,
      testCode: `it('should reject requests without CSRF token', async () => {
  const res = await request(app).post('/api/transfer').send({ amount: 1000 });
  expect(res.status).toBe(403);
});`
    };
  }

  generateSSRFFix(vuln) {
    return {
      language: 'javascript',
      before: `// ❌ VULNERABLE
const url = req.query.url;
const response = await axios.get(url);`,
      after: `// ✅ SECURE - URL validation
const { URL } = require('url');

function isValidURL(urlString) {
  try {
    const url = new URL(urlString);
    
    // Only allow http/https
    if (!['http:', 'https:'].includes(url.protocol)) return false;
    
    // Block private IPs
    const hostname = url.hostname;
    const blocklist = [
      'localhost', '127.', '10.', '192.168.', '172.16.',
      '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
      '172.22.', '172.23.', '172.24.', '172.25.', '172.26.',
      '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
    ];
    
    if (blocklist.some(b => hostname.startsWith(b))) return false;
    
    return true;
  } catch {
    return false;
  }
}

const url = req.query.url;
if (!isValidURL(url)) {
  return res.status(400).json({ error: 'Invalid URL' });
}
const response = await axios.get(url, { timeout: 5000 });`,
      explanation: 'Validate and whitelist allowed URLs. Block private IP ranges and localhost. Use DNS resolution to detect bypasses.',
      testCode: `it('should block SSRF to metadata', async () => {
  const res = await request(app)
    .get('/fetch?url=http://169.254.169.254/latest/meta-data/');
  expect(res.status).toBe(400);
});`
    };
  }

  generateCommandInjectionFix(vuln) {
    return {
      language: 'javascript',
      before: `// ❌ VULNERABLE
const { exec } = require('child_process');
exec('ping -c 4 ' + req.query.host, callback);`,
      after: `// ✅ SECURE - Use execFile with array
const { execFile } = require('child_process');
execFile('ping', ['-c', '4', req.query.host], callback);

// Even better: Input validation
const host = req.query.host;
if (!/^[a-z0-9.-]+$/i.test(host)) {
  return res.status(400).json({ error: 'Invalid hostname' });
}
execFile('ping', ['-c', '4', host], callback);`,
      explanation: 'Never pass user input to exec(). Use execFile() with argument array. Validate input with strict whitelist regex.',
      npmPackages: [],
      bestPractice: 'Avoid shell commands entirely. Use native libraries (e.g., node-ping instead of system ping).',
      testCode: `it('should block command injection', () => {
  const malicious = '; rm -rf /';
  expect(() => ping(malicious)).toThrow(/Invalid hostname/);
});`
    };
  }

  generateXXEFix(vuln) {
    return {
      language: 'javascript',
      before: `// ❌ VULNERABLE
const xml2js = require('xml2js');
const parser = new xml2js.Parser();
parser.parseString(userXML, callback);`,
      after: `// ✅ SECURE - Disable external entities
const xml2js = require('xml2js');
const parser = new xml2js.Parser({
  explicitArray: false,
  ignoreAttrs: false,
  xmlns: false,
  // Disable DTD and external entities
  strict: true
});

// For libxmljs (native):
const libxmljs = require('libxmljs');
const doc = libxmljs.parseXml(userXML, {
  noent: false,  // Disable entity expansion
  dtdload: false // Disable DTD loading
});`,
      explanation: 'Disable external entity processing in XML parsers. Use JSON instead of XML when possible.',
      npmPackages: ['libxmljs'],
      testCode: `it('should block XXE attack', () => {
  const xxe = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>';
  expect(() => parseXML(xxe)).toThrow();
});`
    };
  }

  generateHeadersFix(vuln) {
    return {
      language: 'javascript',
      framework: 'Express + Helmet',
      before: `// ❌ NO SECURITY HEADERS
const app = express();`,
      after: `// ✅ SECURE HEADERS
const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'nonce-{random}'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));`,
      explanation: 'Use Helmet to set security headers. CSP prevents XSS, HSTS enforces HTTPS, X-Frame-Options prevents clickjacking.',
      npmPackages: ['helmet'],
      headers: {
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
      }
    };
  }

  generateSSLFix(vuln) {
    return {
      service: 'nginx',
      before: `# ❌ WEAK SSL CONFIG
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers ALL;`,
      after: `# ✅ STRONG SSL CONFIG
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_stapling on;
ssl_stapling_verify on;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
      explanation: 'Use TLS 1.2+ only. Disable weak ciphers. Enable OCSP stapling. Force HTTPS with HSTS.',
      testCommand: 'nmap --script ssl-enum-ciphers -p 443 yourdomain.com',
      sslLabsGrade: 'A+'
    };
  }

  getManualSteps(vuln) {
    return [
      `1. Review the vulnerability details in scan report`,
      `2. Locate the vulnerable code at: ${vuln.parameter || 'parameter not identified'}`,
      `3. Consult OWASP guidelines for ${vuln.category}`,
      `4. Test fix in staging environment`,
      `5. Deploy to production after validation`
    ];
  }
}

module.exports = new RemediationGenerator();
