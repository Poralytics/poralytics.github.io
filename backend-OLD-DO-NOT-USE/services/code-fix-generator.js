/**
 * Automated Code Fix Generator
 * Generates actual code fixes for vulnerabilities
 */

class CodeFixGenerator {
  constructor() {
    this.fixTemplates = this.loadFixTemplates();
  }

  loadFixTemplates() {
    return {
      sql_injection: {
        languages: {
          javascript: {
            before: `const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query)`,
            after: `const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId])`,
            explanation: 'Use parameterized queries to prevent SQL injection'
          },
          python: {
            before: `query = f"SELECT * FROM users WHERE id = {user_id}"
cursor.execute(query)`,
            after: `query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))`,
            explanation: 'Use parameterized queries with placeholders'
          },
          php: {
            before: `$query = "SELECT * FROM users WHERE id = " . $_GET['id'];
mysqli_query($conn, $query)`,
            after: `$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute()`,
            explanation: 'Use prepared statements with bound parameters'
          }
        },
        config_fixes: {
          nginx: `# Add to nginx.conf
location / {
    # Block common SQL injection patterns
    if ($args ~* "union.*select|insert.*into|delete.*from") {
        return 403;
    }
}`,
          waf: `# ModSecurity WAF Rule
SecRule ARGS "@rx (?i:union.*select|insert.*into|delete.*from)" \\
    "id:1001,phase:2,deny,status:403,msg:'SQL Injection Detected'"
`
        }
      },
      
      xss: {
        languages: {
          javascript: {
            before: `document.getElementById('output').innerHTML = userInput;`,
            after: `const sanitize = (str) => str.replace(/[<>]/g, c => ({
  '<': '&lt;', '>': '&gt;'
}[c]));
document.getElementById('output').textContent = sanitize(userInput);`,
            explanation: 'Sanitize user input and use textContent instead of innerHTML'
          },
          react: {
            before: `<div dangerouslySetInnerHTML={{__html: userContent}} />`,
            after: `import DOMPurify from 'dompurify';
<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userContent)}} />`,
            explanation: 'Use DOMPurify to sanitize HTML content'
          },
          python: {
            before: `return f"<div>{user_input}</div>"`,
            after: `from html import escape
return f"<div>{escape(user_input)}</div>"`,
            explanation: 'Escape HTML special characters'
          }
        },
        headers: {
          'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'",
          'X-XSS-Protection': '1; mode=block',
          'X-Content-Type-Options': 'nosniff'
        }
      },

      missing_headers: {
        nginx: `# Add to nginx server block
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
        
        express: `const helmet = require('helmet');
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"]
  }
}));`,

        apache: `# Add to .htaccess or httpd.conf
Header always set X-Frame-Options "DENY"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000"
Header always set Content-Security-Policy "default-src 'self'"`
      },

      weak_authentication: {
        languages: {
          javascript: {
            before: `const hash = crypto.createHash('md5').update(password).digest('hex');`,
            after: `const bcrypt = require('bcryptjs');
const salt = await bcrypt.genSalt(12);
const hash = await bcrypt.hash(password, salt);`,
            explanation: 'Use bcrypt with at least 12 rounds instead of MD5'
          },
          python: {
            before: `import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()`,
            after: `import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))`,
            explanation: 'Use bcrypt with sufficient work factor'
          }
        },
        mfa_implementation: {
          javascript: `const speakeasy = require('speakeasy');

// Generate secret for user
const secret = speakeasy.generateSecret({length: 32});
user.mfa_secret = secret.base32;

// Verify token
const verified = speakeasy.totp.verify({
  secret: user.mfa_secret,
  encoding: 'base32',
  token: userToken,
  window: 2
});`
        }
      },

      cors_misconfiguration: {
        express: `// ❌ INSECURE
app.use(cors({origin: '*'}));

// ✅ SECURE
const allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));`,

        nginx: `# Add to nginx location block
add_header 'Access-Control-Allow-Origin' 'https://yourdomain.com' always;
add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE' always;
add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;`
      },

      ssl_tls_weak: {
        nginx: `# Modern SSL/TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# OCSP stapling
ssl_stapling on;
ssl_stapling_verify on;`,

        apache: `# Modern SSL/TLS configuration
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder off
SSLSessionTickets off`
      }
    };
  }

  generateFix(vulnerability, context = {}) {
    const category = vulnerability.category.toLowerCase().replace(/[_\s-]/g, '_');
    const template = this.fixTemplates[category];

    if (!template) {
      return this.generateGenericFix(vulnerability);
    }

    const fix = {
      vulnerability_id: vulnerability.id,
      category: vulnerability.category,
      severity: vulnerability.severity,
      fixes: [],
      implementation_guide: [],
      testing_steps: [],
      rollback_plan: []
    };

    // Language-specific code fixes
    if (template.languages) {
      const detectedLanguage = this.detectLanguage(vulnerability, context);
      const langFix = template.languages[detectedLanguage];

      if (langFix) {
        fix.fixes.push({
          type: 'code',
          language: detectedLanguage,
          before: langFix.before,
          after: langFix.after,
          explanation: langFix.explanation,
          files_to_modify: this.identifyFilesToModify(vulnerability, detectedLanguage)
        });
      }
    }

    // Configuration fixes
    if (template.config_fixes) {
      Object.entries(template.config_fixes).forEach(([tool, config]) => {
        fix.fixes.push({
          type: 'configuration',
          tool: tool,
          configuration: config,
          file: this.getConfigFilePath(tool)
        });
      });
    }

    // Header fixes
    if (template.headers) {
      fix.fixes.push({
        type: 'headers',
        headers: template.headers,
        implementation: template.express || template.nginx || template.apache
      });
    }

    // Implementation guide
    fix.implementation_guide = this.generateImplementationGuide(fix.fixes);

    // Testing steps
    fix.testing_steps = this.generateTestingSteps(vulnerability);

    // Rollback plan
    fix.rollback_plan = this.generateRollbackPlan(fix.fixes);

    return fix;
  }

  detectLanguage(vulnerability, context) {
    const indicators = {
      javascript: ['node', 'express', 'npm', '.js'],
      python: ['python', 'django', 'flask', '.py'],
      php: ['php', 'laravel', 'wordpress', '.php'],
      java: ['java', 'spring', '.java'],
      ruby: ['ruby', 'rails', '.rb']
    };

    const text = (vulnerability.description + ' ' + vulnerability.affected_url + ' ' + JSON.stringify(context)).toLowerCase();

    for (const [lang, keywords] of Object.entries(indicators)) {
      if (keywords.some(keyword => text.includes(keyword))) {
        return lang;
      }
    }

    return 'javascript'; // Default
  }

  identifyFilesToModify(vulnerability, language) {
    const commonPaths = {
      javascript: ['src/routes/*.js', 'src/controllers/*.js', 'api/*.js'],
      python: ['views.py', 'models.py', 'api.py'],
      php: ['index.php', 'functions.php', 'api.php'],
      java: ['Controller.java', 'Service.java'],
      ruby: ['controllers/*.rb', 'models/*.rb']
    };

    return commonPaths[language] || ['**/*.' + language.substring(0, 2)];
  }

  getConfigFilePath(tool) {
    const paths = {
      nginx: '/etc/nginx/nginx.conf',
      apache: '/etc/apache2/apache2.conf or .htaccess',
      waf: '/etc/modsecurity/modsecurity.conf',
      express: 'app.js or server.js'
    };

    return paths[tool] || 'configuration file';
  }

  generateImplementationGuide(fixes) {
    const steps = [];
    let stepNumber = 1;

    fixes.forEach(fix => {
      if (fix.type === 'code') {
        steps.push({
          step: stepNumber++,
          action: `Locate ${fix.files_to_modify.join(', ')}`,
          details: 'Find all files containing the vulnerable code pattern'
        });

        steps.push({
          step: stepNumber++,
          action: 'Backup current code',
          details: 'Create backup: git commit -m "Before security fix" or copy files'
        });

        steps.push({
          step: stepNumber++,
          action: 'Apply code changes',
          details: `Replace vulnerable pattern with secure implementation in ${fix.language}`
        });
      }

      if (fix.type === 'configuration') {
        steps.push({
          step: stepNumber++,
          action: `Update ${fix.tool} configuration`,
          details: `Edit ${fix.file} and add the provided configuration`
        });

        steps.push({
          step: stepNumber++,
          action: `Restart ${fix.tool} service`,
          details: `sudo systemctl restart ${fix.tool}`
        });
      }
    });

    steps.push({
      step: stepNumber++,
      action: 'Run tests',
      details: 'Execute test suite to ensure no regressions'
    });

    steps.push({
      step: stepNumber++,
      action: 'Deploy to staging',
      details: 'Test fixes in staging environment before production'
    });

    steps.push({
      step: stepNumber++,
      action: 'Verify fix',
      details: 'Run NEXUS scan again to confirm vulnerability is resolved'
    });

    return steps;
  }

  generateTestingSteps(vulnerability) {
    return [
      {
        test: 'Unit tests',
        action: 'Run existing unit tests to ensure no breaking changes',
        command: 'npm test or pytest or appropriate test command'
      },
      {
        test: 'Security test',
        action: `Manually attempt to exploit the ${vulnerability.category} vulnerability`,
        expected: 'Exploit should fail with proper error handling'
      },
      {
        test: 'Functional test',
        action: 'Verify legitimate use cases still work correctly',
        expected: 'All normal operations function as expected'
      },
      {
        test: 'Performance test',
        action: 'Ensure fix does not degrade performance',
        expected: 'Response times within acceptable range'
      }
    ];
  }

  generateRollbackPlan(fixes) {
    const plan = [
      {
        step: 1,
        action: 'Stop services',
        command: 'Stop web server and application services'
      }
    ];

    fixes.forEach((fix, index) => {
      if (fix.type === 'code') {
        plan.push({
          step: plan.length + 1,
          action: 'Restore code backup',
          command: 'git revert HEAD or restore backed up files'
        });
      }

      if (fix.type === 'configuration') {
        plan.push({
          step: plan.length + 1,
          action: `Restore ${fix.tool} configuration`,
          command: `Restore backup of ${fix.file}`
        });
      }
    });

    plan.push({
      step: plan.length + 1,
      action: 'Restart services',
      command: 'Restart all services and verify system is stable'
    });

    return plan;
  }

  generateGenericFix(vulnerability) {
    return {
      vulnerability_id: vulnerability.id,
      category: vulnerability.category,
      fixes: [{
        type: 'manual',
        recommendation: vulnerability.remediation_text,
        effort_hours: vulnerability.remediation_effort_hours || 2
      }],
      implementation_guide: [
        {step: 1, action: 'Review vulnerability details'},
        {step: 2, action: 'Research best practices for ' + vulnerability.category},
        {step: 3, action: 'Implement recommended fix'},
        {step: 4, action: 'Test thoroughly'},
        {step: 5, action: 'Deploy and verify'}
      ]
    };
  }

  generateBatchFixes(vulnerabilities, context = {}) {
    return vulnerabilities.map(vuln => this.generateFix(vuln, context));
  }
}

module.exports = new CodeFixGenerator();
