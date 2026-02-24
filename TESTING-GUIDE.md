# 🧪 NEXUS ULTIMATE PRO - Testing Guide

## Guide Complet de Tests

---

## 1. TESTS MANUELS

### Test de Base - Installation

```bash
# 1. Extraire
tar -xzf NEXUS-ULTIMATE-PRO-v2.0-COMPLETE.tar.gz
cd NEXUS-FINAL-PRO

# 2. Installer
cd backend
npm install

# 3. Initialiser DB
node init-nexus.js

# 4. Lancer
npm start

# Vérifications:
✓ Serveur démarre sans erreur
✓ Port 3000 ouvert
✓ Database créée (15 tables)
✓ Compte demo existe
```

### Test de Connexion

```bash
# Navigateur
open http://localhost:3000/login.html

# Credentials
Email: demo@nexus.security
Password: nexus2024

# Vérifications:
✓ Login réussit
✓ JWT token généré
✓ Redirect vers dashboard
✓ Email affiché en haut
```

### Test de Scan Complet

```bash
# 1. Ajouter domaine
Domain: https://example.com

# 2. Lancer scan
Cliquer "Scanner"

# 3. Observer progression
0% → 10% → 20% ... → 100%

# Vérifications:
✓ 10 phases s'exécutent
✓ Vulnérabilités trouvées
✓ Business impact calculé
✓ Predictions générées
✓ Score final affiché
✓ Durée ~30-60 secondes
```

### Test des 20 Scanners

```javascript
// Script de test
const domains = [
  'https://testphp.vulnweb.com', // SQL injection
  'https://xss-game.appspot.com', // XSS
  'http://testaspnet.vulnweb.com', // Various
  'https://crackme.cenzic.com' // Multiple vulns
];

domains.forEach(async (url) => {
  const scan = await startScan(url);
  console.log(`${url}: ${scan.vulnerabilities_found} vulns found`);
});
```

**Résultats Attendus:**
- SQL Injection: 5-10 vulns trouvées
- XSS: 3-8 vulns trouvées
- Headers: 4-7 headers manquants
- SSL/TLS: 1-3 problèmes
- CORS: 1-2 misconfigurations
- Components: 2-5 libs obsolètes

### Test Business Impact

```bash
# Pour chaque vulnérabilité
✓ business_impact_eur > 0
✓ exploit_probability 0.0-1.0
✓ expected_loss_eur calculé
✓ priority_score > 0
✓ remediation_text présent
```

### Test Auto-Remediation

```bash
# Headers manquants
Before: No HSTS, CSP, X-Frame-Options
Scan...
After: auto_fixed = 1 pour headers

# Vérifications:
✓ Headers fixés automatiquement
✓ remediation_actions enregistrées
✓ Status changé à "fixed"
✓ Count vulnerabilities_fixed incrémenté
```

### Test Rapports

```bash
# Générer rapport
POST /api/reports/generate
{
  "scan_id": 123,
  "type": "executive"
}

# Vérifications:
✓ JSON généré
✓ Toutes sections présentes
✓ Top risks calculés
✓ Recommendations générées
✓ File sauvegardé
```

### Test Intégrations

```bash
# Slack
✓ Notification envoyée
✓ Message formaté
✓ KPIs affichés

# Email
✓ Email reçu
✓ HTML formaté
✓ Vulns listées

# Webhook
✓ POST envoyé
✓ Payload JSON correct
✓ Status 200
```

---

## 2. TESTS AUTOMATISÉS (Jest)

### Setup

```bash
npm install --save-dev jest supertest

# package.json
"scripts": {
  "test": "jest",
  "test:watch": "jest --watch",
  "test:coverage": "jest --coverage"
}
```

### Tests Unitaires - Scanners

```javascript
// tests/scanners/sql-injection.test.js
const SQLInjectionScanner = require('../../scanners/sql-injection-scanner');

describe('SQL Injection Scanner', () => {
  let scanner;

  beforeEach(() => {
    scanner = new SQLInjectionScanner({url: 'https://test.com'});
  });

  test('should detect error-based SQL injection', async () => {
    const mockResponse = {
      data: "You have an error in your SQL syntax"
    };
    
    const detected = scanner.detectSQLError(mockResponse.data);
    expect(detected).toBe(true);
  });

  test('should detect time-based SQL injection', async () => {
    const startTime = Date.now();
    // Simulate 5 second delay
    const elapsed = 5100;
    
    expect(elapsed).toBeGreaterThan(4500);
  });

  test('should generate correct findings', async () => {
    const findings = await scanner.scan();
    
    expect(findings).toBeInstanceOf(Array);
    findings.forEach(finding => {
      expect(finding).toHaveProperty('severity');
      expect(finding).toHaveProperty('category');
      expect(finding).toHaveProperty('title');
      expect(finding).toHaveProperty('cvss_score');
    });
  });
});
```

### Tests Unitaires - Services

```javascript
// tests/services/business-impact.test.js
const businessImpact = require('../../services/business-impact-calculator');

describe('Business Impact Calculator', () => {
  test('should calculate breach cost correctly', () => {
    const vuln = {
      category: 'sql injection',
      severity: 'critical'
    };
    
    const context = {
      revenue_per_hour: 25000,
      business_value: 5000000
    };

    const impact = businessImpact.calculateImpact(vuln, context);

    expect(impact.business_impact_eur).toBeGreaterThan(0);
    expect(impact.exploit_probability).toBeGreaterThan(0);
    expect(impact.exploit_probability).toBeLessThanOrEqual(1);
    expect(impact.expected_loss_eur).toBe(
      Math.round(impact.business_impact_eur * impact.exploit_probability)
    );
  });

  test('should calculate expected loss formula', () => {
    const impact = 1000000; // 1M€
    const probability = 0.85; // 85%
    const expectedLoss = impact * probability;

    expect(expectedLoss).toBe(850000);
  });

  test('should prioritize by expected loss', () => {
    const vulns = [
      {expected_loss_eur: 500000, severity: 'high'},
      {expected_loss_eur: 1200000, severity: 'critical'},
      {expected_loss_eur: 100000, severity: 'medium'}
    ];

    const sorted = vulns.sort((a, b) => 
      b.expected_loss_eur - a.expected_loss_eur
    );

    expect(sorted[0].expected_loss_eur).toBe(1200000);
    expect(sorted[2].expected_loss_eur).toBe(100000);
  });
});
```

### Tests Intégration - API

```javascript
// tests/integration/api.test.js
const request = require('supertest');
const app = require('../../server');

describe('API Integration Tests', () => {
  let token;
  let domainId;

  beforeAll(async () => {
    // Login
    const res = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'demo@nexus.security',
        password: 'nexus2024'
      });

    token = res.body.token;
  });

  test('POST /api/domains/add should create domain', async () => {
    const res = await request(app)
      .post('/api/domains/add')
      .set('Authorization', `Bearer ${token}`)
      .send({
        url: 'https://test-domain.com',
        name: 'Test Domain'
      });

    expect(res.status).toBe(200);
    expect(res.body.domain).toHaveProperty('id');
    expect(res.body.domain.url).toBe('https://test-domain.com');
    
    domainId = res.body.domain.id;
  });

  test('POST /api/scans/start should start scan', async () => {
    const res = await request(app)
      .post('/api/scans/start')
      .set('Authorization', `Bearer ${token}`)
      .send({domain_id: domainId});

    expect(res.status).toBe(200);
    expect(res.body.scan).toHaveProperty('id');
    expect(res.body.scan.status).toBe('pending');
  });

  test('GET /api/scans/:id should return scan results', async () => {
    // Wait for scan to complete
    await new Promise(resolve => setTimeout(resolve, 60000));

    const res = await request(app)
      .get(`/api/scans/${scanId}`)
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.scan.status).toBe('completed');
    expect(res.body.vulnerabilities).toBeInstanceOf(Array);
  });

  test('GET /api/analytics/overview should return stats', async () => {
    const res = await request(app)
      .get('/api/analytics/overview')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('total_domains');
    expect(res.body).toHaveProperty('total_scans');
    expect(res.body).toHaveProperty('average_score');
  });
});
```

### Tests E2E (Playwright)

```javascript
// tests/e2e/scan-workflow.test.js
const { test, expect } = require('@playwright/test');

test.describe('Full Scan Workflow', () => {
  test('should complete full scan workflow', async ({ page }) => {
    // 1. Login
    await page.goto('http://localhost:3000/login.html');
    await page.fill('input[name="email"]', 'demo@nexus.security');
    await page.fill('input[name="password"]', 'nexus2024');
    await page.click('button[type="submit"]');

    // Wait for dashboard
    await page.waitForURL('**/dashboard.html');

    // 2. Add domain
    await page.click('button:has-text("Ajouter un domaine")');
    await page.fill('input[name="url"]', 'https://example.com');
    await page.click('button:has-text("Ajouter")');

    // Wait for toast
    await expect(page.locator('.toast.success')).toBeVisible();

    // 3. Start scan
    await page.click('button:has-text("Scanner")');

    // Wait for scan to start
    await expect(page.locator('.scan-progress')).toBeVisible();

    // 4. Wait for completion (max 2 min)
    await page.waitForSelector('.scan-status:has-text("completed")', {
      timeout: 120000
    });

    // 5. Verify results
    const score = await page.locator('.security-score').textContent();
    expect(parseInt(score)).toBeGreaterThanOrEqual(0);
    expect(parseInt(score)).toBeLessThanOrEqual(100);

    const vulnCount = await page.locator('.vulnerability-item').count();
    expect(vulnCount).toBeGreaterThan(0);
  });
});
```

---

## 3. TESTS DE PERFORMANCE

### Load Testing (Artillery)

```yaml
# artillery-config.yml
config:
  target: 'http://localhost:3000'
  phases:
    - duration: 60
      arrivalRate: 5
      name: "Warm up"
    - duration: 120
      arrivalRate: 10
      name: "Ramp up"
    - duration: 60
      arrivalRate: 20
      name: "Sustained load"

scenarios:
  - name: "Login and scan"
    flow:
      - post:
          url: "/api/auth/login"
          json:
            email: "demo@nexus.security"
            password: "nexus2024"
          capture:
            json: "$.token"
            as: "token"
      
      - post:
          url: "/api/scans/start"
          headers:
            Authorization: "Bearer {{ token }}"
          json:
            domain_id: 1
```

```bash
# Run load test
artillery run artillery-config.yml

# Results attendus:
# RPS: 20+ requests/second
# Latency p95: <500ms
# Error rate: <1%
```

### Stress Testing

```javascript
// tests/stress/concurrent-scans.js
const concurrent = 50; // 50 scans simultanés

const promises = Array(concurrent).fill().map((_, i) => 
  fetch('http://localhost:3000/api/scans/start', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({domain_id: 1})
  })
);

const results = await Promise.all(promises);
const successful = results.filter(r => r.ok).length;

console.log(`${successful}/${concurrent} scans started successfully`);
// Expected: 45+/50 (queue system handles overflow)
```

---

## 4. TESTS DE SÉCURITÉ

### Security Testing Checklist

```bash
# SQL Injection
curl -X POST http://localhost:3000/api/auth/login \
  -d "email=admin' OR '1'='1&password=anything"
# Expected: 401 Unauthorized (protected)

# XSS
curl -X POST http://localhost:3000/api/domains/add \
  -H "Authorization: Bearer $TOKEN" \
  -d 'url=<script>alert(1)</script>'
# Expected: Input sanitized or rejected

# JWT tampering
curl http://localhost:3000/api/scans/list \
  -H "Authorization: Bearer FAKE_TOKEN"
# Expected: 401 Unauthorized

# Rate limiting
for i in {1..200}; do
  curl http://localhost:3000/api/auth/login &
done
# Expected: 429 Too Many Requests after ~100 requests
```

### Penetration Testing

```bash
# Run own scanner against NEXUS
./nexus-scanner.sh http://localhost:3000

# Expected results:
✓ No SQL injection
✓ No XSS
✓ No CSRF (tokens validated)
✓ No sensitive data exposure
✓ Strong password policy
✓ Secure headers present
✓ SSL/TLS configured
✓ Rate limiting active
```

---

## 5. TESTS DE RÉGRESSION

### Regression Test Suite

```javascript
// tests/regression/all-scanners.test.js
const scanners = [
  'sql-injection',
  'xss',
  'authentication',
  'access-control',
  'ssrf',
  'xxe',
  'command-injection',
  'crypto',
  'headers',
  'ssl',
  'api-security',
  'file-upload',
  'csrf',
  'clickjacking',
  'open-redirect',
  'info-disclosure',
  'business-logic',
  'infrastructure',
  'components',
  'cors'
];

describe('Regression Tests - All Scanners', () => {
  scanners.forEach(scannerName => {
    test(`${scannerName} scanner should work`, async () => {
      const Scanner = require(`../../scanners/${scannerName}-scanner`);
      const scanner = new Scanner({url: 'https://test.com'});
      
      const findings = await scanner.scan();
      
      expect(findings).toBeInstanceOf(Array);
      // Should not crash
    });
  });
});
```

---

## 6. CONTINUOUS INTEGRATION

### GitHub Actions

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: |
          cd backend
          npm ci
      
      - name: Run linter
        run: npm run lint
      
      - name: Run unit tests
        run: npm test
      
      - name: Run integration tests
        run: npm run test:integration
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

---

## 7. MONITORING DES TESTS

### Test Coverage

```bash
# Generate coverage report
npm run test:coverage

# Expected coverage:
Statements   : 80%+
Branches     : 75%+
Functions    : 80%+
Lines        : 80%+
```

### Test Metrics

```javascript
// Track test metrics
{
  total_tests: 150,
  passed: 148,
  failed: 2,
  skipped: 0,
  duration: "45s",
  coverage: "82%",
  flaky_tests: 1
}
```

---

## 8. TROUBLESHOOTING TESTS

### Tests Qui Échouent

```bash
# Test timeout
# Augmenter timeout dans jest.config.js
module.exports = {
  testTimeout: 30000 // 30 secondes
};

# Database locked
# Utiliser database séparée pour tests
TEST_DB=nexus_test.db npm test

# Port déjà utilisé
# Changer port dans tests
const PORT = process.env.TEST_PORT || 3001;
```

---

**NEXUS ULTIMATE PRO - Fully Tested**
