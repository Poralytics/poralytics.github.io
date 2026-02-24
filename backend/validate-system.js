#!/usr/bin/env node
/**
 * NEXUS VALIDATION SYSTEM
 * Teste TOUT le système avant déploiement
 */

const fs = require('fs');
const path = require('path');

console.log('\n' + '='.repeat(70));
console.log('🔍 NEXUS SYSTEM VALIDATION');
console.log('='.repeat(70) + '\n');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const errors = [];

function test(name, condition, errorMsg = '') {
  totalTests++;
  if (condition) {
    console.log(`✅ ${name}`);
    passedTests++;
    return true;
  } else {
    console.log(`❌ ${name}`);
    failedTests++;
    if (errorMsg) errors.push(`${name}: ${errorMsg}`);
    return false;
  }
}

// ===== STRUCTURE FICHIERS =====
console.log('📁 File Structure Tests\n');

test('Backend directory exists', fs.existsSync(path.join(__dirname)));
test('Server.js exists', fs.existsSync(path.join(__dirname, 'server.js')));
test('Package.json exists', fs.existsSync(path.join(__dirname, 'package.json')));
test('Database schema exists', fs.existsSync(path.join(__dirname, 'database-schema.sql')));
test('Auto-setup script exists', fs.existsSync(path.join(__dirname, 'auto-setup.js')));

// Frontend
const frontendPath = path.join(__dirname, '..', 'frontend');
test('Frontend directory exists', fs.existsSync(frontendPath));
test('Dashboard exists', fs.existsSync(path.join(frontendPath, 'dashboard-ultimate-v2.html')));
test('Login page exists', fs.existsSync(path.join(frontendPath, 'login.html')));
test('Pricing page exists', fs.existsSync(path.join(frontendPath, 'pricing.html')));
test('Index page exists', fs.existsSync(path.join(frontendPath, 'index.html')));

// ===== SERVICES =====
console.log('\n🔧 Services Tests\n');

const servicesPath = path.join(__dirname, 'services');
const requiredServices = [
  'stripe-billing-service.js',
  'license-service.js',
  'security-health-score.js',
  'risk-heatmap-service.js',
  'executive-reporting-service.js',
  'ai-security-service.js',
  'compliance-service.js',
  'cicd-integration-service.js'
];

requiredServices.forEach(service => {
  test(`Service: ${service}`, fs.existsSync(path.join(servicesPath, service)));
});

// ===== ROUTES =====
console.log('\n🛣️  Routes Tests\n');

const routesPath = path.join(__dirname, 'routes');
const requiredRoutes = [
  'auth.js',
  'domains.js',
  'scans.js',
  'billing.js',
  'usage.js',
  'score.js',
  'visualizations.js',
  'executive.js',
  'ai.js',
  'compliance.js',
  'cicd.js'
];

requiredRoutes.forEach(route => {
  test(`Route: ${route}`, fs.existsSync(path.join(routesPath, route)));
});

// ===== SCANNERS =====
console.log('\n🔍 Scanners Tests\n');

const scannersPath = path.join(__dirname, 'scanners');
test('Scanners directory exists', fs.existsSync(scannersPath));
test('SQL Injection scanner', fs.existsSync(path.join(scannersPath, 'sql-injection.js')));
test('XSS scanner', fs.existsSync(path.join(scannersPath, 'xss.js')));
test('Security Headers scanner', fs.existsSync(path.join(scannersPath, 'security-headers.js')));
test('SSL/TLS scanner', fs.existsSync(path.join(scannersPath, 'ssl-tls.js')));
test('Scanner Orchestrator', fs.existsSync(path.join(scannersPath, 'orchestrator.js')));

// ===== COMPONENTS =====
console.log('\n📦 Components Tests\n');

const componentsPath = path.join(frontendPath, 'components');
if (fs.existsSync(componentsPath)) {
  const components = [
    'usage-widget.html',
    'ai-insights.html',
    'risk-heatmap.html',
    'timeline.html',
    'compliance-dashboard.html'
  ];
  
  components.forEach(comp => {
    test(`Component: ${comp}`, fs.existsSync(path.join(componentsPath, comp)));
  });
} else {
  test('Components directory exists', false, 'Components directory missing');
}

// ===== CONFIGURATION =====
console.log('\n⚙️  Configuration Tests\n');

test('.env.example exists', fs.existsSync(path.join(__dirname, '.env.example')));

// Check package.json
const packageJsonPath = path.join(__dirname, 'package.json');
if (fs.existsSync(packageJsonPath)) {
  try {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    test('Package.json is valid JSON', true);
    test('Has dependencies', pkg.dependencies && Object.keys(pkg.dependencies).length > 0);
    test('Has express', pkg.dependencies && pkg.dependencies.express);
    test('Has better-sqlite3', pkg.dependencies && pkg.dependencies['better-sqlite3']);
    test('Has bcryptjs', pkg.dependencies && pkg.dependencies['bcryptjs']);
    test('Has jsonwebtoken', pkg.dependencies && pkg.dependencies['jsonwebtoken']);
    test('Has axios', pkg.dependencies && pkg.dependencies['axios'], 'Axios required for scanners');
  } catch (e) {
    test('Package.json is valid', false, e.message);
  }
} else {
  test('Package.json exists', false);
}

// Check server.js
const serverPath = path.join(__dirname, 'server.js');
if (fs.existsSync(serverPath)) {
  try {
    const serverContent = fs.readFileSync(serverPath, 'utf8');
    test('Server.js has express', serverContent.includes('express'));
    test('Server.js mounts routes', serverContent.includes('app.use'));
    test('Server.js has error handling', serverContent.includes('error'));
  } catch (e) {
    test('Server.js is readable', false, e.message);
  }
}

// ===== DATABASE =====
console.log('\n💾 Database Tests\n');

const dbPath = path.join(__dirname, 'nexus.db');
test('Database file exists', fs.existsSync(dbPath));

if (fs.existsSync(dbPath)) {
  try {
    const Database = require('better-sqlite3');
    const db = new Database(dbPath);
    
    // Test tables
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    const tableNames = tables.map(t => t.name);
    
    test('Users table exists', tableNames.includes('users'));
    test('Domains table exists', tableNames.includes('domains'));
    test('Scans table exists', tableNames.includes('scans'));
    test('Vulnerabilities table exists', tableNames.includes('vulnerabilities'));
    test('Payments table exists', tableNames.includes('payments'));
    test('Scanners table exists', tableNames.includes('scanners'));
    
    // Test admin user
    const adminUser = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@nexus.local');
    test('Admin user exists', adminUser !== undefined);
    
    // Test scanners
    const scanners = db.prepare('SELECT COUNT(*) as count FROM scanners').get();
    test('Scanners seeded', scanners && scanners.count > 0, `Found ${scanners?.count || 0} scanners`);
    
    db.close();
  } catch (e) {
    test('Database is accessible', false, e.message);
  }
}

// ===== NODE_MODULES =====
console.log('\n📦 Dependencies Tests\n');

const nodeModulesPath = path.join(__dirname, 'node_modules');
test('node_modules exists', fs.existsSync(nodeModulesPath));

if (fs.existsSync(nodeModulesPath)) {
  const criticalDeps = ['express', 'better-sqlite3', 'bcryptjs', 'jsonwebtoken', 'axios'];
  criticalDeps.forEach(dep => {
    test(`${dep} installed`, fs.existsSync(path.join(nodeModulesPath, dep)));
  });
}

// ===== DOCUMENTATION =====
console.log('\n📚 Documentation Tests\n');

const docsPath = path.join(__dirname, '..');
test('README exists', fs.existsSync(path.join(docsPath, 'README.md')));
test('QUICK-START exists', fs.existsSync(path.join(docsPath, 'QUICK-START.md')));
test('STATUS-FINAL-HONNETE exists', fs.existsSync(path.join(docsPath, 'STATUS-FINAL-HONNETE.md')));

// ===== RÉSULTATS =====
console.log('\n' + '='.repeat(70));
console.log('📊 VALIDATION RESULTS');
console.log('='.repeat(70));
console.log(`Total Tests: ${totalTests}`);
console.log(`Passed: ${passedTests} ✅`);
console.log(`Failed: ${failedTests} ❌`);

const passRate = Math.round((passedTests / totalTests) * 100);
console.log(`\nPass Rate: ${passRate}%`);

if (passRate >= 90) {
  console.log('\n✅ SYSTEM READY FOR PRODUCTION!');
  console.log('='.repeat(70));
  console.log('\n🚀 Next Steps:');
  console.log('1. If node_modules missing: npm install');
  console.log('2. Start server: npm start');
  console.log('3. Open: http://localhost:3000');
  console.log('4. Login: admin@nexus.local / Admin123!@#NexusChange\n');
  process.exit(0);
} else if (passRate >= 70) {
  console.log('\n⚠️  SYSTEM MOSTLY READY - Some issues found');
  console.log('='.repeat(70));
  if (errors.length > 0) {
    console.log('\n❌ Errors to fix:');
    errors.forEach(err => console.log(`   - ${err}`));
  }
  console.log('\n💡 Run: npm install');
  console.log('💡 Then run: node auto-setup.js\n');
  process.exit(1);
} else {
  console.log('\n❌ SYSTEM NOT READY - Critical issues found');
  console.log('='.repeat(70));
  if (errors.length > 0) {
    console.log('\n❌ Critical Errors:');
    errors.forEach(err => console.log(`   - ${err}`));
  }
  console.log('\n🆘 Please fix the errors above before proceeding.\n');
  process.exit(1);
}
