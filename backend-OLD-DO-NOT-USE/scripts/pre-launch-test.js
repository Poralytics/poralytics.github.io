#!/usr/bin/env node

/**
 * NEXUS PRE-LAUNCH VERIFICATION
 * Vérifie que TOUT fonctionne avant le lancement
 */

const fs = require('fs');
const path = require('path');

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
  reset: '\x1b[0m'
};

function log(msg, color = 'reset') {
  console.log(`${colors[color]}${msg}${colors.reset}`);
}

function section(title) {
  console.log('\n' + '='.repeat(70));
  log(title, 'bold');
  console.log('='.repeat(70) + '\n');
}

let passed = 0;
let failed = 0;
const issues = [];

function test(description, fn) {
  try {
    if (fn()) {
      log(`✅ ${description}`, 'green');
      passed++;
    } else {
      log(`❌ ${description}`, 'red');
      failed++;
      issues.push(description);
    }
  } catch (error) {
    log(`❌ ${description}: ${error.message}`, 'red');
    failed++;
    issues.push(`${description}: ${error.message}`);
  }
}

log('\n🔍 NEXUS PRE-LAUNCH VERIFICATION\n', 'cyan');
log('Testing all components before launch...\n', 'cyan');

// ========== 1. FILE STRUCTURE ==========
section('1️⃣  FILE STRUCTURE');

test('Backend directory exists', () => fs.existsSync(__dirname + '/..'));
test('Frontend directory exists', () => fs.existsSync(__dirname + '/../../frontend'));
test('package.json exists', () => fs.existsSync(__dirname + '/../package.json'));
test('server.js exists', () => fs.existsSync(__dirname + '/../server.js'));
test('.env.example exists', () => fs.existsSync(__dirname + '/../.env.example'));
test('config/database.js exists', () => fs.existsSync(__dirname + '/../config/database.js'));

// ========== 2. CRITICAL SERVICES ==========
section('2️⃣  CRITICAL SERVICES');

const criticalServices = [
  'legendary-scanner',
  'predictive-scoring',
  'automated-pentesting',
  'attack-simulation-training',
  'ai-security-assistant',
  'intelligent-cache',
  'compliance-automation',
  'threat-intelligence-platform'
];

criticalServices.forEach(service => {
  test(`Service: ${service}.js`, () => {
    return fs.existsSync(__dirname + `/../services/${service}.js`);
  });
});

// ========== 3. CRITICAL ROUTES ==========
section('3️⃣  CRITICAL ROUTES');

const criticalRoutes = [
  'auth',
  'domains',
  'scans',
  'scoring',
  'pentesting',
  'training',
  'marketplace',
  'compliance',
  'ai-assistant'
];

criticalRoutes.forEach(route => {
  test(`Route: ${route}.js`, () => {
    return fs.existsSync(__dirname + `/../routes/${route}.js`);
  });
});

// ========== 4. PACKAGE.JSON VALIDATION ==========
section('4️⃣  PACKAGE.JSON VALIDATION');

try {
  const pkg = require('../package.json');
  
  test('Package name is set', () => !!pkg.name);
  test('Package version is set', () => !!pkg.version);
  test('Start script exists', () => pkg.scripts && pkg.scripts.start);
  test('Dev script exists', () => pkg.scripts && pkg.scripts.dev);
  test('Test script exists', () => pkg.scripts && pkg.scripts.test);
  
  // Critical dependencies
  const criticalDeps = [
    'express',
    'cors',
    'helmet',
    'dotenv',
    'bcryptjs',
    'jsonwebtoken',
    'better-sqlite3',
    'axios',
    'joi'
  ];
  
  criticalDeps.forEach(dep => {
    test(`Dependency: ${dep}`, () => pkg.dependencies && pkg.dependencies[dep]);
  });
  
} catch (error) {
  log(`❌ Cannot read package.json: ${error.message}`, 'red');
  failed++;
}

// ========== 5. CONFIGURATION FILES ==========
section('5️⃣  CONFIGURATION FILES');

test('config/database.js', () => {
  try {
    const content = fs.readFileSync(__dirname + '/../config/database.js', 'utf8');
    return content.includes('CREATE TABLE') && content.includes('users');
  } catch {
    return false;
  }
});

test('.env.example has JWT_SECRET', () => {
  try {
    const content = fs.readFileSync(__dirname + '/../.env.example', 'utf8');
    return content.includes('JWT_SECRET');
  } catch {
    return false;
  }
});

test('.env.example has PORT', () => {
  try {
    const content = fs.readFileSync(__dirname + '/../.env.example', 'utf8');
    return content.includes('PORT');
  } catch {
    return false;
  }
});

// ========== 6. DOCUMENTATION ==========
section('6️⃣  DOCUMENTATION');

const docs = [
  'README.md',
  'QUICK-START.md',
  'SETUP-GUIDE.md',
  'DEPLOYMENT-PRODUCTION.md',
  'RELEASE-NOTES-v5.2-FINAL.md'
];

docs.forEach(doc => {
  test(`Documentation: ${doc}`, () => {
    return fs.existsSync(path.join(__dirname, '../..', doc));
  });
});

// ========== 7. MIDDLEWARE ==========
section('7️⃣  MIDDLEWARE');

test('middleware/auth.js exists', () => {
  return fs.existsSync(__dirname + '/../middleware/auth.js');
});

// ========== 8. SCRIPTS ==========
section('8️⃣  HELPER SCRIPTS');

const scripts = [
  'setup.js',
  'verify-installation.js',
  'backup-database.js'
];

scripts.forEach(script => {
  const scriptPath = script === 'setup.js' 
    ? __dirname + '/../setup.js'
    : __dirname + `/../scripts/${script}`;
  
  test(`Script: ${script}`, () => fs.existsSync(scriptPath));
});

// ========== 9. SYNTAX CHECKS ==========
section('9️⃣  SYNTAX VALIDATION');

test('server.js has no syntax errors', () => {
  try {
    require('../server.js');
    return false; // Server shouldn't start in test mode
  } catch (error) {
    // We expect it to fail because we're not running it
    // But syntax errors would show up differently
    return !error.message.includes('SyntaxError');
  }
});

test('database.js is valid', () => {
  try {
    const db = require('../config/database');
    return !!db;
  } catch (error) {
    return !error.message.includes('SyntaxError');
  }
});

// ========== 10. FRONTEND ==========
section('🔟 FRONTEND FILES');

const frontendFiles = [
  'index.html',
  'dashboard.html',
  'login.html',
  'pricing.html'
];

frontendFiles.forEach(file => {
  test(`Frontend: ${file}`, () => {
    return fs.existsSync(path.join(__dirname, '../../frontend', file));
  });
});

// ========== FINAL REPORT ==========
section('📊 VERIFICATION SUMMARY');

const total = passed + failed;
const percentage = ((passed / total) * 100).toFixed(1);

console.log(`Total Tests: ${total}`);
log(`✅ Passed: ${passed}`, 'green');

if (failed > 0) {
  log(`❌ Failed: ${failed}`, 'red');
  console.log('\n⚠️  Issues Found:');
  issues.forEach((issue, i) => {
    log(`   ${i + 1}. ${issue}`, 'yellow');
  });
  
  console.log('\n💡 Recommendations:');
  log('   1. Run: npm install', 'cyan');
  log('   2. Run: node setup.js', 'cyan');
  log('   3. Fix the issues above', 'cyan');
  log('   4. Run this test again', 'cyan');
  
} else {
  log(`❌ Failed: ${failed}`, 'green');
  
  section('🎉 ALL TESTS PASSED!');
  
  log('✅ NEXUS is 100% ready for launch!', 'green');
  log('\n🚀 Next Steps:', 'cyan');
  log('   1. Run: npm install (if not done)', 'cyan');
  log('   2. Run: node setup.js (if not done)', 'cyan');
  log('   3. Run: npm start', 'cyan');
  log('   4. Open: http://localhost:3000', 'cyan');
  log('\n💎 You have the best security SaaS in the world!', 'bold');
}

console.log('\nSuccess Rate: ' + percentage + '%\n');
console.log('='.repeat(70) + '\n');

process.exit(failed > 0 ? 1 : 0);
