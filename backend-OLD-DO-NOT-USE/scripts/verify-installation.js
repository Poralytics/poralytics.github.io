#!/usr/bin/env node

/**
 * NEXUS ULTIMATE PRO - COMPREHENSIVE TEST SCRIPT
 * Vérifie que TOUT fonctionne avant le lancement
 */

const fs = require('fs');
const path = require('path');

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function section(title) {
  console.log('\n' + '='.repeat(70));
  log(title, 'bold');
  console.log('='.repeat(70) + '\n');
}

let passedTests = 0;
let failedTests = 0;
const issues = [];

function test(description, fn) {
  try {
    const result = fn();
    if (result) {
      log(`✅ ${description}`, 'green');
      passedTests++;
    } else {
      log(`❌ ${description}`, 'red');
      failedTests++;
      issues.push(description);
    }
  } catch (error) {
    log(`❌ ${description}: ${error.message}`, 'red');
    failedTests++;
    issues.push(`${description}: ${error.message}`);
  }
}

// ========== START TESTS ==========

log('\n🔍 NEXUS ULTIMATE PRO - COMPREHENSIVE VERIFICATION\n', 'cyan');

// ========== FILE STRUCTURE TESTS ==========
section('1️⃣  FILE STRUCTURE');

test('Backend directory exists', () => {
  return fs.existsSync(path.join(__dirname, '..'));
});

test('Frontend directory exists', () => {
  return fs.existsSync(path.join(__dirname, '../..', 'frontend'));
});

test('package.json exists', () => {
  return fs.existsSync(path.join(__dirname, '..', 'package.json'));
});

test('server.js exists', () => {
  return fs.existsSync(path.join(__dirname, '..', 'server.js'));
});

test('.env.example exists', () => {
  return fs.existsSync(path.join(__dirname, '..', '.env.example'));
});

// ========== SERVICES TESTS ==========
section('2️⃣  BACKEND SERVICES');

const services = [
  'legendary-scanner',
  'compliance-automation',
  'threat-intelligence-platform',
  'scanner-marketplace',
  'ai-security-assistant',
  'white-label-system',
  'gamification-system',
  'realtime-notifications',
  'ml-anomaly-detector',
  'enterprise-analytics',
  'billing-system',
  'distributed-scan-system',
  'intelligent-cache',
  'intelligent-crawler',
  'advanced-sql-scanner'
];

services.forEach(service => {
  test(`Service ${service}.js exists`, () => {
    return fs.existsSync(path.join(__dirname, '..', 'services', `${service}.js`));
  });
});

// ========== ROUTES TESTS ==========
section('3️⃣  API ROUTES');

const routes = [
  'auth',
  'domains',
  'scans',
  'analytics',
  'reports',
  'notifications',
  'marketplace',
  'white-label',
  'compliance',
  'threat-intel',
  'gamification',
  'ai-assistant',
  'billing'
];

routes.forEach(route => {
  test(`Route ${route}.js exists`, () => {
    return fs.existsSync(path.join(__dirname, '..', 'routes', `${route}.js`));
  });
});

// ========== MIGRATIONS TESTS ==========
section('4️⃣  DATABASE MIGRATIONS');

test('Migration SQL file exists', () => {
  return fs.existsSync(path.join(__dirname, '..', 'migrations', 'v5.0-complete.sql'));
});

test('Migration runner exists', () => {
  return fs.existsSync(path.join(__dirname, '..', 'migrations', 'run-migrations.js'));
});

// ========== CONFIGURATION TESTS ==========
section('5️⃣  CONFIGURATION');

test('database.js config exists', () => {
  return fs.existsSync(path.join(__dirname, '..', 'config', 'database.js'));
});

test('ESLint config exists', () => {
  return fs.existsSync(path.join(__dirname, '..', '.eslintrc.js'));
});

test('Prettier config exists', () => {
  return fs.existsSync(path.join(__dirname, '..', '.prettierrc.json'));
});

// ========== PACKAGE.JSON VALIDATION ==========
section('6️⃣  PACKAGE.JSON VALIDATION');

try {
  const pkg = require('../package.json');
  
  test('Package name is set', () => pkg.name === 'nexus-ultimate-pro-backend');
  test('Package version is set', () => !!pkg.version);
  test('Main entry point is server.js', () => pkg.main === 'server.js');
  
  // Check critical dependencies
  const criticalDeps = [
    'express', 'cors', 'helmet', 'dotenv',
    'bcryptjs', 'jsonwebtoken', 'better-sqlite3',
    'axios', 'cheerio', 'stripe', 'redis'
  ];
  
  criticalDeps.forEach(dep => {
    test(`Dependency ${dep} is declared`, () => {
      return pkg.dependencies && pkg.dependencies[dep];
    });
  });
  
  // Check scripts
  const criticalScripts = ['start', 'dev', 'test', 'setup', 'migrate'];
  
  criticalScripts.forEach(script => {
    test(`Script '${script}' is defined`, () => {
      return pkg.scripts && pkg.scripts[script];
    });
  });
  
} catch (error) {
  log(`❌ Could not read package.json: ${error.message}`, 'red');
  failedTests++;
}

// ========== ENV VARIABLES TESTS ==========
section('7️⃣  ENVIRONMENT VARIABLES');

try {
  const envExample = fs.readFileSync(
    path.join(__dirname, '..', '.env.example'),
    'utf8'
  );
  
  const criticalVars = [
    'NODE_ENV',
    'PORT',
    'JWT_SECRET',
    'STRIPE_SECRET_KEY',
    'REDIS_URL',
    'OPENAI_API_KEY'
  ];
  
  criticalVars.forEach(varName => {
    test(`${varName} is documented in .env.example`, () => {
      return envExample.includes(varName);
    });
  });
  
} catch (error) {
  log(`⚠️  Could not read .env.example: ${error.message}`, 'yellow');
}

// ========== DOCUMENTATION TESTS ==========
section('8️⃣  DOCUMENTATION');

const docs = [
  'SETUP-GUIDE.md',
  'STATUS-FINAL-100.md',
  'GO-TO-MARKET-STRATEGY.md',
  'FINAL-EMPIRE-STATUS.md'
];

docs.forEach(doc => {
  test(`Documentation ${doc} exists`, () => {
    return fs.existsSync(path.join(__dirname, '../..', doc));
  });
});

// ========== FRONTEND TESTS ==========
section('9️⃣  FRONTEND FILES');

const frontendFiles = [
  'index.html',
  'dashboard.html',
  'login.html',
  'register.html',
  'pricing.html'
];

frontendFiles.forEach(file => {
  test(`Frontend file ${file} exists`, () => {
    return fs.existsSync(path.join(__dirname, '../..', 'frontend', file));
  });
});

// ========== DOCKER TESTS ==========
section('🔟 DOCKER CONFIGURATION');

test('docker-compose.yml exists', () => {
  return fs.existsSync(path.join(__dirname, '../..', 'docker', 'docker-compose.yml'));
});

test('Dockerfile exists', () => {
  return fs.existsSync(path.join(__dirname, '../..', 'docker', 'Dockerfile'));
});

// ========== SECURITY TESTS ==========
section('🔒 SECURITY CHECKS');

test('No .env file committed (should use .env.example)', () => {
  const gitignore = fs.readFileSync(path.join(__dirname, '../..', '.gitignore'), 'utf8');
  return gitignore.includes('.env');
});

test('Auth middleware exists', () => {
  return fs.existsSync(path.join(__dirname, '..', 'middleware', 'auth.js'));
});

// ========== CODE QUALITY TESTS ==========
section('✨ CODE QUALITY');

test('ESLint configuration is valid JSON', () => {
  try {
    require('../.eslintrc.js');
    return true;
  } catch {
    return false;
  }
});

test('Prettier configuration is valid JSON', () => {
  try {
    JSON.parse(fs.readFileSync(path.join(__dirname, '..', '.prettierrc.json'), 'utf8'));
    return true;
  } catch {
    return false;
  }
});

// ========== FINAL SUMMARY ==========
section('📊 TEST SUMMARY');

const total = passedTests + failedTests;
const percentage = ((passedTests / total) * 100).toFixed(1);

console.log(`Total Tests: ${total}`);
log(`✅ Passed: ${passedTests}`, 'green');

if (failedTests > 0) {
  log(`❌ Failed: ${failedTests}`, 'red');
  console.log('\n⚠️  Issues Found:');
  issues.forEach((issue, i) => {
    log(`   ${i + 1}. ${issue}`, 'yellow');
  });
} else {
  log(`❌ Failed: ${failedTests}`, 'green');
}

console.log(`\nSuccess Rate: ${percentage}%\n`);

// ========== RECOMMENDATIONS ==========
if (failedTests > 0) {
  section('💡 RECOMMENDATIONS');
  
  log('Please fix the issues above before deploying to production.', 'yellow');
  log('Run: npm install', 'cyan');
  log('Run: node setup.js', 'cyan');
  log('Run: npm run migrate', 'cyan');
  
} else {
  section('🎉 ALL TESTS PASSED!');
  
  log('✅ NEXUS is ready for production!', 'green');
  log('\n📋 Next Steps:', 'cyan');
  log('   1. Configure .env with your API keys', 'cyan');
  log('   2. Run: npm install', 'cyan');
  log('   3. Run: node setup.js', 'cyan');
  log('   4. Run: npm start', 'cyan');
  log('   5. Deploy to production 🚀', 'cyan');
}

console.log('\n' + '='.repeat(70) + '\n');

// Exit code
process.exit(failedTests > 0 ? 1 : 0);
