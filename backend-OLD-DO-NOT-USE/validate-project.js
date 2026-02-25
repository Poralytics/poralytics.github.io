#!/usr/bin/env node

console.log('🔍 NEXUS PROJECT VALIDATION\n');

const fs = require('fs');
const path = require('path');

let errors = 0;
let warnings = 0;

// 1. Vérifier structure des dossiers
console.log('📁 Checking directory structure...');
const requiredDirs = [
  'config', 'middleware', 'routes', 'scanners', 'services',
  'tests/unit', 'tests/integration', 'tests/e2e', 'utils', 'workers'
];

requiredDirs.forEach(dir => {
  if (fs.existsSync(dir)) {
    console.log(`  ✓ ${dir}/`);
  } else {
    console.log(`  ✗ ${dir}/ MISSING`);
    errors++;
  }
});

// 2. Vérifier fichiers critiques
console.log('\n📄 Checking critical files...');
const requiredFiles = [
  'server.js', 'init-db.js', 'package.json',
  'config/database.js', 'middleware/auth.js',
  'utils/error-handler.js', 'utils/secure-http-client.js'
];

requiredFiles.forEach(file => {
  if (fs.existsSync(file)) {
    console.log(`  ✓ ${file}`);
  } else {
    console.log(`  ✗ ${file} MISSING`);
    errors++;
  }
});

// 3. Vérifier scanners
console.log('\n🔍 Checking scanners...');
const scanners = fs.readdirSync('scanners').filter(f => f.endsWith('.js'));
console.log(`  Found ${scanners.length} scanners`);
if (scanners.length !== 23) {
  console.log(`  ⚠️  Expected 23 scanners, found ${scanners.length}`);
  warnings++;
}

// 4. Vérifier routes
console.log('\n🛣️  Checking routes...');
const routes = fs.readdirSync('routes').filter(f => f.endsWith('.js'));
console.log(`  Found ${routes.length} route files`);

// 5. Vérifier package.json
console.log('\n📦 Checking package.json...');
try {
  const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
  console.log(`  ✓ Name: ${pkg.name}`);
  console.log(`  ✓ Version: ${pkg.version}`);
  console.log(`  ✓ Dependencies: ${Object.keys(pkg.dependencies || {}).length}`);
  console.log(`  ✓ DevDependencies: ${Object.keys(pkg.devDependencies || {}).length}`);
} catch (e) {
  console.log(`  ✗ Invalid package.json: ${e.message}`);
  errors++;
}

// 6. Résumé
console.log('\n' + '='.repeat(50));
console.log(`✓ Errors: ${errors}`);
console.log(`⚠️  Warnings: ${warnings}`);

if (errors === 0) {
  console.log('\n✅ PROJECT STRUCTURE VALID');
  process.exit(0);
} else {
  console.log('\n❌ PROJECT HAS ERRORS');
  process.exit(1);
}
