#!/usr/bin/env node

/**
 * Install Essential Dependencies Only
 * Installs only the critical dependencies needed to run NEXUS
 * Optional deps (Stripe, Redis, OpenAI) can be added later
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const colors = {
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function execCommand(command, description) {
  try {
    log(`⏳ ${description}...`, 'cyan');
    execSync(command, { stdio: 'inherit' });
    log(`✅ ${description} - Done!`, 'green');
    return true;
  } catch (error) {
    log(`❌ ${description} - Failed!`, 'red');
    return false;
  }
}

log('\n🚀 Installing NEXUS Essential Dependencies\n', 'cyan');

// Essential dependencies (must have)
const essentials = [
  'express',
  'cors',
  'helmet',
  'dotenv',
  'bcryptjs',
  'jsonwebtoken',
  'better-sqlite3',
  'axios',
  'cheerio',
  'compression',
  'express-rate-limit',
  'joi',
  'uuid',
  'form-data',
  'validator'
];

// Optional dependencies (nice to have)
const optional = {
  'stripe': 'Billing (Stripe payments)',
  'redis': 'Caching (performance boost)',
  'ioredis': 'Caching (alternative)',
  'bullmq': 'Queue management',
  'ws': 'WebSocket (real-time)',
  'nodemailer': 'Email notifications',
  'pdfkit': 'PDF reports',
  'exceljs': 'Excel reports',
  'sharp': 'Image processing',
  'web-push': 'Push notifications'
};

log('📦 Installing essential dependencies...', 'yellow');
log(`   Installing: ${essentials.join(', ')}`, 'cyan');

const essentialsCmd = `npm install --save ${essentials.join(' ')}`;
const success = execCommand(essentialsCmd, 'Installing essentials');

if (!success) {
  log('\n❌ Failed to install essential dependencies', 'red');
  log('   Try manually: npm install', 'yellow');
  process.exit(1);
}

log('\n✅ Essential dependencies installed!', 'green');
log('\n📋 Optional Dependencies (can install later):', 'cyan');

Object.entries(optional).forEach(([pkg, desc]) => {
  log(`   • ${pkg} - ${desc}`, 'yellow');
  log(`     Install: npm install ${pkg}`, 'cyan');
});

log('\n💡 To install ALL dependencies (including optional):', 'cyan');
log('   npm install\n', 'yellow');

log('✅ NEXUS is ready to start with essential features!', 'green');
log('   Run: npm start\n', 'cyan');
