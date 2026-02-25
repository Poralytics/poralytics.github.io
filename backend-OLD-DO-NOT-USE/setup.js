#!/usr/bin/env node

/**
 * NEXUS ULTIMATE PRO - AUTOMATED SETUP SCRIPT
 * Configure tout le projet en une commande
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSection(title) {
  console.log('\n' + '='.repeat(60));
  log(title, 'bright');
  console.log('='.repeat(60) + '\n');
}

function execCommand(command, description) {
  try {
    log(`⏳ ${description}...`, 'cyan');
    execSync(command, { stdio: 'inherit' });
    log(`✅ ${description} - Done!`, 'green');
    return true;
  } catch (error) {
    log(`❌ ${description} - Failed!`, 'red');
    log(`   Error: ${error.message}`, 'red');
    return false;
  }
}

async function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

// Check if a module is available
function isModuleAvailable(moduleName) {
  try {
    require.resolve(moduleName);
    return true;
  } catch {
    return false;
  }
}

async function setup() {
  log('\n🚀 NEXUS ULTIMATE PRO - AUTOMATED SETUP', 'bright');
  log('   Setting up your enterprise security platform...\n', 'cyan');

  // ========== STEP 1: CHECK NODE VERSION ==========
  logSection('1️⃣  CHECKING PREREQUISITES');
  
  const nodeVersion = process.version;
  const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0]);
  
  if (majorVersion >= 18) {
    log(`✅ Node.js ${nodeVersion} (>= 18 required)`, 'green');
  } else {
    log(`❌ Node.js ${nodeVersion} is too old. Please upgrade to Node 18+`, 'red');
    process.exit(1);
  }

  // ========== STEP 2: ENVIRONMENT ==========
  logSection('2️⃣  ENVIRONMENT CONFIGURATION');

  const envExists = fs.existsSync(path.join(__dirname, '..', '.env'));

  if (!envExists) {
    log('📝 Creating .env file from template...', 'yellow');
    fs.copyFileSync(
      path.join(__dirname, '..', '.env.example'),
      path.join(__dirname, '..', '.env')
    );
    log('✅ .env file created!', 'green');
    log('⚠️  Please edit .env and add your API keys before starting', 'yellow');
  } else {
    log('✅ .env file already exists', 'green');
  }

  // ========== STEP 3: DEPENDENCIES ==========
  logSection('3️⃣  INSTALLING DEPENDENCIES');

  const installDeps = await question('Install npm dependencies? (y/n): ');

  if (installDeps.toLowerCase() === 'y') {
    // Check if better-sqlite3 is available
    const hasSqlite = isModuleAvailable('better-sqlite3');
    
    if (!hasSqlite) {
      log('📦 Installing essential dependencies...', 'cyan');
      
      // Try to install essentials first
      const essentials = 'express cors helmet dotenv bcryptjs jsonwebtoken better-sqlite3 axios cheerio compression express-rate-limit joi uuid validator';
      
      const success = execCommand(
        `npm install ${essentials}`,
        'Installing essential packages'
      );
      
      if (!success) {
        log('⚠️  Some packages failed to install', 'yellow');
        log('   Continuing with available packages...', 'yellow');
      }
    } else {
      log('✅ Essential packages already installed', 'green');
    }
    
    // Ask about optional packages
    const installOptional = await question('Install optional packages (Stripe, Redis, etc.)? (y/n): ');
    
    if (installOptional.toLowerCase() === 'y') {
      const optional = 'stripe redis ioredis bullmq ws nodemailer pdfkit exceljs sharp web-push multer archiver csv-parser date-fns';
      execCommand(
        `npm install ${optional}`,
        'Installing optional packages'
      );
    } else {
      log('⏭️  Skipped optional packages', 'yellow');
      log('   You can install them later with: npm install', 'cyan');
    }
  } else {
    log('⏭️  Skipped dependency installation', 'yellow');
  }

  // ========== STEP 4: DATABASE ==========
  logSection('4️⃣  DATABASE SETUP');

  const setupDb = await question('Setup database? (y/n): ');

  if (setupDb.toLowerCase() === 'y') {
    log('📊 Initializing database...', 'cyan');
    
    try {
      // Load database module (this will create tables)
      require('../config/database');
      log('✅ Database initialized successfully!', 'green');
    } catch (error) {
      log(`❌ Database initialization error: ${error.message}`, 'red');
      log('   Make sure better-sqlite3 is installed: npm install better-sqlite3', 'yellow');
    }

    // Create admin user
    const createAdmin = await question('Create admin user? (y/n): ');
    
    if (createAdmin.toLowerCase() === 'y') {
      log('\n👤 Creating admin user...', 'cyan');
      const adminEmail = await question('Admin email: ');
      const adminPassword = await question('Admin password: ');

      try {
        const bcrypt = require('bcryptjs');
        const db = require('../config/database');
        
        const hashedPassword = bcrypt.hashSync(adminPassword, 10);
        
        db.prepare(`
          INSERT OR IGNORE INTO users (email, password, name, role, subscription_tier, gamification_points, gamification_level)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(adminEmail, hashedPassword, 'Admin', 'admin', 'enterprise', 1000, 5);

        log('✅ Admin user created!', 'green');
      } catch (error) {
        log(`⚠️  Admin user creation error: ${error.message}`, 'yellow');
        log('   You can create it manually later', 'yellow');
      }
    }
  } else {
    log('⏭️  Skipped database setup', 'yellow');
  }

  // ========== STEP 5: OPTIONAL SERVICES ==========
  logSection('5️⃣  OPTIONAL SERVICES');

  log('ℹ️  Optional services enhance NEXUS but aren\'t required:', 'cyan');
  log('   • Redis - Caching and queues (performance boost)', 'yellow');
  log('   • Stripe - Payment processing (billing)', 'yellow');
  log('   • OpenAI - AI assistant features', 'yellow');
  log('   • SMTP - Email notifications', 'yellow');
  log('\n💡 You can configure these later in .env', 'cyan');

  // ========== STEP 6: DIRECTORIES ==========
  logSection('6️⃣  CREATING DIRECTORIES');

  const directories = [
    'uploads',
    'reports',
    'backups',
    'logs',
    '../public/white-label'
  ];

  directories.forEach(dir => {
    const dirPath = path.join(__dirname, '..', dir);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
      log(`✅ Created directory: ${dir}`, 'green');
    } else {
      log(`✅ Directory exists: ${dir}`, 'green');
    }
  });

  // ========== STEP 7: VERIFICATION ==========
  logSection('7️⃣  VERIFICATION');

  log('🔍 Checking setup...', 'cyan');

  const checks = {
    '.env file': fs.existsSync(path.join(__dirname, '..', '.env')),
    'config/database.js': fs.existsSync(path.join(__dirname, '..', 'config', 'database.js')),
    'server.js': fs.existsSync(path.join(__dirname, '..', 'server.js')),
    'uploads directory': fs.existsSync(path.join(__dirname, '..', 'uploads')),
    'reports directory': fs.existsSync(path.join(__dirname, '..', 'reports')),
    'better-sqlite3 module': isModuleAvailable('better-sqlite3'),
    'express module': isModuleAvailable('express')
  };

  let allGood = true;
  Object.entries(checks).forEach(([name, exists]) => {
    if (exists) {
      log(`✅ ${name}`, 'green');
    } else {
      log(`❌ ${name}`, 'red');
      allGood = false;
    }
  });

  // ========== STEP 8: SUMMARY ==========
  logSection('8️⃣  SETUP SUMMARY');

  if (allGood) {
    log('🎉 SETUP COMPLETE!', 'bright');
    log('\nYour NEXUS Ultimate Pro instance is ready!\n', 'green');
    
    log('📋 Next Steps:', 'cyan');
    log('   1. Edit .env and add your API keys (optional)', 'cyan');
    log('   2. Start the server: npm start', 'cyan');
    log('   3. Open http://localhost:3000', 'cyan');
    
    log('\n🔥 Quick Start Commands:', 'yellow');
    log('   Development: npm run dev', 'cyan');
    log('   Production:  npm start', 'cyan');
    log('   Tests:       npm test', 'cyan');

  } else {
    log('⚠️  SETUP INCOMPLETE', 'yellow');
    log('\nSome components are missing. Common fixes:\n', 'yellow');
    log('   • Run: npm install', 'cyan');
    log('   • Check Node.js version (need 18+)', 'cyan');
    log('   • Make sure you\'re in the backend/ directory', 'cyan');
  }

  // ========== STEP 9: START NOW? ==========
  logSection('9️⃣  START SERVER NOW?');

  if (allGood) {
    const startNow = await question('Start NEXUS now? (y/n): ');

    if (startNow.toLowerCase() === 'y') {
      log('\n🚀 Starting NEXUS Ultimate Pro...', 'cyan');
      log('   Server will start on http://localhost:3000', 'cyan');
      log('   Press Ctrl+C to stop\n', 'yellow');
      
      try {
        execSync('npm start', { stdio: 'inherit' });
      } catch (error) {
        // User pressed Ctrl+C
        log('\n👋 Server stopped', 'yellow');
      }
    } else {
      log('\n👋 Setup complete! Start with: npm start', 'green');
    }
  } else {
    log('\n💡 Fix the issues above, then run: npm start', 'cyan');
  }

  rl.close();
}

// Run setup
setup().catch(error => {
  log(`\n❌ Setup failed: ${error.message}`, 'red');
  console.error(error);
  process.exit(1);
});

  // ========== STEP 1: ENVIRONMENT ==========
  logSection('1️⃣  ENVIRONMENT CONFIGURATION');

  const envExists = fs.existsSync(path.join(__dirname, '.env'));

  if (!envExists) {
    log('📝 Creating .env file from template...', 'yellow');
    fs.copyFileSync(
      path.join(__dirname, '.env.example'),
      path.join(__dirname, '.env')
    );
    log('✅ .env file created!', 'green');
    log('⚠️  Please edit .env and add your API keys', 'yellow');
  } else {
    log('✅ .env file already exists', 'green');
  }

  // ========== STEP 2: DEPENDENCIES ==========
  logSection('2️⃣  INSTALLING DEPENDENCIES');

  const installDeps = await question('Install npm dependencies? (y/n): ');

  if (installDeps.toLowerCase() === 'y') {
    execCommand('npm install', 'Installing npm packages');
  } else {
    log('⏭️  Skipped dependency installation', 'yellow');
  }

  // ========== STEP 3: DATABASE ==========
  logSection('3️⃣  DATABASE SETUP');

  const setupDb = await question('Setup database? (y/n): ');

  if (setupDb.toLowerCase() === 'y') {
    // Run migrations
    log('📊 Running database migrations...', 'cyan');
    
    try {
      require('./migrations/run-migrations.js');
      log('✅ Database migrations complete!', 'green');
    } catch (error) {
      log(`❌ Migration error: ${error.message}`, 'red');
    }

    // Create admin user
    log('\n👤 Creating admin user...', 'cyan');
    const adminEmail = await question('Admin email: ');
    const adminPassword = await question('Admin password: ');

    try {
      const bcrypt = require('bcryptjs');
      const db = require('./config/database');
      
      const hashedPassword = bcrypt.hashSync(adminPassword, 10);
      
      db.prepare(`
        INSERT INTO users (email, password, name, role, subscription_tier)
        VALUES (?, ?, 'Admin', 'admin', 'enterprise')
      `).run(adminEmail, hashedPassword);

      log('✅ Admin user created!', 'green');
    } catch (error) {
      log(`⚠️  Admin user creation error: ${error.message}`, 'yellow');
    }
  } else {
    log('⏭️  Skipped database setup', 'yellow');
  }

  // ========== STEP 4: REDIS (OPTIONAL) ==========
  logSection('4️⃣  REDIS SETUP (OPTIONAL)');

  const useRedis = await question('Do you have Redis installed? (y/n): ');

  if (useRedis.toLowerCase() === 'y') {
    log('✅ Redis will be used for caching and queues', 'green');
    log('   Make sure Redis is running: redis-server', 'cyan');
  } else {
    log('⚠️  Redis not configured - some features may be limited', 'yellow');
    log('   Install Redis: brew install redis (Mac) or apt-get install redis (Linux)', 'cyan');
  }

  // ========== STEP 5: STRIPE (OPTIONAL) ==========
  logSection('5️⃣  STRIPE SETUP (OPTIONAL)');

  const useStripe = await question('Configure Stripe for billing? (y/n): ');

  if (useStripe.toLowerCase() === 'y') {
    log('📝 Stripe Configuration:', 'cyan');
    log('   1. Go to https://dashboard.stripe.com/test/apikeys', 'cyan');
    log('   2. Copy your Secret Key (sk_test_...)', 'cyan');
    log('   3. Add it to .env as STRIPE_SECRET_KEY', 'cyan');
    log('   4. Create products and copy Price IDs to .env', 'cyan');
    log('\n✅ Remember to update .env with your Stripe keys!', 'yellow');
  } else {
    log('⏭️  Skipped Stripe configuration', 'yellow');
  }

  // ========== STEP 6: AI ASSISTANT (OPTIONAL) ==========
  logSection('6️⃣  AI ASSISTANT SETUP (OPTIONAL)');

  const useAI = await question('Configure AI Assistant (OpenAI)? (y/n): ');

  if (useAI.toLowerCase() === 'y') {
    log('📝 OpenAI Configuration:', 'cyan');
    log('   1. Go to https://platform.openai.com/api-keys', 'cyan');
    log('   2. Create a new API key', 'cyan');
    log('   3. Add it to .env as OPENAI_API_KEY', 'cyan');
    log('\n✅ Remember to update .env with your OpenAI key!', 'yellow');
  } else {
    log('⏭️  Skipped AI configuration', 'yellow');
  }

  // ========== STEP 7: DIRECTORIES ==========
  logSection('7️⃣  CREATING DIRECTORIES');

  const directories = [
    'uploads',
    'reports',
    'backups',
    'logs',
    'public/white-label'
  ];

  directories.forEach(dir => {
    const dirPath = path.join(__dirname, '..', dir);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
      log(`✅ Created directory: ${dir}`, 'green');
    } else {
      log(`✅ Directory exists: ${dir}`, 'green');
    }
  });

  // ========== STEP 8: VERIFICATION ==========
  logSection('8️⃣  VERIFICATION');

  log('🔍 Checking setup...', 'cyan');

  const checks = {
    '.env file': fs.existsSync(path.join(__dirname, '.env')),
    'node_modules': fs.existsSync(path.join(__dirname, 'node_modules')),
    'database': fs.existsSync(path.join(__dirname, 'nexus-ultimate.db')),
    'uploads directory': fs.existsSync(path.join(__dirname, '..', 'uploads')),
    'reports directory': fs.existsSync(path.join(__dirname, '..', 'reports'))
  };

  let allGood = true;
  Object.entries(checks).forEach(([name, exists]) => {
    if (exists) {
      log(`✅ ${name}`, 'green');
    } else {
      log(`❌ ${name}`, 'red');
      allGood = false;
    }
  });

  // ========== STEP 9: SUMMARY ==========
  logSection('9️⃣  SETUP SUMMARY');

  if (allGood) {
    log('🎉 SETUP COMPLETE!', 'bright');
    log('\nYour NEXUS Ultimate Pro instance is ready!\n', 'green');
    
    log('📋 Next Steps:', 'cyan');
    log('   1. Edit .env and add your API keys', 'cyan');
    log('   2. Start Redis (if using): redis-server', 'cyan');
    log('   3. Start the server: npm start', 'cyan');
    log('   4. Open http://localhost:3000', 'cyan');
    log('   5. Login with your admin credentials', 'cyan');
    
    log('\n🔥 Quick Start Commands:', 'yellow');
    log('   Development: npm run dev', 'cyan');
    log('   Production:  npm start', 'cyan');
    log('   Tests:       npm test', 'cyan');
    log('   Migrations:  node backend/migrations/run-migrations.js', 'cyan');

  } else {
    log('⚠️  SETUP INCOMPLETE', 'yellow');
    log('\nSome components are missing. Please review the errors above.\n', 'yellow');
  }

  // ========== STEP 10: OPTIONAL SERVICES ==========
  logSection('🔟 OPTIONAL: START SERVICES NOW?');

  const startNow = await question('Start the server now? (y/n): ');

  if (startNow.toLowerCase() === 'y') {
    log('\n🚀 Starting NEXUS Ultimate Pro...', 'cyan');
    execCommand('npm start', 'Starting server');
  } else {
    log('\n👋 Setup complete! Start the server with: npm start', 'green');
  }

  rl.close();
}

// Run setup
setup().catch(error => {
  log(`\n❌ Setup failed: ${error.message}`, 'red');
  process.exit(1);
});
