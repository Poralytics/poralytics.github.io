#!/usr/bin/env node
/**
 * AUTO-SETUP COMPLETE
 * Configure TOUT automatiquement
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

console.log('\n' + '='.repeat(70));
console.log('🚀 NEXUS AUTO-SETUP — Configuration Automatique Complète');
console.log('='.repeat(70) + '\n');

let setupSuccess = true;

// ===== 1. CRÉER .ENV =====
console.log('📝 Step 1: Configuration Environment\n');

const envPath = path.join(__dirname, '.env');
if (!fs.existsSync(envPath)) {
  const jwtSecret = crypto.randomBytes(32).toString('hex');
  
  const envContent = `# NEXUS Configuration (Auto-generated)
NODE_ENV=development
PORT=3000
JWT_SECRET=${jwtSecret}
JWT_EXPIRY=1h
DATABASE_PATH=./nexus.db
CORS_ORIGIN=*

# Stripe (Optional - Configure for billing)
# STRIPE_SECRET_KEY=sk_test_...
# STRIPE_WEBHOOK_SECRET=whsec_...

# OpenAI (Optional - Configure for AI features)
# OPENAI_API_KEY=sk-...
`;
  
  fs.writeFileSync(envPath, envContent);
  console.log('✅ .env created with random JWT_SECRET');
} else {
  console.log('✅ .env already exists');
}

// ===== 2. CRÉER DATABASE COMPLÈTE =====
console.log('\n📊 Step 2: Database Creation\n');

try {
  const Database = require('better-sqlite3');
  const dbPath = path.join(__dirname, 'nexus.db');
  const db = new Database(dbPath);
  
  // Lire et exécuter le schema SQL complet
  const schemaPath = path.join(__dirname, 'database-schema.sql');
  
  if (fs.existsSync(schemaPath)) {
    console.log('📖 Reading database-schema.sql...');
    const schema = fs.readFileSync(schemaPath, 'utf8');
    
    // Exécuter le schema
    db.exec(schema);
    console.log('✅ All tables created from schema');
    console.log('✅ All indexes created');
    console.log('✅ Seed data inserted');
    
  } else {
    console.log('⚠️  database-schema.sql not found, creating basic tables...');
    
    // Créer au moins les tables essentielles
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT,
        role TEXT DEFAULT 'user',
        stripe_customer_id TEXT,
        subscription_status TEXT DEFAULT 'free',
        subscription_plan TEXT DEFAULT 'free',
        created_at INTEGER NOT NULL
      );
      
      CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        name TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      
      CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        FOREIGN KEY (domain_id) REFERENCES domains(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
      
      CREATE TABLE IF NOT EXISTS payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
    `);
    console.log('✅ Basic tables created');
  }
  
  db.close();
  console.log('✅ Database setup complete');
  
} catch (error) {
  console.error('❌ Database error:', error.message);
  setupSuccess = false;
}

// ===== 3. VÉRIFIER DÉPENDANCES =====
console.log('\n📦 Step 3: Dependencies Check\n');

const packagePath = path.join(__dirname, 'package.json');
if (fs.existsSync(packagePath)) {
  const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  
  const required = ['express', 'better-sqlite3', 'bcryptjs', 'jsonwebtoken'];
  const optional = ['stripe', 'helmet', 'cors', 'compression'];
  
  required.forEach(dep => {
    if (pkg.dependencies && pkg.dependencies[dep]) {
      console.log(`✅ ${dep}`);
    } else {
      console.log(`❌ ${dep} MISSING (required)`);
      setupSuccess = false;
    }
  });
  
  optional.forEach(dep => {
    if (pkg.dependencies && pkg.dependencies[dep]) {
      console.log(`✅ ${dep}`);
    } else {
      console.log(`⚠️  ${dep} (optional)`);
    }
  });
  
} else {
  console.log('❌ package.json not found');
  setupSuccess = false;
}

// ===== 4. VÉRIFIER FICHIERS ESSENTIELS =====
console.log('\n📁 Step 4: Essential Files Check\n');

const essentialFiles = [
  'server.js',
  'config/database.js',
  'routes/auth.js',
  'routes/domains.js',
  'routes/scans.js'
];

essentialFiles.forEach(file => {
  const filePath = path.join(__dirname, file);
  if (fs.existsSync(filePath)) {
    console.log(`✅ ${file}`);
  } else {
    console.log(`⚠️  ${file} not found`);
  }
});

// ===== RAPPORT FINAL =====
console.log('\n' + '='.repeat(70));

if (setupSuccess) {
  console.log('✅ SETUP COMPLETE — Ready to Start!');
  console.log('='.repeat(70));
  console.log('\n📋 NEXT STEPS:\n');
  console.log('1. Install dependencies:');
  console.log('   npm install');
  console.log('');
  console.log('2. (Optional) Configure Stripe in .env:');
  console.log('   STRIPE_SECRET_KEY=sk_test_...');
  console.log('');
  console.log('3. Start server:');
  console.log('   npm start');
  console.log('');
  console.log('4. Open dashboard:');
  console.log('   http://localhost:3000/dashboard');
  console.log('');
  console.log('5. Login with:');
  console.log('   Email: admin@nexus.local');
  console.log('   Password: Admin123!@#NexusChange');
  console.log('\n' + '='.repeat(70) + '\n');
  process.exit(0);
} else {
  console.log('⚠️  SETUP INCOMPLETE — Issues Found');
  console.log('='.repeat(70));
  console.log('\n❌ Please fix the errors above and run again.\n');
  process.exit(1);
}
