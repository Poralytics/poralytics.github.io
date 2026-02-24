/**
 * NEXUS Database Initialization
 * Run once before first start: node init-db.js
 */

require('dotenv').config();
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, 'nexus-ultimate.db');
console.log('🔄 Initializing NEXUS database at:', dbPath);

const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function safeExec(sql, name) {
  try {
    db.exec(sql);
    console.log(`  ✅ ${name}`);
  } catch (err) {
    if (!err.message.includes('already exists')) {
      console.error(`  ❌ ${name}: ${err.message}`);
    }
  }
}

// Users
safeExec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    role TEXT DEFAULT 'user' CHECK(role IN ('user','admin','enterprise')),
    plan TEXT DEFAULT 'free' CHECK(plan IN ('free','pro','business','enterprise')),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    email_verified INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    updated_at INTEGER DEFAULT (strftime('%s','now'))
  )
`, 'users');

// Domains
safeExec(`
  CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    name TEXT,
    security_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'unknown',
    last_scan_at INTEGER,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`, 'domains');

// Scans
safeExec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed','cancelled')),
    progress INTEGER DEFAULT 0,
    started_at INTEGER DEFAULT (strftime('%s','now')),
    completed_at INTEGER,
    duration INTEGER,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    total_vulns INTEGER DEFAULT 0,
    error_message TEXT
  )
`, 'scans');

// Vulnerabilities
safeExec(`
  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    domain_id INTEGER NOT NULL REFERENCES domains(id),
    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
    category TEXT NOT NULL,
    type TEXT,
    title TEXT NOT NULL,
    description TEXT,
    parameter TEXT,
    payload TEXT,
    evidence TEXT,
    cvss_score REAL DEFAULT 0,
    confidence TEXT DEFAULT 'medium' CHECK(confidence IN ('high','medium','low')),
    remediation_text TEXT,
    remediation_effort_hours INTEGER DEFAULT 0,
    owasp_category TEXT,
    cwe_id TEXT,
    status TEXT DEFAULT 'open' CHECK(status IN ('open','acknowledged','fixed','false_positive')),
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`, 'vulnerabilities');

// Security tables
safeExec(`
  CREATE TABLE IF NOT EXISTS stripe_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    data TEXT,
    processed_at INTEGER DEFAULT (strftime('%s','now'))
  )
`, 'stripe_events');

safeExec(`
  CREATE TABLE IF NOT EXISTS error_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT DEFAULT (datetime('now')),
    level TEXT NOT NULL,
    service TEXT DEFAULT 'nexus',
    message TEXT NOT NULL,
    stack TEXT,
    context TEXT,
    user_id INTEGER,
    ip_address TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`, 'error_logs');

safeExec(`
  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    user_id INTEGER,
    ip_address TEXT,
    details TEXT,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  )
`, 'security_events');

// Indexes
safeExec(`CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain_id)`, 'idx_scans_domain');
safeExec(`CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)`, 'idx_scans_user');
safeExec(`CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)`, 'idx_scans_status');
safeExec(`CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)`, 'idx_vulns_scan');
safeExec(`CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)`, 'idx_vulns_severity');
safeExec(`CREATE INDEX IF NOT EXISTS idx_domains_user ON domains(user_id)`, 'idx_domains_user');
safeExec(`CREATE INDEX IF NOT EXISTS idx_stripe_events ON stripe_events(event_id)`, 'idx_stripe_events');

// Create admin user if doesn't exist
const bcrypt = require('bcryptjs');
const existing = db.prepare("SELECT id FROM users WHERE email = 'admin@nexus.local'").get();
if (!existing) {
  const hash = bcrypt.hashSync('Admin123!@#NexusChange', 12);
  db.prepare(`
    INSERT INTO users (email, password, name, role, plan, email_verified)
    VALUES (?, ?, ?, 'admin', 'enterprise', 1)
  `).run('admin@nexus.local', hash, 'NEXUS Admin');
  console.log('\n  ✅ Admin user created: admin@nexus.local / Admin123!@#NexusChange');
  console.log('  ⚠️  CHANGE THIS PASSWORD IN PRODUCTION!\n');
}

db.close();
console.log('\n✅ Database initialized successfully!');
console.log('📋 Next: npm start\n');

// Add scan automation columns if not exists
try {
  safeExec(`ALTER TABLE domains ADD COLUMN scan_schedule TEXT`, 'domains.scan_schedule');
  safeExec(`ALTER TABLE scans ADD COLUMN scan_type TEXT DEFAULT 'manual'`, 'scans.scan_type');
  console.log('✅ Scan automation columns added');
} catch (e) {
  // Columns may already exist
}
