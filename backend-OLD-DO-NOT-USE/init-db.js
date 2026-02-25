#!/usr/bin/env node
/**
 * NEXUS DATABASE INITIALIZATION - FIXED VERSION
 * Creates ALL tables with ALL columns needed
 */

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'nexus-ultimate.db');
console.log(`🔄 Initializing NEXUS database at: ${dbPath}`);

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

function safeExec(sql, description) {
  try {
    db.exec(sql);
    console.log(`  ✅ ${description}`);
  } catch (err) {
    if (!err.message.includes('already exists') && !err.message.includes('duplicate column')) {
      console.log(`  ❌ ${description}: ${err.message}`);
    }
  }
}

// Users table with ALL columns
safeExec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    company TEXT,
    role TEXT DEFAULT 'user',
    plan TEXT DEFAULT 'free',
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER
  )
`, 'users');

// Domains table with scan_schedule
safeExec(`
  CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    name TEXT,
    security_score INTEGER DEFAULT 0,
    risk_level TEXT,
    last_scan_at INTEGER,
    scan_schedule TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`, 'domains');

// Scans table with scan_type
safeExec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    scan_type TEXT DEFAULT 'manual',
    progress INTEGER DEFAULT 0,
    started_at INTEGER,
    completed_at INTEGER,
    total_vulns INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    security_score INTEGER,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`, 'scans');

// Vulnerabilities table
safeExec(`
  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    domain_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    type TEXT,
    title TEXT NOT NULL,
    description TEXT,
    parameter TEXT,
    payload TEXT,
    evidence TEXT,
    cvss_score REAL,
    confidence TEXT,
    remediation_text TEXT,
    remediation_effort_hours INTEGER,
    owasp_category TEXT,
    cwe_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  )
`, 'vulnerabilities');

// Stripe events table
safeExec(`
  CREATE TABLE IF NOT EXISTS stripe_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT UNIQUE NOT NULL,
    type TEXT NOT NULL,
    data TEXT,
    processed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  )
`, 'stripe_events');

// Error logs table
safeExec(`
  CREATE TABLE IF NOT EXISTS error_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    level TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT 'nexus',
    message TEXT NOT NULL,
    stack TEXT,
    context TEXT,
    user_id INTEGER,
    ip_address TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  )
`, 'error_logs');

// Circuit breaker stats table
safeExec(`
  CREATE TABLE IF NOT EXISTS circuit_breaker_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    breaker_name TEXT UNIQUE NOT NULL,
    state TEXT NOT NULL,
    failures INTEGER DEFAULT 0,
    successes INTEGER DEFAULT 0,
    last_failure_time INTEGER,
    next_attempt_time INTEGER,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
  )
`, 'circuit_breaker_stats');

// Security events table
safeExec(`
  CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    user_id INTEGER,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  )
`, 'security_events');

// User alert preferences table
safeExec(`
  CREATE TABLE IF NOT EXISTS user_alert_preferences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    preferences TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )
`, 'user_alert_preferences');

// Alerts table
safeExec(`
  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    sent_channels TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
  )
`, 'alerts');

// Create indexes
console.log('📊 Creating indexes...');
safeExec('CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain_id)', 'idx_scans_domain');
safeExec('CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)', 'idx_scans_user');
safeExec('CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)', 'idx_scans_status');
safeExec('CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)', 'idx_vulns_scan');
safeExec('CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)', 'idx_vulns_severity');
safeExec('CREATE INDEX IF NOT EXISTS idx_domains_user ON domains(user_id)', 'idx_domains_user');
safeExec('CREATE INDEX IF NOT EXISTS idx_stripe_events ON stripe_events(event_id)', 'idx_stripe_events');
safeExec('CREATE INDEX IF NOT EXISTS idx_error_logs_created ON error_logs(created_at)', 'idx_error_logs_created');

// Create default admin user
console.log('👤 Creating default admin user...');
const adminEmail = 'admin@nexus.local';
const adminPassword = 'Admin123!@#NexusChange';

try {
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(adminEmail);
  if (!existing) {
    const hash = bcrypt.hashSync(adminPassword, 12);
    db.prepare(`
      INSERT INTO users (email, password_hash, name, role, plan)
      VALUES (?, ?, ?, ?, ?)
    `).run(adminEmail, hash, 'Administrator', 'admin', 'enterprise');
    console.log('  ✅ Admin user created');
    console.log('  📧 Email:', adminEmail);
    console.log('  🔑 Password:', adminPassword);
    console.log('  ⚠️  CHANGE THIS PASSWORD IMMEDIATELY!');
  } else {
    console.log('  ℹ️  Admin user already exists');
  }
} catch (err) {
  console.log('  ❌ Admin creation error:', err.message);
}

db.close();

console.log('\n✅ Database initialized successfully!');
console.log('📋 Next: npm start');
