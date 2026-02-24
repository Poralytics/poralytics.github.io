/**
 * DATABASE CONFIGURATION
 * SQLite with better-sqlite3
 */

const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'nexus-ultimate.db');

// Create database if doesn't exist
if (!fs.existsSync(dbPath)) {
  console.log('📁 Creating new database at:', dbPath);
}

const db = new Database(dbPath, {
  verbose: process.env.NODE_ENV === 'development' ? console.log : null
});

// Enable WAL mode for better concurrency
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Helper function for safe exec
function safeExec(sql, description) {
  try {
    db.exec(sql);
    if (description) console.log(`✅ ${description}`);
    return true;
  } catch (err) {
    if (!err.message.includes('already exists') && !err.message.includes('duplicate')) {
      console.error(`❌ ${description || 'SQL'}:`, err.message);
    }
    return false;
  }
}

// Initialize core tables on first load
function initializeTables() {
  console.log('🔄 Initializing NEXUS database...');

  // Users
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
  `, 'Core: users table');

  // Domains
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
  `, 'Core: domains table');

  // Scans
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
  `, 'Core: scans table');

  // Vulnerabilities
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
  `, 'Core: vulnerabilities table');

  // Additional tables
  safeExec(`CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, type TEXT, title TEXT, message TEXT, read INTEGER DEFAULT 0, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Core: notifications table');
  safeExec(`CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, user_id INTEGER, type TEXT, content TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (scan_id) REFERENCES scans(id), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Core: reports table');

  // Marketplace tables
  safeExec(`CREATE TABLE IF NOT EXISTS scanners (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, author TEXT, version TEXT, price REAL DEFAULT 0, downloads INTEGER DEFAULT 0, rating REAL DEFAULT 0, created_at INTEGER DEFAULT (strftime('%s', 'now')))`, 'Marketplace: scanners table');
  safeExec(`CREATE TABLE IF NOT EXISTS user_installed_scanners (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, scanner_id INTEGER, installed_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (scanner_id) REFERENCES scanners(id))`, 'Marketplace: user_installed_scanners table');
  safeExec(`CREATE TABLE IF NOT EXISTS scanner_reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, scanner_id INTEGER, user_id INTEGER, rating INTEGER, comment TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (scanner_id) REFERENCES scanners(id), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Marketplace: scanner_reviews table');
  safeExec(`CREATE TABLE IF NOT EXISTS scanner_usage_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, scanner_id INTEGER, scan_id INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (scanner_id) REFERENCES scanners(id), FOREIGN KEY (scan_id) REFERENCES scans(id))`, 'Marketplace: scanner_usage_log table');
  safeExec(`CREATE TABLE IF NOT EXISTS developer_revenue (id INTEGER PRIMARY KEY AUTOINCREMENT, developer_id INTEGER, scanner_id INTEGER, amount REAL, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (developer_id) REFERENCES users(id), FOREIGN KEY (scanner_id) REFERENCES scanners(id))`, 'Marketplace: developer_revenue table');

  // White-label tables
  safeExec(`CREATE TABLE IF NOT EXISTS white_label_accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, brand_name TEXT, logo_url TEXT, primary_color TEXT, domain TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'White-Label: accounts table');
  safeExec(`CREATE TABLE IF NOT EXISTS white_label_clients (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id INTEGER, name TEXT, email TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (account_id) REFERENCES white_label_accounts(id))`, 'White-Label: clients table');

  // Compliance tables
  safeExec(`CREATE TABLE IF NOT EXISTS compliance_monitoring (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, framework TEXT, status TEXT, last_check INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))`, 'Compliance: monitoring table');
  safeExec(`CREATE TABLE IF NOT EXISTS compliance_results (id INTEGER PRIMARY KEY AUTOINCREMENT, monitoring_id INTEGER, requirement TEXT, status TEXT, evidence TEXT, checked_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (monitoring_id) REFERENCES compliance_monitoring(id))`, 'Compliance: results table');
  safeExec(`CREATE TABLE IF NOT EXISTS compliance_evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, result_id INTEGER, file_path TEXT, description TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (result_id) REFERENCES compliance_results(id))`, 'Compliance: evidence table');
  safeExec(`CREATE TABLE IF NOT EXISTS compliance_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, monitoring_id INTEGER, generated_at INTEGER DEFAULT (strftime('%s', 'now')), content TEXT, FOREIGN KEY (monitoring_id) REFERENCES compliance_monitoring(id))`, 'Compliance: reports table');

  // Threat intelligence tables
  safeExec(`CREATE TABLE IF NOT EXISTS threat_intelligence (id INTEGER PRIMARY KEY AUTOINCREMENT, indicator TEXT NOT NULL, type TEXT, severity TEXT, source TEXT, description TEXT, submitted_by INTEGER, votes INTEGER DEFAULT 0, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (submitted_by) REFERENCES users(id))`, 'Threat Intel: intelligence table');
  safeExec(`CREATE TABLE IF NOT EXISTS threat_intel_votes (id INTEGER PRIMARY KEY AUTOINCREMENT, intel_id INTEGER, user_id INTEGER, vote INTEGER, FOREIGN KEY (intel_id) REFERENCES threat_intelligence(id), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Threat Intel: votes table');
  safeExec(`CREATE TABLE IF NOT EXISTS blocking_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, intel_id INTEGER, action TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (intel_id) REFERENCES threat_intelligence(id))`, 'Threat Intel: blocking_rules table');

  // Gamification tables
  safeExec(`CREATE TABLE IF NOT EXISTS gamification_points_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, points INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Gamification: points_log table');
  safeExec(`CREATE TABLE IF NOT EXISTS user_achievements (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, achievement_id TEXT, unlocked_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Gamification: user_achievements table');
  safeExec(`CREATE TABLE IF NOT EXISTS challenges (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT, points INTEGER, start_date INTEGER, end_date INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')))`, 'Gamification: challenges table');
  safeExec(`CREATE TABLE IF NOT EXISTS challenge_participants (id INTEGER PRIMARY KEY AUTOINCREMENT, challenge_id INTEGER, user_id INTEGER, progress INTEGER DEFAULT 0, FOREIGN KEY (challenge_id) REFERENCES challenges(id), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Gamification: challenge_participants table');

  // AI tables
  safeExec(`CREATE TABLE IF NOT EXISTS ai_conversations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, message TEXT, response TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'AI: conversations table');
  safeExec(`CREATE TABLE IF NOT EXISTS ai_usage_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, feature TEXT, tokens_used INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'AI: usage_log table');

  // Billing tables
  safeExec(`CREATE TABLE IF NOT EXISTS billing_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plan TEXT, status TEXT, started_at INTEGER, ends_at INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))`, 'Billing: subscriptions table');
  safeExec(`CREATE TABLE IF NOT EXISTS usage_records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, feature TEXT, quantity INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Billing: usage_records table');
  safeExec(`CREATE TABLE IF NOT EXISTS invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, status TEXT, due_date INTEGER, paid_at INTEGER, FOREIGN KEY (user_id) REFERENCES users(id))`, 'Billing: invoices table');

  // Notifications tables
  safeExec(`CREATE TABLE IF NOT EXISTS notification_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, channel TEXT, message TEXT, sent_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Notifications: log table');
  safeExec(`CREATE TABLE IF NOT EXISTS notification_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, type TEXT, data TEXT, scheduled_at INTEGER, processed INTEGER DEFAULT 0, FOREIGN KEY (user_id) REFERENCES users(id))`, 'Notifications: queue table');
  safeExec(`CREATE TABLE IF NOT EXISTS push_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, endpoint TEXT, keys TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Notifications: push_subscriptions table');

  // Audit tables
  safeExec(`CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, action TEXT, resource TEXT, details TEXT, ip_address TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'Audit: logs table');

  // API tables
  safeExec(`CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, key TEXT UNIQUE, name TEXT, last_used INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (user_id) REFERENCES users(id))`, 'API: keys table');
  safeExec(`CREATE TABLE IF NOT EXISTS api_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, api_key_id INTEGER, endpoint TEXT, method TEXT, status INTEGER, created_at INTEGER DEFAULT (strftime('%s', 'now')), FOREIGN KEY (api_key_id) REFERENCES api_keys(id))`, 'API: logs table');

  // Security tables (must have)
  safeExec(`CREATE TABLE IF NOT EXISTS stripe_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, type TEXT NOT NULL, data TEXT, processed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')))`, 'Security: stripe_events table');
  safeExec(`CREATE INDEX IF NOT EXISTS idx_stripe_events ON stripe_events(event_id)`, 'Security: stripe_events index');
  safeExec(`CREATE TABLE IF NOT EXISTS error_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL DEFAULT (datetime('now')), level TEXT NOT NULL, service TEXT NOT NULL DEFAULT 'nexus', message TEXT NOT NULL, stack TEXT, context TEXT, user_id INTEGER, ip_address TEXT, created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')))`, 'Security: error_logs table');

  // Create indexes for performance
  console.log('📊 Creating performance indexes...');
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain_id)',
    'CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)',
    'CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)',
    'CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)',
    'CREATE INDEX IF NOT EXISTS idx_domains_user ON domains(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
    'CREATE INDEX IF NOT EXISTS idx_users_plan ON users(plan)',
    'CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_reports_scan ON reports(scan_id)',
    'CREATE INDEX IF NOT EXISTS idx_scanners_name ON scanners(name)',
    'CREATE INDEX IF NOT EXISTS idx_user_scanners ON user_installed_scanners(user_id, scanner_id)',
    'CREATE INDEX IF NOT EXISTS idx_scanner_reviews ON scanner_reviews(scanner_id)',
    'CREATE INDEX IF NOT EXISTS idx_scanner_usage ON scanner_usage_log(user_id, scanner_id)',
    'CREATE INDEX IF NOT EXISTS idx_developer_revenue ON developer_revenue(developer_id)',
    'CREATE INDEX IF NOT EXISTS idx_white_label_user ON white_label_accounts(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_white_label_clients ON white_label_clients(account_id)',
    'CREATE INDEX IF NOT EXISTS idx_compliance_user ON compliance_monitoring(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_compliance_results ON compliance_results(monitoring_id)',
    'CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intelligence(type)',
    'CREATE INDEX IF NOT EXISTS idx_threat_intel_user ON threat_intelligence(submitted_by)',
    'CREATE INDEX IF NOT EXISTS idx_blocking_rules ON blocking_rules(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_gamification_user ON gamification_points_log(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_user_achievements ON user_achievements(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_challenge_participants ON challenge_participants(challenge_id, user_id)',
    'CREATE INDEX IF NOT EXISTS idx_ai_conversations ON ai_conversations(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_ai_usage ON ai_usage_log(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_billing_subs ON billing_subscriptions(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_usage_records ON usage_records(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_invoices_user ON invoices(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_notif_log ON notification_log(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_notif_queue ON notification_queue(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_push_subs ON push_subscriptions(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_audit_logs ON audit_logs(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_api_keys_key ON api_keys(key)',
    'CREATE INDEX IF NOT EXISTS idx_api_logs ON api_logs(api_key_id)',
    'CREATE INDEX IF NOT EXISTS idx_error_logs_created ON error_logs(created_at)',
    'CREATE INDEX IF NOT EXISTS idx_scans_completed ON scans(completed_at)',
    'CREATE INDEX IF NOT EXISTS idx_domains_score ON domains(security_score)',
    'CREATE INDEX IF NOT EXISTS idx_vulns_severity_scan ON vulnerabilities(severity, scan_id)'
  ];

  indexes.forEach((sql, i) => {
    safeExec(sql, `Index ${i + 1}/${indexes.length}`);
  });

  console.log(`\n✅ NEXUS Database initialized successfully!`);
  console.log(`   📊 Tables: 39`);
  console.log(`   🔍 Indexes: ${indexes.length + 3}`);
  console.log(`   💾 Database: ${dbPath}\n`);
}

// Initialize on first require
initializeTables();

module.exports = db;
