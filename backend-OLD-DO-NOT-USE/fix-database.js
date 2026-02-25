const Database = require('better-sqlite3');
const db = new Database('./nexus-ultimate.db');

console.log('🔧 Fixing database schema...');

// Vérifier si la colonne company existe
try {
  const cols = db.pragma("table_info('users')");
  const hasCompany = cols.some(c => c.name === 'company');
  
  if (!hasCompany) {
    console.log('  Adding company column to users...');
    db.exec('ALTER TABLE users ADD COLUMN company TEXT');
    console.log('  ✅ Added company column');
  } else {
    console.log('  ✓ Company column already exists');
  }
} catch (e) {
  console.log('  ✗ Error:', e.message);
}

// Vérifier scan_schedule
try {
  const cols = db.pragma("table_info('domains')");
  const hasSchedule = cols.some(c => c.name === 'scan_schedule');
  
  if (!hasSchedule) {
    console.log('  Adding scan_schedule column to domains...');
    db.exec('ALTER TABLE domains ADD COLUMN scan_schedule TEXT');
    console.log('  ✅ Added scan_schedule column');
  } else {
    console.log('  ✓ scan_schedule column already exists');
  }
} catch (e) {
  console.log('  ✗ Error:', e.message);
}

// Vérifier scan_type
try {
  const cols = db.pragma("table_info('scans')");
  const hasScanType = cols.some(c => c.name === 'scan_type');
  
  if (!hasScanType) {
    console.log('  Adding scan_type column to scans...');
    db.exec("ALTER TABLE scans ADD COLUMN scan_type TEXT DEFAULT 'manual'");
    console.log('  ✅ Added scan_type column');
  } else {
    console.log('  ✓ scan_type column already exists');
  }
} catch (e) {
  console.log('  ✗ Error:', e.message);
}

// Vérifier table user_alert_preferences
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_alert_preferences (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      preferences TEXT NOT NULL,
      updated_at INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
  console.log('  ✅ user_alert_preferences table ready');
} catch (e) {
  console.log('  ✗ Error:', e.message);
}

// Vérifier table alerts
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vulnerability_id INTEGER,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      sent_channels TEXT,
      created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
      FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
    )
  `);
  console.log('  ✅ alerts table ready');
} catch (e) {
  console.log('  ✗ Error:', e.message);
}

db.close();
console.log('\n✅ Database schema fixed!');
