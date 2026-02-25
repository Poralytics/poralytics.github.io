const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, '..', 'nexus-ultimate.db');
const db = new Database(dbPath);

// Optimisations performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('cache_size = -64000'); // 64MB cache
db.pragma('temp_store = memory');
db.pragma('mmap_size = 30000000000');
db.pragma('page_size = 4096');

// Création schéma complet
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT,
    company TEXT,
    role TEXT DEFAULT 'user',
    api_key TEXT UNIQUE,
    tier TEXT DEFAULT 'professional',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    settings TEXT DEFAULT '{}'
  );

  CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    name TEXT,
    industry TEXT,
    annual_revenue INTEGER DEFAULT 10000000,
    employee_count INTEGER DEFAULT 50,
    revenue_per_hour INTEGER DEFAULT 15000,
    data_sensitivity TEXT DEFAULT 'high',
    compliance_required TEXT DEFAULT '["GDPR"]',
    status TEXT DEFAULT 'active',
    last_scan_at DATETIME,
    security_score INTEGER DEFAULT 0,
    risk_level TEXT DEFAULT 'unknown',
    risk_exposure_eur INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    scan_type TEXT DEFAULT 'comprehensive',
    status TEXT DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    phase TEXT DEFAULT 'initializing',
    security_score INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    vulnerabilities_fixed INTEGER DEFAULT 0,
    risk_exposure_eur INTEGER DEFAULT 0,
    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    duration_seconds INTEGER,
    scan_data TEXT DEFAULT '{}',
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    domain_id INTEGER NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    subcategory TEXT,
    title TEXT NOT NULL,
    description TEXT,
    technical_details TEXT,
    affected_component TEXT,
    affected_url TEXT,
    cve_id TEXT,
    cvss_score REAL DEFAULT 0,
    cvss_vector TEXT,
    exploit_available INTEGER DEFAULT 0,
    exploit_public INTEGER DEFAULT 0,
    patch_available INTEGER DEFAULT 0,
    business_impact_eur INTEGER DEFAULT 0,
    exploit_probability REAL DEFAULT 0,
    expected_loss_eur INTEGER DEFAULT 0,
    remediation_text TEXT,
    remediation_effort_hours REAL DEFAULT 0,
    remediation_cost_eur INTEGER DEFAULT 0,
    auto_fixable INTEGER DEFAULT 0,
    auto_fixed INTEGER DEFAULT 0,
    fix_validated INTEGER DEFAULT 0,
    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'open',
    priority_score INTEGER DEFAULT 0,
    mitre_attack TEXT,
    owasp_category TEXT,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS attack_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    attack_type TEXT NOT NULL,
    attack_vector TEXT,
    attack_technique TEXT,
    mitre_id TEXT,
    probability REAL NOT NULL,
    confidence REAL DEFAULT 0.7,
    timeframe_hours INTEGER NOT NULL,
    predicted_impact_eur INTEGER DEFAULT 0,
    indicators TEXT,
    prevention_steps TEXT,
    detection_rules TEXT,
    predicted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    status TEXT DEFAULT 'active',
    accuracy_feedback REAL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS remediation_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    action_type TEXT NOT NULL,
    action_level TEXT DEFAULT 'automated',
    action_description TEXT,
    action_script TEXT,
    status TEXT DEFAULT 'pending',
    executed_at DATETIME,
    execution_time_ms INTEGER,
    result_success INTEGER DEFAULT 0,
    result_message TEXT,
    rollback_available INTEGER DEFAULT 1,
    rollback_script TEXT,
    validation_checks TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS threat_intelligence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    intel_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    iocs TEXT,
    ttps TEXT,
    affected_systems TEXT,
    cve_refs TEXT,
    published_date DATETIME,
    expires_date DATETIME,
    relevance_score REAL DEFAULT 0,
    matched_domains TEXT,
    status TEXT DEFAULT 'active',
    ingested_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS attack_surface_map (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    node_id TEXT UNIQUE NOT NULL,
    node_type TEXT NOT NULL,
    node_name TEXT NOT NULL,
    node_description TEXT,
    ip_address TEXT,
    port INTEGER,
    protocol TEXT,
    exposure_level TEXT DEFAULT 'internal',
    criticality INTEGER DEFAULT 5,
    connections TEXT DEFAULT '[]',
    vulnerabilities TEXT DEFAULT '[]',
    position_x REAL,
    position_y REAL,
    position_z REAL,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    security_score INTEGER,
    risk_exposure_eur INTEGER,
    vulnerabilities_total INTEGER DEFAULT 0,
    vulnerabilities_critical INTEGER DEFAULT 0,
    vulnerabilities_high INTEGER DEFAULT 0,
    vulnerabilities_medium INTEGER DEFAULT 0,
    vulnerabilities_low INTEGER DEFAULT 0,
    vulnerabilities_fixed INTEGER DEFAULT 0,
    scan_duration_seconds INTEGER,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain_id INTEGER,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT,
    action_required TEXT,
    action_url TEXT,
    impact_eur INTEGER,
    is_read INTEGER DEFAULT 0,
    is_resolved INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT DEFAULT '{}',
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS compliance_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    framework TEXT NOT NULL,
    overall_score INTEGER DEFAULT 0,
    controls_total INTEGER DEFAULT 0,
    controls_passed INTEGER DEFAULT 0,
    controls_failed INTEGER DEFAULT 0,
    gaps TEXT,
    evidence TEXT,
    last_assessed DATETIME DEFAULT CURRENT_TIMESTAMP,
    next_assessment DATETIME,
    certification_status TEXT DEFAULT 'not_certified',
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS ai_learning_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    domain_id INTEGER,
    vulnerability_id INTEGER,
    prediction_id INTEGER,
    actual_outcome TEXT,
    predicted_outcome TEXT,
    accuracy REAL,
    features TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS purple_team_simulations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id INTEGER NOT NULL,
    simulation_type TEXT NOT NULL,
    mitre_technique TEXT,
    attack_success INTEGER DEFAULT 0,
    detection_success INTEGER DEFAULT 0,
    response_time_seconds INTEGER,
    gaps_identified TEXT,
    recommendations TEXT,
    executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    domain_id INTEGER,
    report_type TEXT DEFAULT 'executive',
    title TEXT NOT NULL,
    format TEXT DEFAULT 'pdf',
    file_path TEXT,
    file_size INTEGER,
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    download_count INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS websocket_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_id TEXT UNIQUE NOT NULL,
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Indexes pour performance
  CREATE INDEX IF NOT EXISTS idx_domains_user ON domains(user_id);
  CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain_id);
  CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
  CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
  CREATE INDEX IF NOT EXISTS idx_vulns_domain ON vulnerabilities(domain_id);
  CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
  CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
  CREATE INDEX IF NOT EXISTS idx_predictions_domain ON attack_predictions(domain_id);
  CREATE INDEX IF NOT EXISTS idx_predictions_status ON attack_predictions(status);
  CREATE INDEX IF NOT EXISTS idx_alerts_user ON alerts(user_id);
  CREATE INDEX IF NOT EXISTS idx_alerts_read ON alerts(is_read);
  CREATE INDEX IF NOT EXISTS idx_history_domain ON scan_history(domain_id);
  CREATE INDEX IF NOT EXISTS idx_intel_status ON threat_intelligence(status);
  CREATE INDEX IF NOT EXISTS idx_surface_domain ON attack_surface_map(domain_id);
  CREATE INDEX IF NOT EXISTS idx_compliance_domain ON compliance_status(domain_id);
`);

console.log('✅ NEXUS Ultimate Database: 15 Tables | 15 Indexes | Production Ready');

module.exports = db;
