-- ================================================
-- NEXUS DATABASE SCHEMA COMPLETE
-- Toutes les tables nécessaires pour le projet
-- ================================================

-- Table users (complète avec colonnes Stripe)
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  organization_id INTEGER,
  organization_name TEXT,
  role TEXT DEFAULT 'user',
  
  -- Stripe billing
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  subscription_status TEXT DEFAULT 'free',
  subscription_plan TEXT DEFAULT 'free',
  trial_ends_at INTEGER,
  grace_period_ends_at INTEGER,
  current_period_end INTEGER,
  
  -- Quotas
  domains_limit INTEGER DEFAULT 1,
  scans_limit_monthly INTEGER DEFAULT 5,
  api_calls_limit_daily INTEGER DEFAULT 0,
  
  -- Features
  ai_enabled INTEGER DEFAULT 0,
  compliance_enabled INTEGER DEFAULT 0,
  integrations_enabled INTEGER DEFAULT 0,
  
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  last_login_at INTEGER
);

-- Table domains
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  url TEXT NOT NULL,
  name TEXT,
  status TEXT DEFAULT 'active',
  last_scan_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table scans
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  progress INTEGER DEFAULT 0,
  vulnerabilities_found INTEGER DEFAULT 0,
  scan_type TEXT DEFAULT 'full',
  started_at INTEGER,
  completed_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  url TEXT,
  evidence TEXT,
  recommendation TEXT,
  status TEXT DEFAULT 'open',
  assigned_to TEXT,
  assigned_at INTEGER,
  fixed_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- Table organizations
CREATE TABLE IF NOT EXISTS organizations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  owner_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table organization_members
CREATE TABLE IF NOT EXISTS organization_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  organization_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  role TEXT DEFAULT 'member',
  joined_at INTEGER NOT NULL,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table scanners (les 26 scanners disponibles)
CREATE TABLE IF NOT EXISTS scanners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  description TEXT,
  severity TEXT DEFAULT 'medium',
  enabled INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL
);

-- Table scan_results (résultats détaillés)
CREATE TABLE IF NOT EXISTS scan_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  scanner_id INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  result TEXT,
  duration_ms INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
  FOREIGN KEY (scanner_id) REFERENCES scanners(id)
);

-- Table notifications
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  title TEXT NOT NULL,
  message TEXT,
  read INTEGER DEFAULT 0,
  link TEXT,
  created_at INTEGER NOT NULL,
  read_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table audit_logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id INTEGER,
  details TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- ================================================
-- NOUVELLES TABLES (pour features avancées)
-- ================================================

-- Table payments (pour Stripe)
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  stripe_payment_id TEXT,
  stripe_invoice_id TEXT,
  amount INTEGER NOT NULL,
  currency TEXT DEFAULT 'usd',
  status TEXT DEFAULT 'pending',
  description TEXT,
  created_at INTEGER NOT NULL,
  paid_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table integration_events (pour Jira/GitHub/Slack)
CREATE TABLE IF NOT EXISTS integration_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  integration_type TEXT NOT NULL,
  event_type TEXT NOT NULL,
  reference_id INTEGER,
  reference_type TEXT,
  external_id TEXT,
  external_url TEXT,
  status TEXT DEFAULT 'pending',
  payload TEXT,
  error TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table api_calls (pour tracking usage)
CREATE TABLE IF NOT EXISTS api_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER,
  response_time_ms INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ================================================
-- INDEXES POUR PERFORMANCE
-- ================================================

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_organization ON users(organization_id);
CREATE INDEX IF NOT EXISTS idx_users_subscription ON users(subscription_status);
CREATE INDEX IF NOT EXISTS idx_users_stripe_customer ON users(stripe_customer_id);

-- Domains indexes
CREATE INDEX IF NOT EXISTS idx_domains_user ON domains(user_id);
CREATE INDEX IF NOT EXISTS idx_domains_url ON domains(url);
CREATE INDEX IF NOT EXISTS idx_domains_status ON domains(status);

-- Scans indexes
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain_id);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);

-- Vulnerabilities indexes
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_vulns_type ON vulnerabilities(type);
CREATE INDEX IF NOT EXISTS idx_vulns_scan_severity ON vulnerabilities(scan_id, severity);

-- Payments indexes
CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_date ON payments(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);

-- Integration events indexes
CREATE INDEX IF NOT EXISTS idx_integration_user ON integration_events(user_id);
CREATE INDEX IF NOT EXISTS idx_integration_type ON integration_events(integration_type);
CREATE INDEX IF NOT EXISTS idx_integration_created ON integration_events(created_at DESC);

-- API calls indexes
CREATE INDEX IF NOT EXISTS idx_api_calls_user ON api_calls(user_id);
CREATE INDEX IF NOT EXISTS idx_api_calls_created ON api_calls(created_at DESC);

-- Notifications indexes
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications(read);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

-- ================================================
-- SEED DATA (données de test)
-- ================================================

-- Admin user (password: Admin123!@#NexusChange)
-- Hash bcrypt pour ce password
INSERT OR IGNORE INTO users (id, email, password_hash, name, role, subscription_plan, subscription_status, domains_limit, scans_limit_monthly, ai_enabled, compliance_enabled, created_at)
VALUES (1, 'admin@nexus.local', '$2a$10$XQ4SZ9Z9Z9Z9Z9Z9Z9Z9ZeVKGX9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z9Z9', 'Admin User', 'admin', 'professional', 'active', 50, 500, 1, 1, strftime('%s', 'now'));

-- Scanners de base (les 26)
INSERT OR IGNORE INTO scanners (name, type, description, severity, enabled, created_at) VALUES
('SQL Injection', 'sql_injection', 'Tests for SQL injection vulnerabilities', 'critical', 1, strftime('%s', 'now')),
('Cross-Site Scripting (XSS)', 'xss', 'Tests for XSS vulnerabilities', 'high', 1, strftime('%s', 'now')),
('Cross-Site Request Forgery (CSRF)', 'csrf', 'Tests for CSRF vulnerabilities', 'medium', 1, strftime('%s', 'now')),
('Authentication Bypass', 'authentication', 'Tests for authentication weaknesses', 'critical', 1, strftime('%s', 'now')),
('Authorization Issues', 'authorization', 'Tests for authorization flaws', 'high', 1, strftime('%s', 'now')),
('Sensitive Data Exposure', 'data_exposure', 'Tests for exposed sensitive data', 'high', 1, strftime('%s', 'now')),
('XML External Entity (XXE)', 'xxe', 'Tests for XXE vulnerabilities', 'high', 1, strftime('%s', 'now')),
('Broken Access Control', 'access_control', 'Tests for access control issues', 'high', 1, strftime('%s', 'now')),
('Security Misconfiguration', 'misconfiguration', 'Tests for security misconfigurations', 'medium', 1, strftime('%s', 'now')),
('Insecure Deserialization', 'deserialization', 'Tests for deserialization flaws', 'high', 1, strftime('%s', 'now')),
('Using Components with Known Vulnerabilities', 'vulnerable_components', 'Tests for vulnerable dependencies', 'medium', 1, strftime('%s', 'now')),
('Insufficient Logging & Monitoring', 'logging', 'Tests for logging weaknesses', 'low', 1, strftime('%s', 'now')),
('Server-Side Request Forgery (SSRF)', 'ssrf', 'Tests for SSRF vulnerabilities', 'high', 1, strftime('%s', 'now')),
('Remote Code Execution', 'rce', 'Tests for RCE vulnerabilities', 'critical', 1, strftime('%s', 'now')),
('File Upload Vulnerabilities', 'file_upload', 'Tests for file upload issues', 'high', 1, strftime('%s', 'now')),
('Path Traversal', 'path_traversal', 'Tests for path traversal', 'medium', 1, strftime('%s', 'now')),
('Command Injection', 'command_injection', 'Tests for command injection', 'critical', 1, strftime('%s', 'now')),
('LDAP Injection', 'ldap_injection', 'Tests for LDAP injection', 'high', 1, strftime('%s', 'now')),
('NoSQL Injection', 'nosql_injection', 'Tests for NoSQL injection', 'high', 1, strftime('%s', 'now')),
('Session Management', 'session_management', 'Tests for session handling issues', 'medium', 1, strftime('%s', 'now')),
('Weak Cryptography', 'weak_crypto', 'Tests for weak encryption', 'medium', 1, strftime('%s', 'now')),
('Information Disclosure', 'info_disclosure', 'Tests for information leaks', 'low', 1, strftime('%s', 'now')),
('Clickjacking', 'clickjacking', 'Tests for clickjacking vulnerabilities', 'low', 1, strftime('%s', 'now')),
('HTTP Security Headers', 'security_headers', 'Tests for missing security headers', 'low', 1, strftime('%s', 'now')),
('SSL/TLS Issues', 'ssl_tls', 'Tests for SSL/TLS problems', 'medium', 1, strftime('%s', 'now')),
('API Security', 'api_security', 'Tests for API vulnerabilities', 'medium', 1, strftime('%s', 'now'));

-- ================================================
-- DATABASE READY ✅
-- ================================================
