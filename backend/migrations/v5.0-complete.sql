-- ================================================================
-- NEXUS ULTIMATE PRO - COMPLETE DATABASE MIGRATIONS
-- Ajout de toutes les tables manquantes pour v5.0
-- ================================================================

-- ========== MARKETPLACE TABLES ==========

CREATE TABLE IF NOT EXISTS marketplace_scanners (
  id TEXT PRIMARY KEY,
  developer_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '1.0.0',
  code TEXT NOT NULL,
  entrypoint TEXT DEFAULT 'scan',
  dependencies TEXT DEFAULT '[]',
  pricing_tier TEXT DEFAULT 'free',
  price REAL DEFAULT 0,
  tags TEXT DEFAULT '[]',
  icon_url TEXT,
  screenshots TEXT DEFAULT '[]',
  downloads INTEGER DEFAULT 0,
  rating REAL DEFAULT 0,
  reviews_count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'pending_review',
  reviewed_by INTEGER,
  reviewed_at INTEGER,
  review_feedback TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (developer_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_installed_scanners (
  user_id INTEGER NOT NULL,
  scanner_id TEXT NOT NULL,
  installed_at INTEGER NOT NULL,
  auto_update INTEGER DEFAULT 1,
  PRIMARY KEY (user_id, scanner_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (scanner_id) REFERENCES marketplace_scanners(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scanner_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scanner_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
  review TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (scanner_id) REFERENCES marketplace_scanners(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(scanner_id, user_id)
);

CREATE TABLE IF NOT EXISTS scanner_usage_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  scanner_id TEXT NOT NULL,
  executed_at INTEGER NOT NULL,
  duration_ms INTEGER,
  success INTEGER DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (scanner_id) REFERENCES marketplace_scanners(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS developer_revenue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  developer_id INTEGER NOT NULL,
  scanner_id TEXT NOT NULL,
  amount REAL NOT NULL,
  transaction_type TEXT DEFAULT 'sale',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (developer_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (scanner_id) REFERENCES marketplace_scanners(id) ON DELETE CASCADE
);

-- ========== WHITE LABEL TABLES ==========

CREATE TABLE IF NOT EXISTS white_label_accounts (
  id TEXT PRIMARY KEY,
  reseller_id INTEGER NOT NULL,
  company_name TEXT NOT NULL,
  logo_url TEXT,
  primary_color TEXT DEFAULT '#667eea',
  secondary_color TEXT DEFAULT '#764ba2',
  custom_domain TEXT,
  support_email TEXT,
  commission_rate REAL DEFAULT 0.30,
  max_clients INTEGER DEFAULT 100,
  hide_powered_by INTEGER DEFAULT 0,
  dns_config TEXT,
  ssl_status TEXT DEFAULT 'pending',
  status TEXT DEFAULT 'active',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (reseller_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS white_label_clients (
  id TEXT PRIMARY KEY,
  white_label_id TEXT NOT NULL,
  company_name TEXT NOT NULL,
  contact_email TEXT NOT NULL,
  contact_name TEXT,
  plan_tier TEXT DEFAULT 'pro',
  status TEXT DEFAULT 'active',
  last_scan_at INTEGER,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (white_label_id) REFERENCES white_label_accounts(id) ON DELETE CASCADE
);

-- ========== COMPLIANCE TABLES ==========

CREATE TABLE IF NOT EXISTS compliance_monitoring (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  framework_id TEXT NOT NULL,
  status TEXT DEFAULT 'active',
  next_check INTEGER,
  started_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compliance_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  framework_id TEXT NOT NULL,
  score INTEGER NOT NULL CHECK (score >= 0 AND score <= 100),
  results TEXT NOT NULL,
  checked_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compliance_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  framework_id TEXT NOT NULL,
  type TEXT NOT NULL,
  description TEXT,
  data TEXT NOT NULL,
  file_path TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS compliance_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  framework_id TEXT NOT NULL,
  score INTEGER NOT NULL,
  report_data TEXT NOT NULL,
  pdf_path TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ========== THREAT INTELLIGENCE TABLES ==========

CREATE TABLE IF NOT EXISTS threat_intelligence (
  id TEXT PRIMARY KEY,
  submitted_by INTEGER NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  iocs TEXT DEFAULT '[]',
  attack_vector TEXT,
  attack_pattern TEXT,
  exploit_used TEXT,
  source_ip TEXT,
  target_url TEXT,
  payload TEXT,
  user_agent TEXT,
  confidence TEXT DEFAULT 'medium',
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  occurrence_count INTEGER DEFAULT 1,
  upvotes INTEGER DEFAULT 0,
  downvotes INTEGER DEFAULT 0,
  verified INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (submitted_by) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_votes (
  user_id INTEGER NOT NULL,
  threat_id TEXT NOT NULL,
  vote TEXT NOT NULL CHECK (vote IN ('up', 'down')),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, threat_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (threat_id) REFERENCES threat_intelligence(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threat_blocking_rules (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  enabled INTEGER DEFAULT 1,
  block_malicious INTEGER DEFAULT 1,
  block_suspicious INTEGER DEFAULT 0,
  min_confidence TEXT DEFAULT 'high',
  action_type TEXT DEFAULT 'block',
  notification INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ========== GAMIFICATION TABLES ==========

CREATE TABLE IF NOT EXISTS gamification_points_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  points INTEGER NOT NULL,
  multiplier REAL DEFAULT 1.0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_achievements (
  user_id INTEGER NOT NULL,
  achievement_id TEXT NOT NULL,
  unlocked_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, achievement_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS challenges (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  type TEXT NOT NULL,
  goal INTEGER NOT NULL,
  reward_points INTEGER NOT NULL,
  start_date INTEGER NOT NULL,
  end_date INTEGER NOT NULL,
  active INTEGER DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS challenge_participants (
  user_id INTEGER NOT NULL,
  challenge_id TEXT NOT NULL,
  progress INTEGER DEFAULT 0,
  completed INTEGER DEFAULT 0,
  joined_at INTEGER NOT NULL,
  completed_at INTEGER,
  updated_at INTEGER,
  PRIMARY KEY (user_id, challenge_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (challenge_id) REFERENCES challenges(id) ON DELETE CASCADE
);

-- ========== AI ASSISTANT TABLES ==========

CREATE TABLE IF NOT EXISTS ai_conversations (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  messages TEXT NOT NULL,
  context TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_usage_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  conversation_id TEXT,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  total_tokens INTEGER,
  cost REAL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ========== SUBSCRIPTION & BILLING TABLES ==========

CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  plan_id TEXT NOT NULL,
  stripe_subscription_id TEXT UNIQUE,
  stripe_customer_id TEXT,
  status TEXT NOT NULL,
  current_period_start INTEGER,
  current_period_end INTEGER,
  trial_end INTEGER,
  cancel_at_period_end INTEGER DEFAULT 0,
  canceled_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS usage_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  metric TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  period_start INTEGER NOT NULL,
  period_end INTEGER NOT NULL,
  timestamp INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS invoices (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  stripe_invoice_id TEXT UNIQUE,
  amount INTEGER NOT NULL,
  currency TEXT DEFAULT 'usd',
  status TEXT NOT NULL,
  pdf_url TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ========== NOTIFICATION TABLES ==========

CREATE TABLE IF NOT EXISTS notification_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,
  content TEXT NOT NULL,
  read INTEGER DEFAULT 0,
  read_at INTEGER,
  priority TEXT DEFAULT 'normal',
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  delivered INTEGER DEFAULT 0,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  endpoint TEXT NOT NULL,
  keys TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ========== AUDIT & LOGGING TABLES ==========

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  resource TEXT,
  resource_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  changes TEXT,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- ========== API MANAGEMENT TABLES ==========

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  permissions TEXT DEFAULT '[]',
  rate_limit INTEGER DEFAULT 1000,
  last_used INTEGER,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked INTEGER DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  api_key_id TEXT,
  endpoint TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER,
  response_time_ms INTEGER,
  ip_address TEXT,
  timestamp INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
);

-- ========== PERFORMANCE INDEXES ==========

-- Marketplace indexes
CREATE INDEX IF NOT EXISTS idx_marketplace_status ON marketplace_scanners(status);
CREATE INDEX IF NOT EXISTS idx_marketplace_category ON marketplace_scanners(category);
CREATE INDEX IF NOT EXISTS idx_marketplace_developer ON marketplace_scanners(developer_id);
CREATE INDEX IF NOT EXISTS idx_scanner_reviews_scanner ON scanner_reviews(scanner_id);
CREATE INDEX IF NOT EXISTS idx_scanner_reviews_rating ON scanner_reviews(rating);

-- White-label indexes
CREATE INDEX IF NOT EXISTS idx_white_label_reseller ON white_label_accounts(reseller_id);
CREATE INDEX IF NOT EXISTS idx_white_label_clients_account ON white_label_clients(white_label_id);

-- Compliance indexes
CREATE INDEX IF NOT EXISTS idx_compliance_user ON compliance_monitoring(user_id);
CREATE INDEX IF NOT EXISTS idx_compliance_framework ON compliance_monitoring(framework_id);
CREATE INDEX IF NOT EXISTS idx_compliance_results_user ON compliance_results(user_id);

-- Threat intel indexes
CREATE INDEX IF NOT EXISTS idx_threat_category ON threat_intelligence(category);
CREATE INDEX IF NOT EXISTS idx_threat_severity ON threat_intelligence(severity);
CREATE INDEX IF NOT EXISTS idx_threat_verified ON threat_intelligence(verified);
CREATE INDEX IF NOT EXISTS idx_threat_last_seen ON threat_intelligence(last_seen);

-- Gamification indexes
CREATE INDEX IF NOT EXISTS idx_points_user ON gamification_points_log(user_id);
CREATE INDEX IF NOT EXISTS idx_points_created ON gamification_points_log(created_at);
CREATE INDEX IF NOT EXISTS idx_achievements_user ON user_achievements(user_id);
CREATE INDEX IF NOT EXISTS idx_challenges_active ON challenges(active, end_date);

-- AI indexes
CREATE INDEX IF NOT EXISTS idx_ai_conv_user ON ai_conversations(user_id);
CREATE INDEX IF NOT EXISTS idx_ai_usage_user ON ai_usage_log(user_id);

-- Subscription indexes
CREATE INDEX IF NOT EXISTS idx_sub_user ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_sub_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_records(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_metric ON usage_records(metric);

-- Notification indexes
CREATE INDEX IF NOT EXISTS idx_notif_user ON notification_log(user_id);
CREATE INDEX IF NOT EXISTS idx_notif_read ON notification_log(read);
CREATE INDEX IF NOT EXISTS idx_notif_priority ON notification_log(priority);

-- Audit indexes
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

-- API indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_logs_user ON api_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_api_logs_timestamp ON api_logs(timestamp);

-- ========== ALTER EXISTING USERS TABLE ==========

-- Ajout des colonnes gamification au users table si elles n'existent pas
-- Note: SQLite ne supporte pas ALTER TABLE ADD COLUMN IF NOT EXISTS
-- Ces colonnes doivent être ajoutées si elles n'existent pas déjà

-- ALTER TABLE users ADD COLUMN gamification_points INTEGER DEFAULT 0;
-- ALTER TABLE users ADD COLUMN gamification_level INTEGER DEFAULT 1;
-- ALTER TABLE users ADD COLUMN gamification_updated_at INTEGER;
-- ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;
-- ALTER TABLE users ADD COLUMN subscription_tier TEXT DEFAULT 'free';
-- ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0;
-- ALTER TABLE users ADD COLUMN mfa_secret TEXT;
-- ALTER TABLE users ADD COLUMN company_name TEXT;
-- ALTER TABLE users ADD COLUMN industry TEXT;
-- ALTER TABLE users ADD COLUMN team_id INTEGER;

-- ================================================================
-- Migration Complete
-- Total New Tables: 30+
-- Total New Indexes: 25+
-- ================================================================
-- ================================================================
-- NEXUS SECURITY CORRECTIONS - DATABASE MIGRATIONS
-- Ajout des tables pour idempotence et logging
-- ================================================================

-- Table pour idempotence des webhooks Stripe
CREATE TABLE IF NOT EXISTS stripe_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  data TEXT NOT NULL,
  processed_at INTEGER NOT NULL,
  created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_stripe_events_event_id ON stripe_events(event_id);
CREATE INDEX IF NOT EXISTS idx_stripe_events_type ON stripe_events(type);
CREATE INDEX IF NOT EXISTS idx_stripe_events_processed_at ON stripe_events(processed_at);

-- Table pour error logging (si besoin de persister)
CREATE TABLE IF NOT EXISTS error_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  level TEXT NOT NULL,
  service TEXT NOT NULL,
  message TEXT NOT NULL,
  stack TEXT,
  context TEXT,
  user_id INTEGER,
  ip_address TEXT,
  created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_error_logs_timestamp ON error_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_error_logs_level ON error_logs(level);
CREATE INDEX IF NOT EXISTS idx_error_logs_user_id ON error_logs(user_id);

-- Table pour circuit breaker stats (optionnel - pour monitoring)
CREATE TABLE IF NOT EXISTS circuit_breaker_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  breaker_name TEXT NOT NULL,
  state TEXT NOT NULL,
  total_calls INTEGER DEFAULT 0,
  success_calls INTEGER DEFAULT 0,
  failure_calls INTEGER DEFAULT 0,
  open_count INTEGER DEFAULT 0,
  last_failure INTEGER,
  last_success INTEGER,
  recorded_at INTEGER NOT NULL,
  created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_breaker_stats_name ON circuit_breaker_stats(breaker_name);
CREATE INDEX IF NOT EXISTS idx_breaker_stats_recorded ON circuit_breaker_stats(recorded_at);

-- Nettoyer les anciens logs (optionnel - à exécuter périodiquement)
-- DELETE FROM error_logs WHERE created_at < strftime('%s', 'now') - (30 * 86400); -- 30 jours
-- DELETE FROM stripe_events WHERE created_at < strftime('%s', 'now') - (90 * 86400); -- 90 jours

-- ================================================================
-- FIN DES MIGRATIONS
-- ================================================================
