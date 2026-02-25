-- Security additions migration
-- Run after v5.0-complete.sql

-- Stripe idempotency table
CREATE TABLE IF NOT EXISTS stripe_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT UNIQUE NOT NULL,
  type TEXT NOT NULL,
  data TEXT,
  processed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_stripe_events_event_id ON stripe_events(event_id);
CREATE INDEX IF NOT EXISTS idx_stripe_events_processed ON stripe_events(processed_at);

-- Structured error logs
CREATE TABLE IF NOT EXISTS error_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL DEFAULT (datetime('now')),
  level TEXT NOT NULL CHECK(level IN ('error','warn','info','debug')),
  service TEXT NOT NULL DEFAULT 'nexus',
  message TEXT NOT NULL,
  stack TEXT,
  context TEXT,
  user_id INTEGER REFERENCES users(id),
  ip_address TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_error_logs_level ON error_logs(level);
CREATE INDEX IF NOT EXISTS idx_error_logs_created ON error_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_error_logs_service ON error_logs(service);

-- Circuit breaker tracking
CREATE TABLE IF NOT EXISTS circuit_breaker_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  breaker_name TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('CLOSED','OPEN','HALF_OPEN')),
  total_calls INTEGER DEFAULT 0,
  total_failures INTEGER DEFAULT 0,
  total_successes INTEGER DEFAULT 0,
  last_failure_at INTEGER,
  last_success_at INTEGER,
  opened_at INTEGER,
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_circuit_breakers_name ON circuit_breaker_stats(breaker_name);

-- Security events audit log
CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
  user_id INTEGER REFERENCES users(id),
  ip_address TEXT,
  user_agent TEXT,
  path TEXT,
  details TEXT,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);

-- Rate limit tracking (in-DB fallback when Redis unavailable)
CREATE TABLE IF NOT EXISTS rate_limit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip_address TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_ip ON rate_limit_log(ip_address, endpoint, timestamp);
