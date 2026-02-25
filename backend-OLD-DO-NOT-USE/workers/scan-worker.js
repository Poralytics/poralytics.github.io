/**
 * SCAN WORKER - Connected to CompleteScanOrchestrator
 * Processes scan jobs from queue using parallel orchestrator
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });
const db = require('../config/database');
const orchestrator = require('../services/complete-scan-orchestrator');
const { logger } = require('../utils/error-handler');

const POLL_INTERVAL = 3000;
const MAX_CONCURRENT = 3;
let activeScans = 0;

logger.logInfo('Scan worker started', { pid: process.pid, maxConcurrent: MAX_CONCURRENT });

orchestrator.on('progress', ({ scanId, progress, phase }) => {
  try {
    db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(progress, scanId);
    logger.logInfo('Scan progress', { scanId, progress, phase });
  } catch (e) {}
});

orchestrator.on('completed', ({ scanId, stats, securityScore, duration }) => {
  logger.logInfo('Scan completed', { scanId, total: stats.total, securityScore, duration });
  activeScans = Math.max(0, activeScans - 1);
});

orchestrator.on('failed', ({ scanId, error }) => {
  logger.logError(new Error(error), { context: 'Scan failed in worker', scanId });
  activeScans = Math.max(0, activeScans - 1);
});

async function processNextScan() {
  if (activeScans >= MAX_CONCURRENT) return;

  try {
    const pending = db.prepare(`
      SELECT s.id, s.domain_id, s.user_id, d.url
      FROM scans s
      JOIN domains d ON s.domain_id = d.id
      WHERE s.status = 'pending'
      ORDER BY s.started_at ASC
      LIMIT 1
    `).get();

    if (!pending) return;

    activeScans++;
    logger.logInfo('Worker picking up scan', { scanId: pending.id, url: pending.url });

    // Run async - do not await, worker picks up next
    orchestrator.startScan(pending.id, pending.domain_id, pending.user_id, pending.url)
      .catch(err => {
        logger.logError(err, { context: 'Worker scan error', scanId: pending.id });
        activeScans = Math.max(0, activeScans - 1);
      });

  } catch (err) {
    logger.logError(err, { context: 'processNextScan' });
  }
}

// Main poll loop
setInterval(processNextScan, POLL_INTERVAL);

// Cleanup stuck scans on startup (running for > 30 min)
try {
  const stuck = db.prepare(`
    UPDATE scans SET status = 'failed', error_message = 'Timed out - restarted worker'
    WHERE status = 'running' AND started_at < ?
  `).run(Math.floor(Date.now() / 1000) - 1800);
  if (stuck.changes > 0) logger.logWarning('Cleaned up stuck scans', { count: stuck.changes });
} catch (e) {}

process.on('SIGTERM', () => {
  logger.logInfo('Worker SIGTERM received, stopping gracefully');
  process.exit(0);
});

process.on('uncaughtException', (err) => {
  logger.logError(err, { context: 'Uncaught exception in worker' });
});
