/**
 * MONITORING DASHBOARD ROUTES
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { auth } = require('../middleware/auth');
const { asyncHandler, breakerManager } = require('../utils/error-handler');

// System health
router.get('/health', asyncHandler(async (req, res) => {
  const wsServer = require('../services/real-websocket-server');
  res.json({
    status: 'OK',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    circuitBreakers: breakerManager.getAllStats(),
    websocket: wsServer.getStats(),
    timestamp: new Date()
  });
}));

// Scan queue status
router.get('/queue', auth, asyncHandler(async (req, res) => {
  const pending = db.prepare("SELECT COUNT(*) as count FROM scans WHERE status='pending'").get();
  const running = db.prepare("SELECT COUNT(*) as count FROM scans WHERE status='running'").get();
  const runningScans = db.prepare(`
    SELECT s.id, s.progress, d.url, s.started_at
    FROM scans s JOIN domains d ON s.domain_id=d.id WHERE s.status='running'
  `).all();
  res.json({ pending: pending.count, running: running.count, activeScans: runningScans });
}));

// Recent errors
router.get('/errors', auth, asyncHandler(async (req, res) => {
  const errors = db.prepare(`
    SELECT * FROM error_logs ORDER BY created_at DESC LIMIT 50
  `).all();
  res.json({ errors });
}));

// Active users (admin)
router.get('/stats', auth, asyncHandler(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const users = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const scansToday = db.prepare(`SELECT COUNT(*) as count FROM scans WHERE started_at >= ?`).get(Math.floor(Date.now()/1000) - 86400);
  const vulnsTotal = db.prepare('SELECT COUNT(*) as count FROM vulnerabilities').get();
  res.json({ users: users.count, scansToday: scansToday.count, vulnsTotal: vulnsTotal.count });
}));

module.exports = router;
