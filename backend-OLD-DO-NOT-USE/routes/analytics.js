/**
 * ANALYTICS ROUTES - Real data from DB
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');

// Overview
router.get('/overview', auth, asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  const domains = db.prepare('SELECT COUNT(*) as count FROM domains WHERE user_id = ?').get(userId);
  const scans = db.prepare('SELECT COUNT(*) as count FROM scans WHERE user_id = ?').get(userId);
  const completed = db.prepare("SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND status='completed'").get(userId);
  const vulns = db.prepare(`
    SELECT SUM(total_vulns) as total, SUM(critical_count) as critical, SUM(high_count) as high,
           SUM(medium_count) as medium, SUM(low_count) as low
    FROM scans WHERE user_id = ?
  `).get(userId);
  const avgScore = db.prepare('SELECT AVG(security_score) as avg FROM domains WHERE user_id = ? AND security_score > 0').get(userId);

  res.json({
    domains: domains.count,
    scans: scans.count,
    completed_scans: completed.count,
    total_vulnerabilities: vulns.total || 0,
    critical: vulns.critical || 0,
    high: vulns.high || 0,
    medium: vulns.medium || 0,
    low: vulns.low || 0,
    average_security_score: Math.round(avgScore.avg || 0)
  });
}));

// Vulnerability trends (last 30 days)
router.get('/trends', auth, asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  const days = parseInt(req.query.days) || 30;
  const since = Math.floor(Date.now() / 1000) - (days * 86400);

  const trends = db.prepare(`
    SELECT date(s.completed_at, 'unixepoch') as date,
           SUM(s.critical_count) as critical, SUM(s.high_count) as high,
           SUM(s.medium_count) as medium, SUM(s.low_count) as low,
           COUNT(*) as scans
    FROM scans s WHERE s.user_id = ? AND s.completed_at >= ? AND s.status='completed'
    GROUP BY date ORDER BY date ASC
  `).all(userId, since);

  res.json({ trends, days });
}));

// Top vulnerabilities
router.get('/top-vulnerabilities', auth, asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);

  const topVulns = db.prepare(`
    SELECT v.category, v.severity, COUNT(*) as count, AVG(v.cvss_score) as avg_cvss
    FROM vulnerabilities v
    JOIN scans s ON v.scan_id = s.id
    WHERE s.user_id = ?
    GROUP BY v.category, v.severity
    ORDER BY count DESC, avg_cvss DESC
    LIMIT ?
  `).all(userId, limit);

  res.json({ vulnerabilities: topVulns });
}));

// Domain scores
router.get('/domain-scores', auth, asyncHandler(async (req, res) => {
  const domains = db.prepare(`
    SELECT id, url, name, security_score, risk_level, last_scan_at
    FROM domains WHERE user_id = ? ORDER BY security_score ASC LIMIT 20
  `).all(req.user.userId);
  res.json({ domains });
}));

module.exports = router;
