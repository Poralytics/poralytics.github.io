/**
 * DOMAINS ROUTES - Full CRUD with validation
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { auth } = require('../middleware/auth');
const { asyncHandler, logger } = require('../utils/error-handler');

const validateUrl = (url) => {
  try {
    const u = new URL(url);
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http/https');
    // Block private IPs
    const hostname = u.hostname;
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(hostname)) {
      throw new Error('Private IPs not allowed');
    }
    return u.href;
  } catch (e) {
    throw new Error(`Invalid URL: ${e.message}`);
  }
};

// List domains
router.get('/', auth, asyncHandler(async (req, res) => {
  const domains = db.prepare(`
    SELECT d.*, COUNT(s.id) as scan_count,
    MAX(s.completed_at) as last_scan
    FROM domains d LEFT JOIN scans s ON d.id = s.domain_id
    WHERE d.user_id = ? GROUP BY d.id ORDER BY d.created_at DESC
  `).all(req.user.userId);
  res.json({ domains, count: domains.length });
}));

// Get single domain
router.get('/:id', auth, asyncHandler(async (req, res) => {
  const domain = db.prepare('SELECT * FROM domains WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.userId);
  if (!domain) return res.status(404).json({ error: 'Domain not found' });

  const recentScans = db.prepare(`
    SELECT id, status, progress, total_vulns, security_score, started_at, completed_at
    FROM scans WHERE domain_id = ? ORDER BY started_at DESC LIMIT 5
  `).all(domain.id);

  res.json({ domain, recentScans });
}));

// Add domain
router.post('/', auth, asyncHandler(async (req, res) => {
  const { url, name } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });

  let cleanUrl;
  try { cleanUrl = validateUrl(url); }
  catch (e) { return res.status(400).json({ error: e.message }); }

  const existing = db.prepare('SELECT id FROM domains WHERE url = ? AND user_id = ?')
    .get(cleanUrl, req.user.userId);
  if (existing) return res.status(409).json({ error: 'Domain already registered', id: existing.id });

  // Check plan limits
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.userId);
  const limits = { free: 3, pro: 20, business: 100, enterprise: 9999 };
  const count = db.prepare('SELECT COUNT(*) as c FROM domains WHERE user_id = ?').get(req.user.userId);
  const limit = limits[user?.plan] || 3;
  if (count.c >= limit) {
    return res.status(403).json({ error: `Plan limit reached (${limit} domains). Upgrade to add more.` });
  }

  const result = db.prepare(`
    INSERT INTO domains (user_id, url, name, security_score, risk_level, created_at)
    VALUES (?, ?, ?, 0, 'unknown', ?)
  `).run(req.user.userId, cleanUrl, name || new URL(cleanUrl).hostname, Math.floor(Date.now() / 1000));

  logger.logInfo('Domain added', { userId: req.user.userId, url: cleanUrl });
  res.status(201).json({ success: true, id: result.lastInsertRowid, url: cleanUrl });
}));

// Update domain
router.put('/:id', auth, asyncHandler(async (req, res) => {
  const domain = db.prepare('SELECT * FROM domains WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.userId);
  if (!domain) return res.status(404).json({ error: 'Domain not found' });

  const { name } = req.body;
  if (name) db.prepare('UPDATE domains SET name = ? WHERE id = ?').run(name, domain.id);
  res.json({ success: true });
}));

// Delete domain
router.delete('/:id', auth, asyncHandler(async (req, res) => {
  const domain = db.prepare('SELECT * FROM domains WHERE id = ? AND user_id = ?')
    .get(req.params.id, req.user.userId);
  if (!domain) return res.status(404).json({ error: 'Domain not found' });

  // Cascade delete scans + vulns
  const scanIds = db.prepare('SELECT id FROM scans WHERE domain_id = ?').all(domain.id).map(s => s.id);
  if (scanIds.length > 0) {
    db.prepare(`DELETE FROM vulnerabilities WHERE scan_id IN (${scanIds.map(() => '?').join(',')})`).run(...scanIds);
    db.prepare('DELETE FROM scans WHERE domain_id = ?').run(domain.id);
  }
  db.prepare('DELETE FROM domains WHERE id = ?').run(domain.id);

  logger.logInfo('Domain deleted', { userId: req.user.userId, domainId: domain.id });
  res.json({ success: true });
}));

module.exports = router;
