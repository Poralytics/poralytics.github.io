/**
 * AUTH ROUTES - Register, Login, Profile, Password
 */
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const db = require('../config/database');
const { auth, signToken } = require('../middleware/auth');
const { asyncHandler, logger } = require('../utils/error-handler');

const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validatePassword = (pw) => pw && pw.length >= 8;

// Register
router.post('/register', asyncHandler(async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !validateEmail(email)) return res.status(400).json({ error: 'Valid email required' });
  if (!validatePassword(password)) return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(400).json({ error: 'Email already registered' });

  const hash = await bcrypt.hash(password, 12);
  const result = db.prepare(`
    INSERT INTO users (email, password_hash, name, role, plan, created_at)
    VALUES (?, ?, ?, 'user', 'free', ?)
  `).run(email.toLowerCase(), hash, name || email.split('@')[0], Math.floor(Date.now() / 1000));

  const token = signToken({ userId: result.lastInsertRowid, email: email.toLowerCase(), role: 'user', plan: 'free' });
  logger.logInfo('User registered', { userId: result.lastInsertRowid, email: email.toLowerCase() });
  res.status(201).json({ success: true, token, user: { id: result.lastInsertRowid, email: email.toLowerCase(), name, role: 'user', plan: 'free' } });
}));

// Login
router.post('/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signToken({ userId: user.id, email: user.email, role: user.role, plan: user.plan });
  logger.logInfo('User login', { userId: user.id });
  res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name, role: user.role, plan: user.plan } });
}));

// Profile
router.get('/profile', auth, asyncHandler(async (req, res) => {
  const user = db.prepare('SELECT id, email, name, role, plan, created_at FROM users WHERE id = ?').get(req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const domains = db.prepare('SELECT COUNT(*) as c FROM domains WHERE user_id = ?').get(user.id);
  const scans = db.prepare('SELECT COUNT(*) as c FROM scans WHERE user_id = ?').get(user.id);
  res.json({ user: { ...user, domain_count: domains.c, scan_count: scans.c } });
}));

// Update profile
router.put('/profile', auth, asyncHandler(async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.user.userId);
  res.json({ success: true });
}));

// Change password
router.post('/change-password', auth, asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !validatePassword(newPassword)) {
    return res.status(400).json({ error: 'Current password and new password (8+ chars) required' });
  }
  const user = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.userId);
  const valid = await bcrypt.compare(currentPassword, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Current password incorrect' });
  const hash = await bcrypt.hash(newPassword, 12);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.userId);
  logger.logInfo('Password changed', { userId: req.user.userId });
  res.json({ success: true, message: 'Password updated' });
}));

module.exports = router;
