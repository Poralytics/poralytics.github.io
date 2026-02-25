/**
 * SCHEDULED SCANS ROUTES
 * Permet aux clients de programmer des scans automatiques
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const scheduler = require('../services/scan-scheduler');
const db = require('../config/database');

// Lister les scans programmés
router.get('/', auth, asyncHandler(async (req, res) => {
  const schedules = scheduler.listSchedules(req.user.userId);
  res.json({ schedules, count: schedules.length });
}));

// Créer un scan programmé
router.post('/', auth, asyncHandler(async (req, res) => {
  const { domain_id, frequency, time_of_day, day_of_week, day_of_month } = req.body;

  if (!domain_id || !frequency) {
    return res.status(400).json({ error: 'domain_id and frequency required' });
  }

  if (!['daily', 'weekly', 'monthly'].includes(frequency)) {
    return res.status(400).json({ error: 'frequency must be daily, weekly, or monthly' });
  }

  // Vérifier ownership du domain
  const domain = db.prepare('SELECT * FROM domains WHERE id = ? AND user_id = ?')
    .get(domain_id, req.user.userId);
  
  if (!domain) {
    return res.status(404).json({ error: 'Domain not found' });
  }

  // Vérifier limites de plan
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(req.user.userId);
  const planLimits = { free: 0, pro: 3, business: 10, enterprise: 999 };
  const limit = planLimits[user?.plan] || 0;

  if (limit === 0) {
    return res.status(403).json({ 
      error: 'Scheduled scans require Pro plan or higher',
      upgrade_url: '/pricing'
    });
  }

  const existing = db.prepare('SELECT COUNT(*) as c FROM scheduled_scans WHERE user_id = ?')
    .get(req.user.userId);

  if (existing.c >= limit) {
    return res.status(403).json({ 
      error: `Plan limit reached (${limit} scheduled scans). Upgrade for more.`,
      current: existing.c,
      limit
    });
  }

  const scheduleId = scheduler.createSchedule(domain_id, req.user.userId, frequency, {
    time_of_day,
    day_of_week: day_of_week || 1,
    day_of_month: day_of_month || 1
  });

  res.status(201).json({ 
    success: true, 
    id: scheduleId,
    message: `Scheduled ${frequency} scan for ${domain.url}`
  });
}));

// Activer/désactiver
router.patch('/:id/toggle', auth, asyncHandler(async (req, res) => {
  const { enabled } = req.body;
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'enabled must be boolean' });
  }

  scheduler.toggleSchedule(parseInt(req.params.id), req.user.userId, enabled);
  res.json({ success: true, enabled });
}));

// Supprimer
router.delete('/:id', auth, asyncHandler(async (req, res) => {
  const result = scheduler.deleteSchedule(parseInt(req.params.id), req.user.userId);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Schedule not found' });
  }
  res.json({ success: true });
}));

module.exports = router;
