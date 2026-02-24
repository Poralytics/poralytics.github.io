/**
 * AUTOMATION ROUTES
 * Scan scheduling and automation
 */
const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const scheduler = require('../services/scan-scheduler');

// Get scheduled scans
router.get('/scheduled', auth, asyncHandler(async (req, res) => {
  const scans = scheduler.getScheduledScans(req.user.userId);
  res.json({ scheduled: scans, count: scans.length });
}));

// Set scan schedule for a domain
router.post('/schedule/:domainId', auth, asyncHandler(async (req, res) => {
  const { schedule } = req.body; // 'hourly', 'daily', 'weekly', 'monthly', or null
  
  if (!['hourly', 'daily', 'weekly', 'monthly', null].includes(schedule)) {
    return res.status(400).json({ error: 'Invalid schedule' });
  }

  try {
    const result = scheduler.setSchedule(req.params.domainId, req.user.userId, schedule);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
}));

// Remove schedule
router.delete('/schedule/:domainId', auth, asyncHandler(async (req, res) => {
  scheduler.setSchedule(req.params.domainId, req.user.userId, null);
  res.json({ success: true, message: 'Schedule removed' });
}));

// Get automation status
router.get('/status', auth, asyncHandler(async (req, res) => {
  const user = require('../config/database').prepare('SELECT plan FROM users WHERE id = ?').get(req.user.userId);
  
  const features = {
    free: { automation: false, schedules: [] },
    pro: { automation: true, schedules: ['daily', 'weekly', 'monthly'] },
    business: { automation: true, schedules: ['hourly', 'daily', 'weekly', 'monthly'] },
    enterprise: { automation: true, schedules: ['hourly', 'daily', 'weekly', 'monthly'], customSchedules: true }
  };

  res.json({
    plan: user.plan,
    features: features[user.plan] || features.free,
    schedulerRunning: scheduler.running
  });
}));

module.exports = router;
