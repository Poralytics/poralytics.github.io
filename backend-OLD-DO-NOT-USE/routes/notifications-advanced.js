const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const AdvancedNotifications = require('../services/advanced-notifications');

/**
 * GET /api/notifications-advanced/preferences
 * Get user notification preferences
 */
router.get('/preferences', auth, async (req, res) => {
  try {
    const preferences = await AdvancedNotifications.getUserPreferences(req.user.id);

    res.json({
      success: true,
      preferences,
      availableChannels: Object.keys(AdvancedNotifications.channels).filter(
        c => AdvancedNotifications.channels[c]
      )
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * PUT /api/notifications-advanced/preferences
 * Update notification preferences
 */
router.put('/preferences', auth, async (req, res) => {
  try {
    const result = await AdvancedNotifications.updatePreferences(
      req.user.id,
      req.body
    );

    res.json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/notifications-advanced/stats
 * Get notification statistics
 */
router.get('/stats', auth, async (req, res) => {
  try {
    const stats = AdvancedNotifications.getStats();

    res.json({
      success: true,
      stats
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/notifications-advanced/test
 * Send test notification
 */
router.post('/test', auth, async (req, res) => {
  try {
    const { channel } = req.body;

    const result = await AdvancedNotifications.notify(req.user.id, {
      title: 'Test Notification',
      message: 'This is a test notification from NEXUS',
      type: 'info',
      priority: 'normal',
      channels: channel ? [channel] : ['web']
    });

    res.json({
      success: true,
      result
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
