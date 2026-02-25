const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const db = require('../config/database');
const { auth } = require('../middleware/auth');

// Get all alerts
router.get('/alerts', auth, (req, res) => {
  try {
    const alerts = db.prepare(`
      SELECT a.*, d.url as domain_url
      FROM alerts a
      LEFT JOIN domains d ON a.domain_id = d.id
      WHERE a.user_id = ?
      ORDER BY a.created_at DESC
      LIMIT 50
    `).all(req.user.userId);

    res.json({ alerts });
  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

// Mark alert as read
router.patch('/alerts/:id/read', auth, (req, res) => {
  try {
    const alert = db.prepare('SELECT * FROM alerts WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.userId);

    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    db.prepare('UPDATE alerts SET is_read = 1 WHERE id = ?')
      .run(req.params.id);

    res.json({ message: 'Alert marked as read' });
  } catch (error) {
    console.error('Mark alert read error:', error);
    res.status(500).json({ error: 'Failed to mark alert as read' });
  }
});

// Mark all alerts as read
router.patch('/alerts/read-all', auth, (req, res) => {
  try {
    db.prepare('UPDATE alerts SET is_read = 1 WHERE user_id = ?')
      .run(req.user.userId);

    res.json({ message: 'All alerts marked as read' });
  } catch (error) {
    console.error('Mark all alerts read error:', error);
    res.status(500).json({ error: 'Failed to mark alerts as read' });
  }
});

// Delete alert
router.delete('/alerts/:id', auth, (req, res) => {
  try {
    const alert = db.prepare('SELECT * FROM alerts WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.user.userId);

    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    db.prepare('DELETE FROM alerts WHERE id = ?').run(req.params.id);

    res.json({ message: 'Alert deleted' });
  } catch (error) {
    console.error('Delete alert error:', error);
    res.status(500).json({ error: 'Failed to delete alert' });
  }
});

module.exports = router;
