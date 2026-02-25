const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const {auth} = require('../middleware/auth');
const threatIntel = require('../services/threat-intelligence-feed');

// Get active threats
router.get('/active', auth, async (req, res) => {
  try {
    const filters = {
      severity: req.query.severity,
      since: req.query.since,
      limit: parseInt(req.query.limit) || 50
    };
    
    const threats = await threatIntel.getActiveThreats(filters);
    res.json({threats});
  } catch (error) {
    res.status(500).json({error: 'Failed to fetch threats'});
  }
});

// Get threat intel stats
router.get('/stats', auth, async (req, res) => {
  try {
    const stats = await threatIntel.getStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({error: 'Failed to get stats'});
  }
});

// Correlate threats with domain
router.get('/correlate/:domainId', auth, async (req, res) => {
  try {
    const correlations = await threatIntel.correlateWithScans(req.params.domainId);
    res.json({correlations});
  } catch (error) {
    res.status(500).json({error: 'Failed to correlate threats'});
  }
});

// Force update feeds
router.post('/update', auth, async (req, res) => {
  try {
    await threatIntel.updateFeeds();
    res.json({success: true, message: 'Threat intelligence updated'});
  } catch (error) {
    res.status(500).json({error: 'Failed to update feeds'});
  }
});

module.exports = router;
