const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const {auth} = require('../middleware/auth');
const continuousMonitoring = require('../services/continuous-monitoring');
const db = require('../config/database');

// Start monitoring for a domain
router.post('/start', auth, async (req, res) => {
  try {
    const {domain_id, frequency} = req.body;
    
    const domain = db.prepare('SELECT * FROM domains WHERE id = ? AND user_id = ?')
      .get(domain_id, req.user.id);
    
    if (!domain) {
      return res.status(404).json({error: 'Domain not found'});
    }

    continuousMonitoring.startMonitoring(domain_id, frequency || 'daily');
    
    res.json({
      success: true,
      message: `Monitoring started for ${domain.url}`,
      frequency
    });
  } catch (error) {
    console.error('Start monitoring error:', error);
    res.status(500).json({error: 'Failed to start monitoring'});
  }
});

// Stop monitoring
router.post('/stop', auth, async (req, res) => {
  try {
    const {domain_id} = req.body;
    
    const stopped = continuousMonitoring.stopMonitoring(domain_id);
    
    if (stopped) {
      res.json({success: true, message: 'Monitoring stopped'});
    } else {
      res.status(404).json({error: 'No active monitoring found'});
    }
  } catch (error) {
    res.status(500).json({error: 'Failed to stop monitoring'});
  }
});

// Get monitoring status
router.get('/status/:domainId', auth, (req, res) => {
  try {
    const status = continuousMonitoring.getMonitoringStatus(req.params.domainId);
    res.json(status);
  } catch (error) {
    res.status(500).json({error: 'Failed to get status'});
  }
});

// Get alerts
router.get('/alerts', auth, async (req, res) => {
  try {
    const {domain_id, unread_only} = req.query;
    
    const alerts = await continuousMonitoring.getAlerts(
      domain_id, 
      unread_only === 'true'
    );
    
    res.json({alerts});
  } catch (error) {
    res.status(500).json({error: 'Failed to fetch alerts'});
  }
});

// Mark alert as read
router.patch('/alerts/:id/read', auth, (req, res) => {
  try {
    continuousMonitoring.markAlertRead(req.params.id);
    res.json({success: true});
  } catch (error) {
    res.status(500).json({error: 'Failed to mark alert as read'});
  }
});

module.exports = router;
