const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const {auth} = require('../middleware/auth');
const exploitSimulator = require('../services/exploit-simulator');
const db = require('../config/database');

// Run purple team exercise
router.post('/exercise', auth, async (req, res) => {
  try {
    const {domain_id} = req.body;
    
    const domain = db.prepare('SELECT * FROM domains WHERE id = ? AND user_id = ?')
      .get(domain_id, req.user.id);
    
    if (!domain) {
      return res.status(404).json({error: 'Domain not found'});
    }

    const results = await exploitSimulator.runPurpleTeamExercise(domain_id);
    
    res.json(results);
  } catch (error) {
    console.error('Purple team error:', error);
    res.status(500).json({error: 'Failed to run purple team exercise'});
  }
});

// Get simulation history
router.get('/history/:domainId', auth, (req, res) => {
  try {
    const simulations = db.prepare(`
      SELECT * FROM purple_team_simulations
      WHERE domain_id = ?
      ORDER BY started_at DESC
      LIMIT 50
    `).all(req.params.domainId);
    
    res.json({simulations});
  } catch (error) {
    res.status(500).json({error: 'Failed to fetch history'});
  }
});

// Get attack scenario
router.post('/scenario', auth, async (req, res) => {
  try {
    const {domain_id} = req.body;
    
    const vulnerabilities = db.prepare(`
      SELECT * FROM vulnerabilities
      WHERE domain_id = ? AND status = 'open'
      ORDER BY cvss_score DESC
    `).all(domain_id);
    
    const scenario = await exploitSimulator.generateAttackScenario(vulnerabilities);
    
    res.json(scenario);
  } catch (error) {
    res.status(500).json({error: 'Failed to generate scenario'});
  }
});

module.exports = router;
