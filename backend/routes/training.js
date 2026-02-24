const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const AttackSimulation = require('../services/attack-simulation-training');

/**
 * GET /api/training/scenarios
 * List available training scenarios
 */
router.get('/scenarios', auth, async (req, res) => {
  try {
    const scenarios = AttackSimulation.scenarios.map(s => ({
      id: s.id,
      name: s.name,
      description: s.description,
      difficulty: s.difficulty,
      estimatedDuration: s.estimatedDuration,
      objectives: s.objectives
    }));

    res.json({
      success: true,
      scenarios
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/training/simulate/:scenarioId
 * Start attack simulation
 */
router.post('/simulate/:scenarioId', auth, async (req, res) => {
  try {
    const { scenarioId } = req.params;

    const result = await AttackSimulation.startSimulation(
      req.user.id,
      scenarioId
    );

    res.json({
      success: true,
      simulation: result
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/training/simulation/:simulationId/action
 * Perform defense action during simulation
 */
router.post('/simulation/:simulationId/action', auth, async (req, res) => {
  try {
    const { simulationId } = req.params;
    const action = req.body;

    const result = await AttackSimulation.handleDefenseAction(
      simulationId,
      action
    );

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

/**
 * GET /api/training/readiness
 * Get user's readiness score
 */
router.get('/readiness', auth, async (req, res) => {
  try {
    const readiness = await AttackSimulation.getUserReadinessScore(req.user.id);

    res.json({
      success: true,
      readiness
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/training/team-readiness
 * Get team readiness score
 */
router.get('/team-readiness', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    const user = db.prepare('SELECT team_id FROM users WHERE id = ?').get(req.user.id);

    if (!user.team_id) {
      return res.status(400).json({
        success: false,
        error: 'User not part of a team'
      });
    }

    const readiness = await AttackSimulation.getTeamReadinessScore(user.team_id);

    res.json({
      success: true,
      teamReadiness: readiness
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/training/history
 * Get simulation history
 */
router.get('/history', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const history = db.prepare(`
      SELECT 
        id,
        scenario_id,
        difficulty,
        score,
        time_to_detect,
        time_to_respond,
        time_to_remediate,
        rating,
        started_at,
        completed_at
      FROM attack_simulations
      WHERE user_id = ?
      ORDER BY started_at DESC
      LIMIT 50
    `).all(req.user.id);

    res.json({
      success: true,
      history
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/training/leaderboard
 * Get training leaderboard
 */
router.get('/leaderboard', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const leaderboard = db.prepare(`
      SELECT 
        u.id,
        u.name,
        u.email,
        COUNT(s.id) as simulations_completed,
        AVG(s.score) as avg_score,
        AVG(s.time_to_detect) as avg_detection,
        AVG(s.time_to_respond) as avg_response
      FROM users u
      LEFT JOIN attack_simulations s ON u.id = s.user_id AND s.status = 'completed'
      GROUP BY u.id
      HAVING simulations_completed > 0
      ORDER BY avg_score DESC, avg_detection ASC
      LIMIT 100
    `).all();

    res.json({
      success: true,
      leaderboard
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
