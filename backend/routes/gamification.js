const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const GamificationSystem = require('../services/gamification-system');

/**
 * GET /api/gamification/profile
 * Profil gamification de l'utilisateur
 */
router.get('/profile', auth, async (req, res) => {
  try {
    const profile = await GamificationSystem.getUserProfile(req.user.id);

    res.json({
      success: true,
      profile
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/gamification/leaderboard
 * Classement global
 */
router.get('/leaderboard', asyncHandler(async (req, res) => {
  try {
    const type = req.query.type || 'global';
    const limit = parseInt(req.query.limit) || 100;

    const leaderboard = await GamificationSystem.getLeaderboard(type, limit);

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
}));

/**
 * GET /api/gamification/achievements
 * Liste des achievements
 */
router.get('/achievements', asyncHandler(async (req, res) => {
  try {
    const achievements = GamificationSystem.achievements;

    res.json({
      success: true,
      achievements
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}));

/**
 * GET /api/gamification/my-achievements
 * Achievements débloqués par l'utilisateur
 */
router.get('/my-achievements', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const achievements = db.prepare(`
      SELECT ua.*, ua.unlocked_at
      FROM user_achievements ua
      WHERE ua.user_id = ?
      ORDER BY ua.unlocked_at DESC
    `).all(req.user.id);

    res.json({
      success: true,
      achievements
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/gamification/challenges
 * Challenges actifs
 */
router.get('/challenges', auth, async (req, res) => {
  try {
    const challenges = await GamificationSystem.getActiveChallenges(req.user.id);

    res.json({
      success: true,
      challenges
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/gamification/challenges/:challengeId/join
 * Rejoindre un challenge
 */
router.post('/challenges/:challengeId/join', auth, async (req, res) => {
  try {
    const result = await GamificationSystem.joinChallenge(
      req.user.id,
      req.params.challengeId
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
 * GET /api/gamification/points-history
 * Historique des points
 */
router.get('/points-history', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const limit = parseInt(req.query.limit) || 50;
    
    const history = db.prepare(`
      SELECT * FROM gamification_points_log 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT ?
    `).all(req.user.id, limit);

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
 * GET /api/gamification/levels
 * Liste des niveaux
 */
router.get('/levels', asyncHandler(async (req, res) => {
  try {
    const levels = GamificationSystem.levels.slice(0, 100);

    res.json({
      success: true,
      levels
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}));

/**
 * POST /api/gamification/award-points
 * Attribution manuelle de points (admin)
 */
router.post('/award-points', auth, async (req, res) => {
  try {
    // Check admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const { userId, action, multiplier } = req.body;

    const result = await GamificationSystem.awardPoints(
      userId,
      action,
      multiplier || 1
    );

    res.json({
      success: true,
      ...result
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
