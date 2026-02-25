/**
 * SECURITY HEALTH SCORE ROUTES
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const scoreService = require('../services/security-health-score');

/**
 * GET /api/score
 * Score global de l'utilisateur
 */
router.get('/', auth, asyncHandler(async (req, res) => {
  const score = scoreService.calculateUserScore(req.user.userId);
  res.json(score);
}));

/**
 * GET /api/score/history
 * Historique du score
 */
router.get('/history', auth, asyncHandler(async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const history = scoreService.getScoreHistory(req.user.userId, days);
  res.json({ history, days });
}));

/**
 * GET /api/score/benchmark
 * Comparaison avec l'industrie
 */
router.get('/benchmark', auth, asyncHandler(async (req, res) => {
  const benchmark = scoreService.getIndustryBenchmark(req.user.userId);
  res.json(benchmark);
}));

/**
 * GET /api/score/risk
 * Évaluation des risques
 */
router.get('/risk', auth, asyncHandler(async (req, res) => {
  const risk = scoreService.getRiskAssessment(req.user.userId);
  res.json(risk);
}));

/**
 * GET /api/score/domain/:domainId
 * Score d'un domaine spécifique
 */
router.get('/domain/:domainId', auth, asyncHandler(async (req, res) => {
  const { domainId } = req.params;
  const score = scoreService.calculateDomainScore(parseInt(domainId));
  res.json(score);
}));

module.exports = router;
