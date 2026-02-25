/**
 * VISUALIZATION ROUTES
 * Endpoints pour heatmap, timeline, trends
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const heatmapService = require('../services/risk-heatmap-service');

/**
 * GET /api/visualizations/heatmap
 * Données du Risk Heatmap
 */
router.get('/heatmap', auth, asyncHandler(async (req, res) => {
  const heatmap = heatmapService.generateHeatmap(req.user.userId);
  res.json(heatmap);
}));

/**
 * GET /api/visualizations/timeline
 * Timeline des incidents
 */
router.get('/timeline', auth, asyncHandler(async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const timeline = heatmapService.generateTimeline(req.user.userId, days);
  res.json(timeline);
}));

/**
 * GET /api/visualizations/trend
 * Données de tendance pour graphique
 */
router.get('/trend', auth, asyncHandler(async (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const trend = heatmapService.generateTrendData(req.user.userId, days);
  res.json({ trend, days });
}));

/**
 * GET /api/visualizations/comparison
 * Comparaison multi-domaines
 */
router.get('/comparison', auth, asyncHandler(async (req, res) => {
  const comparison = heatmapService.generateDomainComparison(req.user.userId);
  res.json({ domains: comparison });
}));

module.exports = router;
