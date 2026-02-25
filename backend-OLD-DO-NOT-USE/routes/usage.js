/**
 * USAGE & QUOTA ROUTES
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const licenseService = require('../services/license-service');

/**
 * GET /api/usage
 * Obtenir l'usage complet du user
 */
router.get('/', auth, asyncHandler(async (req, res) => {
  const usage = licenseService.getUsageStats(req.user.userId);
  res.json(usage);
}));

/**
 * GET /api/usage/check/:action
 * Vérifier si une action est possible
 */
router.get('/check/:action', auth, asyncHandler(async (req, res) => {
  const { action } = req.params;
  const check = await licenseService.canPerformAction(req.user.userId, action);
  res.json(check);
}));

/**
 * GET /api/usage/feature/:feature
 * Vérifier l'accès à une feature
 */
router.get('/feature/:feature', auth, asyncHandler(async (req, res) => {
  const { feature } = req.params;
  const check = licenseService.canUseFeature(req.user.userId, feature);
  res.json(check);
}));

/**
 * POST /api/usage/grace-period
 * Activer grace period
 */
router.post('/grace-period', auth, asyncHandler(async (req, res) => {
  const gracePeriodEnd = licenseService.activateGracePeriod(req.user.userId);
  
  res.json({
    success: true,
    grace_period_ends_at: gracePeriodEnd,
    message: `Grace period activated for ${licenseService.gracePeriod} days`
  });
}));

module.exports = router;
