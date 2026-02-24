/**
 * CI/CD INTEGRATION ROUTES
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const cicdService = require('../services/cicd-integration-service');

/**
 * GET /api/cicd/platforms
 * Liste des plateformes supportées
 */
router.get('/platforms', auth, asyncHandler(async (req, res) => {
  res.json({
    platforms: cicdService.supportedPlatforms,
    count: cicdService.supportedPlatforms.length
  });
}));

/**
 * POST /api/cicd/generate/:platform
 * Générer configuration pour une plateforme
 */
router.post('/generate/:platform', auth, asyncHandler(async (req, res) => {
  const { platform } = req.params;
  const config = req.body;
  
  const docs = cicdService.generateIntegrationDocs(platform, config);
  
  res.json(docs);
}));

/**
 * GET /api/cicd/badge
 * Générer badge sécurité pour README
 */
router.get('/badge', auth, asyncHandler(async (req, res) => {
  const badge = cicdService.generateSecurityBadge(req.user.userId);
  res.json(badge);
}));

/**
 * POST /api/cicd/webhook/:platform
 * Webhook pour événements CI/CD
 */
router.post('/webhook/:platform', asyncHandler(async (req, res) => {
  const { platform } = req.params;
  const payload = req.body;
  
  const result = await cicdService.handleCIWebhook(payload, platform);
  
  res.json(result);
}));

/**
 * GET /api/cicd/cli-commands
 * Obtenir commandes CLI
 */
router.get('/cli-commands', auth, asyncHandler(async (req, res) => {
  const { apiKey, domain, format } = req.query;
  
  const commands = cicdService.generateCLICommands({
    apiKey: apiKey || 'YOUR_API_KEY',
    domain: domain || 'example.com',
    format: format || 'json'
  });
  
  res.json(commands);
}));

module.exports = router;
