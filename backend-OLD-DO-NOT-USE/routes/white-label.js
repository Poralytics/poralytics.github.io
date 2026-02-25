const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const WhiteLabelSystem = require('../services/white-label-system');

// ========== RESELLER ROUTES ==========

/**
 * POST /api/white-label/create
 * Créer un compte white-label
 */
router.post('/create', auth, async (req, res) => {
  try {
    const { branding, config } = req.body;

    const result = await WhiteLabelSystem.createWhiteLabelAccount(
      req.user.id,
      branding,
      config
    );

    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/white-label/dashboard
 * Dashboard du revendeur
 */
router.get('/dashboard', auth, async (req, res) => {
  try {
    // Find white-label account for this user
    const db = require('../config/database');
    const account = db.prepare(
      'SELECT id FROM white_label_accounts WHERE reseller_id = ?'
    ).get(req.user.id);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'White-label account not found'
      });
    }

    const dashboard = await WhiteLabelSystem.getResellerDashboard(account.id);

    res.json({
      success: true,
      dashboard
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/white-label/branding/:whiteLabelId
 * Obtenir le branding
 */
router.get('/branding/:whiteLabelId', asyncHandler(async (req, res) => {
  try {
    const branding = await WhiteLabelSystem.getBranding(req.params.whiteLabelId);

    res.json({
      success: true,
      branding
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}));

/**
 * PUT /api/white-label/branding
 * Mettre à jour le branding
 */
router.put('/branding', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    const account = db.prepare(
      'SELECT id FROM white_label_accounts WHERE reseller_id = ?'
    ).get(req.user.id);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'White-label account not found'
      });
    }

    const result = await WhiteLabelSystem.updateBranding(
      account.id,
      req.body
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
 * POST /api/white-label/clients
 * Ajouter un client
 */
router.post('/clients', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    const account = db.prepare(
      'SELECT id FROM white_label_accounts WHERE reseller_id = ?'
    ).get(req.user.id);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'White-label account not found'
      });
    }

    const result = await WhiteLabelSystem.addClient(account.id, req.body);

    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/white-label/clients
 * Liste des clients
 */
router.get('/clients', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    const account = db.prepare(
      'SELECT id FROM white_label_accounts WHERE reseller_id = ?'
    ).get(req.user.id);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'White-label account not found'
      });
    }

    const clients = db.prepare(
      'SELECT * FROM white_label_clients WHERE white_label_id = ?'
    ).all(account.id);

    res.json({
      success: true,
      clients
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * DELETE /api/white-label/clients/:clientId
 * Supprimer un client
 */
router.delete('/clients/:clientId', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    db.prepare('DELETE FROM white_label_clients WHERE id = ?')
      .run(req.params.clientId);

    res.json({
      success: true,
      message: 'Client deleted'
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/white-label/commissions
 * Calcul des commissions
 */
router.get('/commissions', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    const account = db.prepare(
      'SELECT id FROM white_label_accounts WHERE reseller_id = ?'
    ).get(req.user.id);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'White-label account not found'
      });
    }

    const period = req.query.period || 'month';
    const commissions = await WhiteLabelSystem.calculateCommissions(
      account.id,
      period
    );

    res.json({
      success: true,
      commissions
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/white-label/generate-report/:clientId
 * Générer un rapport brandé pour un client
 */
router.post('/generate-report/:clientId', auth, async (req, res) => {
  try {
    const { scanId } = req.body;

    const db = require('../config/database');
    const client = db.prepare(
      'SELECT white_label_id FROM white_label_clients WHERE id = ?'
    ).get(req.params.clientId);

    if (!client) {
      return res.status(404).json({
        success: false,
        error: 'Client not found'
      });
    }

    const report = await WhiteLabelSystem.generateBrandedReport(
      scanId,
      client.white_label_id
    );

    res.json({
      success: true,
      report
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/white-label/setup-domain
 * Configuration du domaine personnalisé
 */
router.post('/setup-domain', auth, async (req, res) => {
  try {
    const { domain } = req.body;

    const db = require('../config/database');
    const account = db.prepare(
      'SELECT id FROM white_label_accounts WHERE reseller_id = ?'
    ).get(req.user.id);

    if (!account) {
      return res.status(404).json({
        success: false,
        error: 'White-label account not found'
      });
    }

    const dnsInstructions = await WhiteLabelSystem.setupCustomDomain(
      account.id,
      domain
    );

    res.json({
      success: true,
      dnsInstructions
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
