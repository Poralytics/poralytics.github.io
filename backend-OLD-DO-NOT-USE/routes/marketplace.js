const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const ScannerMarketplace = require('../services/scanner-marketplace');

// ========== PUBLIC ROUTES ==========

/**
 * GET /api/marketplace/scanners
 * Liste tous les scanners approuvés
 */
router.get('/scanners', asyncHandler(async (req, res) => {
  try {
    const filters = {
      category: req.query.category,
      pricingTier: req.query.pricingTier,
      search: req.query.search,
      sortBy: req.query.sortBy || 'downloads',
      sortOrder: req.query.sortOrder || 'DESC',
      limit: parseInt(req.query.limit) || 50,
      offset: parseInt(req.query.offset) || 0
    };

    const scanners = await ScannerMarketplace.getMarketplaceListings(filters);

    res.json({
      success: true,
      scanners,
      total: scanners.length,
      filters
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}));

/**
 * GET /api/marketplace/scanners/:id
 * Détails d'un scanner
 */
router.get('/scanners/:id', asyncHandler(async (req, res) => {
  try {
    const scanner = await ScannerMarketplace.getScannerDetails(req.params.id);

    if (!scanner) {
      return res.status(404).json({
        success: false,
        error: 'Scanner not found'
      });
    }

    res.json({
      success: true,
      scanner
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}));

// ========== AUTHENTICATED ROUTES ==========

/**
 * POST /api/marketplace/scanners
 * Soumettre un nouveau scanner
 */
router.post('/scanners', auth, async (req, res) => {
  try {
    const result = await ScannerMarketplace.submitScanner(req.user.id, req.body);

    res.status(201).json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/marketplace/scanners/:id/install
 * Installer un scanner
 */
router.post('/scanners/:id/install', auth, async (req, res) => {
  try {
    const result = await ScannerMarketplace.installScanner(req.user.id, req.params.id);

    res.json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/marketplace/scanners/:id/execute
 * Exécuter un scanner installé
 */
router.post('/scanners/:id/execute', auth, async (req, res) => {
  try {
    const result = await ScannerMarketplace.executeScanner(
      req.user.id,
      req.params.id,
      req.body.target
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
 * GET /api/marketplace/my-scanners
 * Scanners installés par l'utilisateur
 */
router.get('/my-scanners', auth, async (req, res) => {
  try {
    const scanners = await ScannerMarketplace.getInstalledScanners(req.user.id);

    res.json({
      success: true,
      scanners
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/marketplace/scanners/:id/review
 * Noter et évaluer un scanner
 */
router.post('/scanners/:id/review', auth, async (req, res) => {
  try {
    const { rating, review } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({
        success: false,
        error: 'Rating must be between 1 and 5'
      });
    }

    const result = await ScannerMarketplace.rateScanner(
      req.user.id,
      req.params.id,
      rating,
      review
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
 * GET /api/marketplace/scanners/:id/reviews
 * Obtenir les reviews d'un scanner
 */
router.get('/scanners/:id/reviews', asyncHandler(async (req, res) => {
  try {
    const reviews = await ScannerMarketplace.getScannerReviews(req.params.id);

    res.json({
      success: true,
      reviews
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}));

// ========== DEVELOPER ROUTES ==========

/**
 * GET /api/marketplace/developer/dashboard
 * Tableau de bord développeur
 */
router.get('/developer/dashboard', auth, async (req, res) => {
  try {
    const dashboard = await ScannerMarketplace.getDeveloperDashboard(req.user.id);

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
 * GET /api/marketplace/developer/revenue
 * Revenus du développeur
 */
router.get('/developer/revenue', auth, async (req, res) => {
  try {
    const period = req.query.period || 'month';
    const revenue = await ScannerMarketplace.getDeveloperRevenue(req.user.id, period);

    res.json({
      success: true,
      revenue
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * PUT /api/marketplace/scanners/:id
 * Mettre à jour un scanner
 */
router.put('/scanners/:id', auth, async (req, res) => {
  try {
    const result = await ScannerMarketplace.updateScanner(
      req.user.id,
      req.params.id,
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
 * DELETE /api/marketplace/scanners/:id
 * Supprimer un scanner
 */
router.delete('/scanners/:id', auth, async (req, res) => {
  try {
    const result = await ScannerMarketplace.deleteScanner(req.user.id, req.params.id);

    res.json(result);
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// ========== ADMIN ROUTES ==========

/**
 * POST /api/marketplace/scanners/:id/review-decision
 * Approuver/rejeter un scanner (admin)
 */
router.post('/scanners/:id/review-decision', auth, async (req, res) => {
  try {
    // Check if user is admin
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const { decision, feedback } = req.body;

    if (!decision || !['approve', 'reject'].includes(decision)) {
      return res.status(400).json({
        success: false,
        error: 'Decision must be approve or reject'
      });
    }

    const result = await ScannerMarketplace.reviewScanner(
      req.params.id,
      req.user.id,
      decision,
      feedback
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
 * GET /api/marketplace/admin/pending
 * Scanners en attente de review (admin)
 */
router.get('/admin/pending', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        error: 'Admin access required'
      });
    }

    const pending = await ScannerMarketplace.getPendingScanners();

    res.json({
      success: true,
      scanners: pending
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
