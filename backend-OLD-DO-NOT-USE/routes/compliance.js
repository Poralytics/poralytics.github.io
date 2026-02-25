const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const ComplianceAutomation = require('../services/compliance-automation');

/**
 * POST /api/compliance/start-monitoring
 * Démarrer le monitoring continu
 */
router.post('/start-monitoring', auth, async (req, res) => {
  try {
    const { frameworks } = req.body;

    if (!frameworks || !Array.isArray(frameworks)) {
      return res.status(400).json({
        success: false,
        error: 'Frameworks array required'
      });
    }

    const result = await ComplianceAutomation.startContinuousMonitoring(
      req.user.id,
      frameworks
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
 * GET /api/compliance/status/:framework
 * Vérifier le statut de conformité
 */
router.get('/status/:framework', auth, async (req, res) => {
  try {
    const status = await ComplianceAutomation.checkComplianceStatus(
      req.user.id,
      req.params.framework
    );

    res.json({
      success: true,
      status
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/compliance/dashboard
 * Dashboard de conformité
 */
router.get('/dashboard', auth, async (req, res) => {
  try {
    const dashboard = await ComplianceAutomation.getComplianceDashboard(req.user.id);

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
 * POST /api/compliance/generate-report/:framework
 * Générer rapport d'audit
 */
router.post('/generate-report/:framework', auth, async (req, res) => {
  try {
    const report = await ComplianceAutomation.generateAuditReport(
      req.user.id,
      req.params.framework,
      req.body.options || {}
    );

    res.json(report);
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/compliance/collect-evidence/:framework
 * Collecter les preuves automatiquement
 */
router.post('/collect-evidence/:framework', auth, async (req, res) => {
  try {
    const evidence = await ComplianceAutomation.collectEvidence(
      req.user.id,
      req.params.framework
    );

    res.json({
      success: true,
      evidence
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/compliance/frameworks
 * Liste des frameworks supportés
 */
router.get('/frameworks', asyncHandler(async (req, res) => {
  try {
    const frameworks = [
      {
        id: 'gdpr',
        name: 'GDPR',
        description: 'General Data Protection Regulation',
        controlsCount: 5
      },
      {
        id: 'soc2',
        name: 'SOC 2 Type II',
        description: 'Trust Services Criteria',
        controlsCount: 3
      },
      {
        id: 'iso27001',
        name: 'ISO 27001',
        description: 'Information Security Management',
        controlsCount: 2
      },
      {
        id: 'hipaa',
        name: 'HIPAA',
        description: 'Health Insurance Portability',
        controlsCount: 2
      },
      {
        id: 'pciDss',
        name: 'PCI DSS',
        description: 'Payment Card Industry',
        controlsCount: 2
      },
      {
        id: 'nist',
        name: 'NIST CSF',
        description: 'Cybersecurity Framework',
        controlsCount: 1
      }
    ];

    res.json({
      success: true,
      frameworks
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
}));

/**
 * GET /api/compliance/reports
 * Historique des rapports
 */
router.get('/reports', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const reports = db.prepare(`
      SELECT * FROM compliance_reports 
      WHERE user_id = ? 
      ORDER BY created_at DESC 
      LIMIT 50
    `).all(req.user.id);

    res.json({
      success: true,
      reports
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/compliance/report/:reportId/download
 * Télécharger un rapport
 */
router.get('/report/:reportId/download', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const report = db.prepare(
      'SELECT * FROM compliance_reports WHERE id = ? AND user_id = ?'
    ).get(req.params.reportId, req.user.id);

    if (!report) {
      return res.status(404).json({
        success: false,
        error: 'Report not found'
      });
    }

    if (report.pdf_path) {
      res.download(report.pdf_path);
    } else {
      res.json({
        success: true,
        report: JSON.parse(report.report_data)
      });
    }
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
