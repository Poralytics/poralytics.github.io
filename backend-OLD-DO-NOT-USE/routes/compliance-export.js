/**
 * COMPLIANCE & DATA EXPORT ROUTES
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const complianceExporter = require('../services/compliance-exporter');

// Export données utilisateur (GDPR)
router.get('/export-my-data', auth, asyncHandler(async (req, res) => {
  const data = await complianceExporter.exportUserData(req.user.userId);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="nexus-data-export-${req.user.userId}.json"`);
  res.json(data);
}));

// Demande de suppression (GDPR Right to be Forgotten)
router.delete('/delete-my-data', auth, asyncHandler(async (req, res) => {
  const { confirm } = req.body;
  if (confirm !== 'DELETE_ALL_MY_DATA') {
    return res.status(400).json({ 
      error: 'Confirmation required',
      message: 'Send {"confirm": "DELETE_ALL_MY_DATA"} to proceed'
    });
  }

  const result = await complianceExporter.deleteUserData(req.user.userId);
  res.json({ 
    success: true, 
    message: 'All your data has been permanently deleted',
    ...result
  });
}));

// SOC2 report (admin only)
router.get('/soc2-report', auth, asyncHandler(async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const { start_date, end_date } = req.query;
  if (!start_date || !end_date) {
    return res.status(400).json({ error: 'start_date and end_date required (YYYY-MM-DD)' });
  }

  const report = await complianceExporter.generateSOC2Report(start_date, end_date);
  res.json(report);
}));

// PCI-DSS report (admin only)
router.get('/pci-dss-report', auth, asyncHandler(async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }

  const report = await complianceExporter.generatePCIDSSReport();
  res.json(report);
}));

module.exports = router;
