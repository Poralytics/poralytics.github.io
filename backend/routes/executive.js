/**
 * EXECUTIVE REPORTING ROUTES
 * Endpoints pour rapports exécutifs
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const executiveService = require('../services/executive-reporting-service');

/**
 * GET /api/executive/summary
 * Executive summary complet
 */
router.get('/summary', auth, asyncHandler(async (req, res) => {
  const summary = executiveService.generateExecutiveSummary(req.user.userId);
  res.json(summary);
}));

/**
 * GET /api/executive/board-report
 * Rapport pour le board of directors
 */
router.get('/board-report', auth, asyncHandler(async (req, res) => {
  const report = executiveService.generateBoardReport(req.user.userId);
  res.json(report);
}));

/**
 * GET /api/executive/export
 * Données d'export (CSV format)
 */
router.get('/export', auth, asyncHandler(async (req, res) => {
  const data = executiveService.generateExportData(req.user.userId);
  res.json(data);
}));

/**
 * GET /api/executive/export/csv
 * Export CSV direct
 */
router.get('/export/csv', auth, asyncHandler(async (req, res) => {
  const data = executiveService.generateExportData(req.user.userId);
  
  // Convertir en CSV
  let csv = '';
  
  // Summary
  csv += 'SECURITY SUMMARY\n';
  data.summary.forEach(row => {
    csv += row.join(',') + '\n';
  });
  
  csv += '\n\nDOMAINS DETAIL\n';
  csv += 'Domain,Score,Category,Critical,High,Medium,Total Vulnerabilities\n';
  data.domains.forEach(d => {
    csv += `${d.Domain},${d.Score},${d.Category},${d.Critical},${d.High},${d.Medium},${d['Total Vulnerabilities']}\n`;
  });
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=nexus-security-report.csv');
  res.send(csv);
}));

module.exports = router;
