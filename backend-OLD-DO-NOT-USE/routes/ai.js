/**
 * AI-POWERED FEATURES ROUTES
 * Endpoints pour l'analyse AI et la génération automatique
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { requireFeature } = require('../middleware/quota-enforcement');
const { asyncHandler } = require('../utils/error-handler');
const aiService = require('../services/ai-security-service');
const db = require('../config/database');

/**
 * POST /api/ai/explain
 * Expliquer une vulnérabilité en langage simple
 */
router.post('/explain', auth, requireFeature('ai'), asyncHandler(async (req, res) => {
  const { vulnerability_id } = req.body;
  
  if (!vulnerability_id) {
    return res.status(400).json({ error: 'vulnerability_id required' });
  }

  // Récupérer la vulnérabilité
  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnerability_id);
  
  if (!vuln) {
    return res.status(404).json({ error: 'Vulnerability not found' });
  }

  const explanation = await aiService.explainVulnerability(vuln);
  
  res.json({
    vulnerability_id,
    explanation,
    generated_at: new Date().toISOString()
  });
}));

/**
 * POST /api/ai/remediate
 * Générer automatiquement un fix pour une vulnérabilité
 */
router.post('/remediate', auth, requireFeature('ai'), asyncHandler(async (req, res) => {
  const { vulnerability_id } = req.body;
  
  if (!vulnerability_id) {
    return res.status(400).json({ error: 'vulnerability_id required' });
  }

  const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?').get(vulnerability_id);
  
  if (!vuln) {
    return res.status(404).json({ error: 'Vulnerability not found' });
  }

  const remediation = await aiService.generateRemediationCode(vuln);
  
  res.json({
    vulnerability_id,
    remediation,
    generated_at: new Date().toISOString()
  });
}));

/**
 * GET /api/ai/executive-summary
 * Générer un résumé exécutif avec AI
 */
router.get('/executive-summary', auth, requireFeature('ai'), asyncHandler(async (req, res) => {
  const summary = await aiService.generateExecutiveSummary(req.user.userId);
  
  res.json({
    summary,
    generated_at: new Date().toISOString()
  });
}));

/**
 * GET /api/ai/predictions
 * Prédire les vulnérabilités futures
 */
router.get('/predictions', auth, requireFeature('ai'), asyncHandler(async (req, res) => {
  const predictions = await aiService.predictFutureVulnerabilities(req.user.userId);
  
  res.json({
    predictions,
    generated_at: new Date().toISOString()
  });
}));

/**
 * POST /api/ai/prioritize
 * Prioriser les vulnérabilités par impact business
 */
router.post('/prioritize', auth, requireFeature('ai'), asyncHandler(async (req, res) => {
  const { vulnerability_ids, business_context } = req.body;
  
  if (!vulnerability_ids || !Array.isArray(vulnerability_ids)) {
    return res.status(400).json({ error: 'vulnerability_ids array required' });
  }

  // Récupérer les vulnérabilités
  const vulns = db.prepare(`
    SELECT * FROM vulnerabilities 
    WHERE id IN (${vulnerability_ids.map(() => '?').join(',')})
  `).all(...vulnerability_ids);

  const prioritization = await aiService.prioritizeByBusinessImpact(
    vulns,
    business_context || {}
  );
  
  res.json({
    prioritization,
    generated_at: new Date().toISOString()
  });
}));

/**
 * GET /api/ai/bulk-explain/:scan_id
 * Expliquer toutes les vulns d'un scan
 */
router.get('/bulk-explain/:scanId', auth, requireFeature('ai'), asyncHandler(async (req, res) => {
  const { scanId } = req.params;
  
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ? LIMIT 10').all(scanId);
  
  const explanations = await Promise.all(
    vulns.map(async (v) => ({
      vulnerability_id: v.id,
      type: v.type,
      severity: v.severity,
      explanation: await aiService.explainVulnerability(v)
    }))
  );
  
  res.json({
    scan_id: scanId,
    explanations,
    total: explanations.length
  });
}));

module.exports = router;
