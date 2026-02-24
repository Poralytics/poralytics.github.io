const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const {auth} = require('../middleware/auth');
const aiAnalyzer = require('../services/ai-vulnerability-analyzer');
const db = require('../config/database');

// Analyze vulnerabilities with AI
router.post('/analyze', auth, async (req, res) => {
  try {
    const {scan_id} = req.body;
    
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scan_id);
    if (!scan) {
      return res.status(404).json({error: 'Scan not found'});
    }

    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?')
      .all(scan_id);
    
    const domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(scan.domain_id);
    const context = {
      criticality: domain.criticality || 'medium',
      exposure_level: 'internet',
      business_value: domain.business_value
    };

    const analyzed = aiAnalyzer.batchAnalyze(vulnerabilities, context);
    const insights = aiAnalyzer.generateInsights(analyzed);
    
    res.json({vulnerabilities: analyzed, insights});
  } catch (error) {
    console.error('AI analysis error:', error);
    res.status(500).json({error: 'Failed to analyze vulnerabilities'});
  }
});

// Get AI insights for domain
router.get('/insights/:domainId', auth, (req, res) => {
  try {
    const latestScan = db.prepare(`
      SELECT * FROM scans 
      WHERE domain_id = ? AND status = 'completed'
      ORDER BY completed_at DESC LIMIT 1
    `).get(req.params.domainId);
    
    if (!latestScan) {
      return res.json({insights: null});
    }

    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?')
      .all(latestScan.id);
    
    const insights = aiAnalyzer.generateInsights(
      vulnerabilities.map(v => ({
        ...v,
        ai_analysis: aiAnalyzer.analyzeVulnerability(v, {criticality: 'medium'})
      }))
    );
    
    res.json({insights});
  } catch (error) {
    res.status(500).json({error: 'Failed to get insights'});
  }
});

module.exports = router;
