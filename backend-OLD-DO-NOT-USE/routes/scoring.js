const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const PredictiveScoring = require('../services/predictive-scoring');

/**
 * GET /api/scoring/:domainId
 * Get comprehensive security score for a domain
 */
router.get('/:domainId', auth, async (req, res) => {
  try {
    const { domainId } = req.params;

    // Verify domain belongs to user
    const db = require('../config/database');
    const domain = db.prepare(
      'SELECT * FROM domains WHERE id = ? AND user_id = ?'
    ).get(domainId, req.user.id);

    if (!domain) {
      return res.status(404).json({
        success: false,
        error: 'Domain not found'
      });
    }

    const score = await PredictiveScoring.calculateSecurityScore(domainId);

    res.json({
      success: true,
      score
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/scoring/:domainId/history
 * Get score history (trend over time)
 */
router.get('/:domainId/history', auth, async (req, res) => {
  try {
    const { domainId } = req.params;
    const { days } = req.query;

    const db = require('../config/database');
    
    // Verify ownership
    const domain = db.prepare(
      'SELECT * FROM domains WHERE id = ? AND user_id = ?'
    ).get(domainId, req.user.id);

    if (!domain) {
      return res.status(404).json({
        success: false,
        error: 'Domain not found'
      });
    }

    const since = Date.now() / 1000 - (parseInt(days) || 30) * 86400;

    const history = db.prepare(`
      SELECT 
        security_score as score,
        completed_at as timestamp,
        vulnerabilities_found,
        vulnerabilities_fixed
      FROM scans
      WHERE domain_id = ? AND status = 'completed' AND completed_at >= ?
      ORDER BY completed_at ASC
    `).all(domainId, since);

    res.json({
      success: true,
      history
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/scoring/benchmark/:industry
 * Get industry benchmark data
 */
router.get('/benchmark/:industry', auth, async (req, res) => {
  try {
    const { industry } = req.params;

    const benchmarks = {
      'finance': {
        average: 850,
        median: 870,
        top10: 950,
        bottom10: 720,
        description: 'Financial services have highest security standards'
      },
      'healthcare': {
        average: 820,
        median: 830,
        top10: 920,
        bottom10: 680,
        description: 'Healthcare focuses on HIPAA compliance'
      },
      'ecommerce': {
        average: 780,
        median: 790,
        top10: 900,
        bottom10: 650,
        description: 'E-commerce balances security and performance'
      },
      'saas': {
        average: 800,
        median: 810,
        top10: 920,
        bottom10: 670,
        description: 'SaaS companies prioritize security'
      },
      'education': {
        average: 750,
        median: 760,
        top10: 870,
        bottom10: 620,
        description: 'Education sector improving security posture'
      },
      'government': {
        average: 880,
        median: 890,
        top10: 970,
        bottom10: 750,
        description: 'Government has strictest requirements'
      }
    };

    const benchmark = benchmarks[industry] || {
      average: 770,
      median: 780,
      top10: 890,
      bottom10: 640,
      description: 'Industry average security score'
    };

    res.json({
      success: true,
      industry,
      benchmark
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/scoring/:domainId/simulate
 * Simulate score improvement with hypothetical fixes
 */
router.post('/:domainId/simulate', auth, async (req, res) => {
  try {
    const { domainId } = req.params;
    const { fixes } = req.body;

    const db = require('../config/database');
    
    // Get current score
    const currentScore = await PredictiveScoring.calculateSecurityScore(domainId);

    // Simulate fixes
    let simulatedScore = currentScore.score;

    if (fixes.critical) {
      simulatedScore += fixes.critical * 80;
    }
    if (fixes.high) {
      simulatedScore += fixes.high * 30;
    }
    if (fixes.medium) {
      simulatedScore += fixes.medium * 10;
    }
    if (fixes.low) {
      simulatedScore += fixes.low * 2;
    }

    simulatedScore = Math.min(1000, simulatedScore);

    const improvement = simulatedScore - currentScore.score;
    const newGrade = PredictiveScoring.getScoreGrade(simulatedScore);
    const newRiskLevel = PredictiveScoring.getRiskLevel(simulatedScore);

    res.json({
      success: true,
      simulation: {
        current: {
          score: currentScore.score,
          grade: currentScore.grade,
          riskLevel: currentScore.riskLevel
        },
        projected: {
          score: simulatedScore,
          grade: newGrade,
          riskLevel: newRiskLevel
        },
        improvement: {
          points: improvement,
          percentage: Math.round((improvement / currentScore.score) * 100)
        },
        fixes
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
