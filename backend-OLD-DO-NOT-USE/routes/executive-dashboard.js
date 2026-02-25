/**
 * EXECUTIVE DASHBOARD ROUTES
 * Rapports business-focused pour C-level et board
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { auth } = require('../middleware/auth');
const { asyncHandler } = require('../utils/error-handler');
const enrichmentService = require('../services/vulnerability-enrichment');
const competitiveIntel = require('../services/competitive-intelligence');

// Executive summary
router.get('/summary', auth, asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  
  // Get latest completed scan
  const latestScan = db.prepare(`
    SELECT s.*, d.url, d.name FROM scans s
    JOIN domains d ON s.domain_id = d.id
    WHERE s.user_id = ? AND s.status = 'completed'
    ORDER BY s.completed_at DESC LIMIT 1
  `).get(userId);

  if (!latestScan) {
    return res.json({ message: 'No completed scans yet. Run your first scan to see executive insights.' });
  }

  // Get vulnerabilities
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(latestScan.id);
  
  // Enrichir avec business impact
  const enriched = enrichmentService.enrichScanResults(vulns);
  
  // Comparative analysis
  const industry = req.query.industry || 'Technology';
  const competitive = competitiveIntel.generateExecutiveReport(latestScan, industry);

  res.json({
    scanOverview: {
      domain: latestScan.name || latestScan.url,
      completedAt: new Date(latestScan.completed_at * 1000),
      securityScore: latestScan.security_score,
      totalVulnerabilities: latestScan.total_vulns,
      criticalCount: latestScan.critical_count
    },
    businessImpact: enriched.businessImpact,
    competitivePosition: competitive,
    topRisks: enriched.vulnerabilities
      .filter(v => v.priority === 'P0' || v.priority === 'P1')
      .slice(0, 5)
      .map(v => ({
        title: v.title,
        priority: v.priority,
        exploitationSpeed: v.businessImpact?.exploitationSpeed,
        estimatedCost: v.businessImpact?.estimatedCost,
        knownExploits: v.knownExploits
      }))
  });
}));

// Board presentation (PDF-ready format)
router.get('/board-report', auth, asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  
  const scans = db.prepare(`
    SELECT s.*, d.url, d.name FROM scans s
    JOIN domains d ON s.domain_id = d.id
    WHERE s.user_id = ? AND s.status = 'completed'
    ORDER BY s.completed_at DESC LIMIT 12
  `).all(userId);

  if (!scans.length) {
    return res.status(404).json({ error: 'No data available for board report' });
  }

  // Trends over time
  const trend = scans.reverse().map(s => ({
    date: new Date(s.completed_at * 1000).toLocaleDateString(),
    score: s.security_score,
    critical: s.critical_count,
    high: s.high_count
  }));

  // Current state (latest scan)
  const latest = scans[scans.length - 1];
  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(latest.id);
  const enriched = enrichmentService.enrichScanResults(vulns);
  const competitive = competitiveIntel.generateExecutiveReport(latest, req.query.industry || 'Technology');

  res.json({
    reportDate: new Date(),
    coverageOverview: {
      domainsMonitored: db.prepare('SELECT COUNT(*) as c FROM domains WHERE user_id = ?').get(userId).c,
      scansCompleted: scans.length,
      lastScanDate: new Date(latest.completed_at * 1000)
    },
    securityPostureTrend: trend,
    currentState: {
      score: latest.security_score,
      percentile: competitive.industryComparison.percentile,
      vulnerabilities: {
        critical: latest.critical_count,
        high: latest.high_count,
        medium: latest.medium_count,
        low: latest.low_count
      }
    },
    riskExposure: {
      estimatedCost: enriched.businessImpact.estimatedCostRange,
      complianceViolations: enriched.businessImpact.complianceViolations,
      topThreats: enriched.businessImpact.criticalFindings.slice(0, 3)
    },
    competitivePosition: {
      industryPercentile: competitive.industryComparison.percentile,
      gapToTopPerformers: competitive.competitorComparison.gapToTop10.scoreGap,
      timeToTopTier: competitive.competitorComparison.gapToTop10.estimatedTimeToClose
    },
    recommendedActions: competitive.priorityActions.slice(0, 5),
    investmentRoadmap: competitive.roadmapToTop10
  });
}));

// Risk heat map (for visualization)
router.get('/risk-heatmap', auth, asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  
  const scans = db.prepare(`
    SELECT s.id, s.security_score, s.total_vulns, s.critical_count, d.url, d.name
    FROM scans s JOIN domains d ON s.domain_id = d.id
    WHERE s.user_id = ? AND s.status = 'completed'
  `).all(userId);

  const heatmap = scans.map(scan => {
    const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scan.id);
    const enriched = enrichmentService.enrichScanResults(vulns);
    
    return {
      domain: scan.name || scan.url,
      securityScore: scan.security_score,
      riskScore: 1000 - scan.security_score, // Inverse for heat
      totalVulnerabilities: scan.total_vulns,
      criticalVulnerabilities: scan.critical_count,
      estimatedLoss: enriched.businessImpact.estimatedCostRange.max,
      priority: scan.critical_count > 0 ? 'P0' : scan.security_score < 700 ? 'P1' : 'P2'
    };
  }).sort((a, b) => b.riskScore - a.riskScore);

  res.json({ heatmap, generatedAt: new Date() });
}));

// Compliance status
router.get('/compliance', auth, asyncHandler(async (req, res) => {
  const userId = req.user.userId;
  
  const latestScan = db.prepare(`
    SELECT s.*, d.url FROM scans s JOIN domains d ON s.domain_id = d.id
    WHERE s.user_id = ? AND s.status = 'completed'
    ORDER BY s.completed_at DESC LIMIT 1
  `).get(userId);

  if (!latestScan) {
    return res.status(404).json({ error: 'No scan data' });
  }

  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(latestScan.id);
  const enriched = enrichmentService.enrichScanResults(vulns);

  // Compliance frameworks
  const frameworks = {
    'PCI-DSS': {
      required: true,
      status: latestScan.critical_count === 0 && latestScan.high_count < 3 ? 'COMPLIANT' : 'NON-COMPLIANT',
      gaps: latestScan.critical_count + latestScan.high_count,
      requirements: [
        'Requirement 6.5.1: Injection flaws (SQL, Command)',
        'Requirement 6.5.7: Cross-site scripting (XSS)',
        'Requirement 11.3: Penetration testing at least annually'
      ]
    },
    'GDPR': {
      required: true,
      status: latestScan.security_score >= 800 ? 'COMPLIANT' : 'AT RISK',
      gaps: Math.max(0, 800 - latestScan.security_score),
      requirements: [
        'Article 32: Security of processing',
        'Article 33: Breach notification within 72 hours',
        'Article 25: Data protection by design'
      ]
    },
    'SOC2 Type II': {
      required: false,
      status: latestScan.security_score >= 850 ? 'READY' : 'NEEDS WORK',
      gaps: Math.max(0, 850 - latestScan.security_score),
      requirements: [
        'CC6.1: Logical and physical access controls',
        'CC6.6: Vulnerability management',
        'CC7.2: System monitoring'
      ]
    },
    'ISO 27001': {
      required: false,
      status: latestScan.security_score >= 820 ? 'READY' : 'NEEDS WORK',
      gaps: Math.max(0, 820 - latestScan.security_score),
      requirements: [
        'A.12.6.1: Technical vulnerability management',
        'A.14.2.8: System security testing',
        'A.18.2.3: Technical compliance review'
      ]
    }
  };

  res.json({
    overall: latestScan.security_score >= 800 ? 'GOOD STANDING' : 'ACTION REQUIRED',
    securityScore: latestScan.security_score,
    frameworks,
    violations: enriched.businessImpact.complianceViolations,
    remediationPlan: competitive.generateClosingPlan(latestScan.security_score, { avgScore: 850 })
  });
}));

module.exports = router;
