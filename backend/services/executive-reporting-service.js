/**
 * EXECUTIVE REPORTING SERVICE
 * Génère des rapports pour CEO, CFO, Board
 */

const db = require('../config/database');
const scoreService = require('./security-health-score');
const heatmapService = require('./risk-heatmap-service');
const { logger } = require('../utils/error-handler');

class ExecutiveReportingService {
  constructor() {
    // Coûts moyens par type de breach (IBM Cost of Data Breach Report)
    this.breachCosts = {
      critical: 500000,   // $500K per critical vuln
      high: 100000,       // $100K per high vuln
      medium: 20000,      // $20K per medium vuln
      low: 5000,          // $5K per low vuln
      info: 1000          // $1K per info
    };
  }

  /**
   * Générer un executive summary complet
   */
  generateExecutiveSummary(userId) {
    const score = scoreService.calculateUserScore(userId);
    const risk = scoreService.getRiskAssessment(userId);
    const benchmark = scoreService.getIndustryBenchmark(userId);
    const heatmap = heatmapService.generateHeatmap(userId);

    // Calculer les métriques financières
    const financialImpact = this.calculateFinancialImpact(userId, score.breakdown);
    
    // Générer les recommandations top 3
    const topRecommendations = this.getTopRecommendations(score, heatmap);

    // Calculer le ROI de la sécurité
    const roi = this.calculateSecurityROI(userId, financialImpact);

    return {
      executive_summary: {
        headline: this.generateHeadline(score.score, risk.breach_probability),
        score: score.score,
        category: score.category,
        trend: score.trend,
        needs_attention: score.score < 750 || risk.breach_probability > 30
      },
      
      key_metrics: {
        security_score: score.score,
        industry_percentile: benchmark.percentile,
        breach_probability: risk.breach_probability,
        financial_risk: financialImpact.total_exposure,
        domains_protected: heatmap.summary.total_domains,
        vulnerabilities_open: score.total_vulnerabilities
      },

      financial_impact: financialImpact,
      
      risk_assessment: {
        level: risk.risk_level,
        probability: risk.breach_probability,
        time_to_breach: risk.time_to_breach,
        estimated_cost: financialImpact.average_breach_cost
      },

      industry_comparison: {
        your_score: benchmark.your_score,
        industry_average: benchmark.industry_average,
        percentile: benchmark.percentile,
        message: benchmark.message
      },

      top_recommendations: topRecommendations,

      roi_analysis: roi,

      summary_bullets: [
        `Security score: ${score.score}/1000 (${score.category})`,
        `${score.total_vulnerabilities} vulnerabilities identified, ${this.countFixed(userId)} resolved`,
        `Estimated financial risk: $${this.formatNumber(financialImpact.total_exposure)}`,
        benchmark.percentile >= 50 
          ? `Performing better than ${benchmark.percentile}% of organizations`
          : `Below industry average, significant room for improvement`,
        score.trend.improving 
          ? `Security posture improving (+${score.trend.difference} points)`
          : `Security posture declining (-${score.trend.difference} points)`
      ]
    };
  }

  /**
   * Calculer l'impact financier
   */
  calculateFinancialImpact(userId, breakdown) {
    let totalExposure = 0;
    const byCategory = {};

    for (const [severity, stats] of Object.entries(breakdown)) {
      const cost = (this.breachCosts[severity] || 0) * stats.open;
      byCategory[severity] = cost;
      totalExposure += cost;
    }

    // Coût moyen d'une breach (selon IBM: $4.35M en 2023)
    const averageBreachCost = 4350000;

    // Calculer les économies potentielles si tout est fixé
    const savingsIfFixed = totalExposure * 0.9; // 90% de réduction du risque

    return {
      total_exposure: totalExposure,
      by_category: byCategory,
      average_breach_cost: averageBreachCost,
      potential_savings: savingsIfFixed,
      investment_required: this.estimateFixCost(breakdown),
      roi_ratio: savingsIfFixed > 0 ? 
        (savingsIfFixed / this.estimateFixCost(breakdown)).toFixed(1) : 0
    };
  }

  /**
   * Estimer le coût de correction
   */
  estimateFixCost(breakdown) {
    // Coût moyen par développeur: $100/heure
    const hourlyRate = 100;
    
    // Temps moyen pour fixer par sévérité (heures)
    const fixTime = {
      critical: 8,
      high: 4,
      medium: 2,
      low: 1,
      info: 0.5
    };

    let totalCost = 0;
    for (const [severity, stats] of Object.entries(breakdown)) {
      const hours = (fixTime[severity] || 0) * stats.open;
      totalCost += hours * hourlyRate;
    }

    return totalCost;
  }

  /**
   * Calculer le ROI de l'investissement sécurité
   */
  calculateSecurityROI(userId, financialImpact) {
    // Coût de NEXUS (supposons plan Professional à $299/mo)
    const nexusCost = 299 * 12; // $3,588/year
    
    // Coût des corrections
    const fixCost = financialImpact.investment_required;
    
    // Économies (risque évité)
    const savings = financialImpact.potential_savings;

    // ROI total
    const totalInvestment = nexusCost + fixCost;
    const netBenefit = savings - totalInvestment;
    const roiPercentage = totalInvestment > 0 
      ? ((netBenefit / totalInvestment) * 100).toFixed(1)
      : 0;

    return {
      total_investment: totalInvestment,
      nexus_cost: nexusCost,
      fix_cost: fixCost,
      potential_savings: savings,
      net_benefit: netBenefit,
      roi_percentage: parseFloat(roiPercentage),
      payback_period_months: netBenefit > 0 
        ? Math.ceil((totalInvestment / (savings / 12)))
        : null,
      message: netBenefit > 0
        ? `${roiPercentage}% ROI - Investment pays back in ${Math.ceil(totalInvestment / (savings / 12))} months`
        : 'Investment required to reduce risk'
    };
  }

  /**
   * Générer un headline accrocheur
   */
  generateHeadline(score, breachProbability) {
    if (score >= 900) {
      return '✅ Excellent Security Posture - Well Protected';
    } else if (score >= 750) {
      return '✓ Good Security - Minor Improvements Needed';
    } else if (score >= 500) {
      return '⚠️ Fair Security - Action Required';
    } else if (score >= 250) {
      return '🔴 Poor Security - Significant Risk';
    } else {
      return '🚨 Critical Security Issues - Immediate Action Required';
    }
  }

  /**
   * Top 3 recommandations
   */
  getTopRecommendations(score, heatmap) {
    const recommendations = [];

    // Recommandation 1: Basé sur les vulns critiques
    if (score.breakdown.critical.open > 0) {
      recommendations.push({
        priority: 1,
        title: `Fix ${score.breakdown.critical.open} Critical Vulnerabilities`,
        impact: 'High',
        effort: 'Medium',
        estimated_time: `${score.breakdown.critical.open * 8} hours`,
        expected_score_increase: 100 * score.breakdown.critical.open,
        action: 'Assign to security team for immediate remediation'
      });
    }

    // Recommandation 2: Domaines à haut risque
    const highRiskDomains = heatmap.domains.filter(d => d.score < 500).length;
    if (highRiskDomains > 0) {
      recommendations.push({
        priority: 2,
        title: `Address ${highRiskDomains} High-Risk Domains`,
        impact: 'High',
        effort: 'High',
        estimated_time: `${highRiskDomains * 16} hours`,
        expected_score_increase: 50 * highRiskDomains,
        action: 'Prioritize scans and fixes for these domains'
      });
    }

    // Recommandation 3: Amélioration continue
    if (score.score < 900) {
      recommendations.push({
        priority: 3,
        title: 'Implement Continuous Security Monitoring',
        impact: 'Medium',
        effort: 'Low',
        estimated_time: '4 hours setup',
        expected_score_increase: 'Prevents degradation',
        action: 'Enable automated weekly scans and alerts'
      });
    }

    return recommendations.slice(0, 3);
  }

  /**
   * Compter les vulns fixées
   */
  countFixed(userId) {
    const result = db.prepare(`
      SELECT COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      AND v.status = 'fixed'
    `).get(userId);

    return result?.count || 0;
  }

  /**
   * Formater les nombres
   */
  formatNumber(num) {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
      return (num / 1000).toFixed(0) + 'K';
    }
    return num.toString();
  }

  /**
   * Générer un rapport board-ready (format simple)
   */
  generateBoardReport(userId) {
    const summary = this.generateExecutiveSummary(userId);
    
    return {
      title: 'Security Status Report',
      date: new Date().toISOString().split('T')[0],
      
      overview: {
        status: summary.executive_summary.headline,
        score: `${summary.key_metrics.security_score}/1000`,
        trend: summary.executive_summary.trend.improving ? '↑ Improving' : '↓ Declining'
      },

      key_findings: [
        `${summary.key_metrics.vulnerabilities_open} open vulnerabilities across ${summary.key_metrics.domains_protected} domains`,
        `${summary.risk_assessment.probability}% probability of security breach`,
        `Estimated financial exposure: $${this.formatNumber(summary.financial_impact.total_exposure)}`,
        `Currently performing better than ${summary.industry_comparison.percentile}% of organizations`
      ],

      recommendations: summary.top_recommendations.map(r => ({
        priority: `Priority ${r.priority}`,
        action: r.title,
        impact: r.impact,
        timeline: r.estimated_time
      })),

      financial_summary: {
        risk_exposure: `$${this.formatNumber(summary.financial_impact.total_exposure)}`,
        investment_needed: `$${this.formatNumber(summary.financial_impact.investment_required)}`,
        expected_roi: `${summary.roi_analysis.roi_percentage}%`,
        payback_period: summary.roi_analysis.payback_period_months 
          ? `${summary.roi_analysis.payback_period_months} months`
          : 'N/A'
      },

      next_steps: [
        'Review and approve recommended security investments',
        'Assign resources to address critical vulnerabilities',
        'Schedule quarterly security review with stakeholders',
        'Monitor progress against security score targets'
      ]
    };
  }

  /**
   * Générer des données pour export (CSV, etc.)
   */
  generateExportData(userId) {
    const summary = this.generateExecutiveSummary(userId);
    const heatmap = heatmapService.generateHeatmap(userId);

    // Format pour CSV export
    const csvData = {
      summary: [
        ['Metric', 'Value'],
        ['Security Score', summary.key_metrics.security_score],
        ['Industry Percentile', `${summary.key_metrics.industry_percentile}%`],
        ['Breach Probability', `${summary.key_metrics.breach_probability}%`],
        ['Financial Risk', `$${summary.key_metrics.financial_risk}`],
        ['Domains Protected', summary.key_metrics.domains_protected],
        ['Open Vulnerabilities', summary.key_metrics.vulnerabilities_open]
      ],
      
      domains: heatmap.domains.map(d => ({
        'Domain': d.domain_url,
        'Score': d.score,
        'Category': d.category,
        'Critical': d.critical_vulns,
        'High': d.high_vulns,
        'Medium': d.medium_vulns,
        'Total Vulnerabilities': d.total_vulnerabilities
      }))
    };

    return csvData;
  }
}

module.exports = new ExecutiveReportingService();
