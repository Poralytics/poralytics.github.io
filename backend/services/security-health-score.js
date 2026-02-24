/**
 * SECURITY HEALTH SCORE SERVICE
 * Calcule un score de sécurité de 0 à 1000 basé sur les vulnérabilités
 */

const db = require('../config/database');
const { logger } = require('../utils/error-handler');

class SecurityHealthScoreService {
  constructor() {
    // Poids par sévérité pour le calcul du score
    this.severityWeights = {
      critical: 100,
      high: 40,
      medium: 15,
      low: 5,
      info: 1
    };

    // Catégories de score
    this.scoreCategories = {
      excellent: { min: 900, max: 1000, label: 'Excellent', color: '#10b981' },
      good: { min: 750, max: 899, label: 'Good', color: '#3b82f6' },
      fair: { min: 500, max: 749, label: 'Fair', color: '#f59e0b' },
      poor: { min: 250, max: 499, label: 'Poor', color: '#ea580c' },
      critical: { min: 0, max: 249, label: 'Critical', color: '#dc2626' }
    };
  }

  /**
   * Calculer le score global d'un user
   */
  calculateUserScore(userId) {
    // Récupérer toutes les vulnérabilités du user
    const vulns = db.prepare(`
      SELECT v.severity, COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      AND v.status != 'fixed'
      GROUP BY v.severity
    `).all(userId);

    // Calculer le score
    let penaltyPoints = 0;
    let totalVulns = 0;

    vulns.forEach(v => {
      const weight = this.severityWeights[v.severity] || 0;
      penaltyPoints += weight * v.count;
      totalVulns += v.count;
    });

    // Score de base: 1000
    // On retire les pénalités
    let score = Math.max(0, 1000 - penaltyPoints);

    // Bonus pour 0 vulnérabilités
    if (totalVulns === 0) {
      score = 1000;
    }

    // Arrondir
    score = Math.round(score);

    // Déterminer la catégorie
    const category = this.getScoreCategory(score);

    return {
      score,
      category: category.label,
      color: category.color,
      total_vulnerabilities: totalVulns,
      breakdown: this.getVulnBreakdown(userId),
      trend: this.calculateTrend(userId),
      recommendations: this.generateRecommendations(score, vulns)
    };
  }

  /**
   * Calculer le score par domaine
   */
  calculateDomainScore(domainId) {
    const vulns = db.prepare(`
      SELECT v.severity, COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.domain_id = ?
      AND v.status != 'fixed'
      GROUP BY v.severity
    `).all(domainId);

    let penaltyPoints = 0;
    let totalVulns = 0;

    vulns.forEach(v => {
      const weight = this.severityWeights[v.severity] || 0;
      penaltyPoints += weight * v.count;
      totalVulns += v.count;
    });

    let score = Math.max(0, 1000 - penaltyPoints);
    if (totalVulns === 0) score = 1000;

    const category = this.getScoreCategory(score);

    return {
      domain_id: domainId,
      score: Math.round(score),
      category: category.label,
      color: category.color,
      total_vulnerabilities: totalVulns
    };
  }

  /**
   * Déterminer la catégorie du score
   */
  getScoreCategory(score) {
    for (const [key, cat] of Object.entries(this.scoreCategories)) {
      if (score >= cat.min && score <= cat.max) {
        return cat;
      }
    }
    return this.scoreCategories.critical;
  }

  /**
   * Breakdown par sévérité
   */
  getVulnBreakdown(userId) {
    const vulns = db.prepare(`
      SELECT 
        v.severity,
        COUNT(*) as count,
        SUM(CASE WHEN v.status = 'fixed' THEN 1 ELSE 0 END) as fixed
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      GROUP BY v.severity
    `).all(userId);

    const breakdown = {
      critical: { total: 0, fixed: 0, open: 0 },
      high: { total: 0, fixed: 0, open: 0 },
      medium: { total: 0, fixed: 0, open: 0 },
      low: { total: 0, fixed: 0, open: 0 },
      info: { total: 0, fixed: 0, open: 0 }
    };

    vulns.forEach(v => {
      if (breakdown[v.severity]) {
        breakdown[v.severity].total = v.count;
        breakdown[v.severity].fixed = v.fixed;
        breakdown[v.severity].open = v.count - v.fixed;
      }
    });

    return breakdown;
  }

  /**
   * Calculer la tendance (amélioration/dégradation)
   */
  calculateTrend(userId) {
    const now = Math.floor(Date.now() / 1000);
    const thirtyDaysAgo = now - (30 * 24 * 60 * 60);

    // Score il y a 30 jours
    const oldVulns = db.prepare(`
      SELECT v.severity, COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      AND s.created_at <= ?
      AND v.status != 'fixed'
      GROUP BY v.severity
    `).all(userId, thirtyDaysAgo);

    let oldPenalty = 0;
    oldVulns.forEach(v => {
      oldPenalty += (this.severityWeights[v.severity] || 0) * v.count;
    });
    const oldScore = Math.max(0, 1000 - oldPenalty);

    // Score actuel
    const currentVulns = db.prepare(`
      SELECT v.severity, COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      AND v.status != 'fixed'
      GROUP BY v.severity
    `).all(userId);

    let currentPenalty = 0;
    currentVulns.forEach(v => {
      currentPenalty += (this.severityWeights[v.severity] || 0) * v.count;
    });
    const currentScore = Math.max(0, 1000 - currentPenalty);

    const difference = currentScore - oldScore;
    const percentChange = oldScore === 0 ? 0 : Math.round((difference / oldScore) * 100);

    return {
      direction: difference > 0 ? 'up' : difference < 0 ? 'down' : 'stable',
      difference: Math.abs(difference),
      percent_change: Math.abs(percentChange),
      improving: difference > 0
    };
  }

  /**
   * Générer des recommandations
   */
  generateRecommendations(score, vulns) {
    const recommendations = [];

    // Recommandations basées sur le score
    if (score < 500) {
      recommendations.push({
        priority: 'critical',
        title: 'Immediate Action Required',
        description: 'Your security score is critically low. Focus on fixing critical and high severity vulnerabilities immediately.',
        action: 'Review critical vulnerabilities'
      });
    } else if (score < 750) {
      recommendations.push({
        priority: 'high',
        title: 'Improve Security Posture',
        description: 'Your security has room for improvement. Prioritize fixing high severity issues.',
        action: 'Address high severity issues'
      });
    }

    // Recommandations par sévérité
    vulns.forEach(v => {
      if (v.severity === 'critical' && v.count > 0) {
        recommendations.push({
          priority: 'critical',
          title: `${v.count} Critical Vulnerabilities Found`,
          description: 'Critical vulnerabilities pose immediate risk to your application.',
          action: 'Fix critical vulnerabilities'
        });
      }
    });

    // Recommandation générale si score élevé
    if (score >= 900) {
      recommendations.push({
        priority: 'info',
        title: 'Excellent Security Posture',
        description: 'Maintain your current practices and continue regular security scans.',
        action: 'Schedule monthly scans'
      });
    }

    return recommendations;
  }

  /**
   * Calculer le score historique (pour graphique)
   */
  getScoreHistory(userId, days = 30) {
    const history = [];
    const now = Math.floor(Date.now() / 1000);

    // Récupérer les scans des X derniers jours
    const scans = db.prepare(`
      SELECT id, created_at
      FROM scans
      WHERE user_id = ?
      AND created_at >= ?
      ORDER BY created_at ASC
    `).all(userId, now - (days * 24 * 60 * 60));

    scans.forEach(scan => {
      // Calculer le score à ce moment-là
      const vulns = db.prepare(`
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        WHERE scan_id = ?
        AND status != 'fixed'
        GROUP BY severity
      `).all(scan.id);

      let penalty = 0;
      vulns.forEach(v => {
        penalty += (this.severityWeights[v.severity] || 0) * v.count;
      });

      const score = Math.max(0, 1000 - penalty);

      history.push({
        date: scan.created_at,
        score: Math.round(score)
      });
    });

    return history;
  }

  /**
   * Comparaison avec l'industrie
   */
  getIndustryBenchmark(userId) {
    const userScore = this.calculateUserScore(userId).score;

    // Calculer la moyenne de tous les users (simulation industrie)
    const allScores = db.prepare(`
      SELECT DISTINCT u.id
      FROM users u
      JOIN scans s ON u.id = s.user_id
      LIMIT 100
    `).all();

    let totalScore = 0;
    let count = 0;

    allScores.forEach(u => {
      try {
        const score = this.calculateUserScore(u.id).score;
        totalScore += score;
        count++;
      } catch (err) {
        // Skip
      }
    });

    const industryAverage = count > 0 ? Math.round(totalScore / count) : 650;

    // Calculer le percentile
    let betterThan = 0;
    allScores.forEach(u => {
      try {
        const score = this.calculateUserScore(u.id).score;
        if (userScore > score) betterThan++;
      } catch (err) {
        // Skip
      }
    });

    const percentile = count > 0 ? Math.round((betterThan / count) * 100) : 50;

    return {
      your_score: userScore,
      industry_average: industryAverage,
      percentile,
      better_than_percent: percentile,
      message: percentile >= 75 
        ? 'You are performing better than most organizations'
        : percentile >= 50
        ? 'You are performing at an average level'
        : 'There is significant room for improvement'
    };
  }

  /**
   * Risk assessment détaillé
   */
  getRiskAssessment(userId) {
    const score = this.calculateUserScore(userId);
    const breakdown = score.breakdown;

    // Calculer le risque financier potentiel
    const financialRisk = 
      (breakdown.critical.open * 500000) +  // $500K per critical
      (breakdown.high.open * 100000) +      // $100K per high
      (breakdown.medium.open * 20000) +     // $20K per medium
      (breakdown.low.open * 5000);          // $5K per low

    // Probabilité de breach
    let breachProbability = 0;
    if (breakdown.critical.open > 0) breachProbability += 70;
    else if (breakdown.high.open > 0) breachProbability += 40;
    else if (breakdown.medium.open > 0) breachProbability += 15;
    breachProbability = Math.min(100, breachProbability);

    return {
      financial_risk: financialRisk,
      breach_probability: breachProbability,
      risk_level: breachProbability > 60 ? 'Critical' : 
                  breachProbability > 30 ? 'High' :
                  breachProbability > 10 ? 'Medium' : 'Low',
      time_to_breach: breakdown.critical.open > 0 ? 'Hours to days' :
                      breakdown.high.open > 0 ? 'Days to weeks' :
                      breakdown.medium.open > 0 ? 'Weeks to months' : 'Low risk'
    };
  }
}

module.exports = new SecurityHealthScoreService();
