/**
 * RISK HEATMAP SERVICE
 * Génère les données pour la visualisation du risque par domaine
 */

const db = require('../config/database');
const scoreService = require('./security-health-score');
const { logger } = require('../utils/error-handler');

class RiskHeatmapService {
  constructor() {
    // Configuration du heatmap
    this.riskLevels = {
      critical: { min: 0, max: 249, color: '#dc2626', label: 'Critical' },
      high: { min: 250, max: 499, color: '#ea580c', label: 'High Risk' },
      medium: { min: 500, max: 749, color: '#f59e0b', label: 'Medium Risk' },
      low: { min: 750, max: 899, color: '#3b82f6', label: 'Low Risk' },
      minimal: { min: 900, max: 1000, color: '#10b981', label: 'Minimal Risk' }
    };
  }

  /**
   * Générer les données du heatmap pour tous les domaines d'un user
   */
  generateHeatmap(userId) {
    // Récupérer tous les domaines
    const domains = db.prepare(`
      SELECT 
        d.id,
        d.url,
        d.name,
        d.created_at,
        (SELECT MAX(s.created_at) FROM scans s WHERE s.domain_id = d.id) as last_scan_at,
        (SELECT COUNT(*) FROM scans s WHERE s.domain_id = d.id) as total_scans
      FROM domains d
      WHERE d.user_id = ?
      ORDER BY d.created_at DESC
    `).all(userId);

    const heatmapData = domains.map(domain => {
      // Calculer le score du domaine
      const score = scoreService.calculateDomainScore(domain.id);
      
      // Déterminer le niveau de risque
      const riskLevel = this.getRiskLevel(score.score);
      
      // Compter les vulnérabilités actives
      const vulnStats = this.getDomainVulnStats(domain.id);
      
      return {
        domain_id: domain.id,
        domain_url: domain.url,
        domain_name: domain.name || domain.url,
        score: score.score,
        category: score.category,
        risk_level: riskLevel.label,
        risk_color: riskLevel.color,
        total_vulnerabilities: score.total_vulnerabilities,
        critical_vulns: vulnStats.critical,
        high_vulns: vulnStats.high,
        medium_vulns: vulnStats.medium,
        last_scan: domain.last_scan_at,
        total_scans: domain.total_scans,
        needs_attention: score.score < 500 || vulnStats.critical > 0
      };
    });

    return {
      domains: heatmapData,
      summary: this.generateSummary(heatmapData),
      grid: this.generateGrid(heatmapData)
    };
  }

  /**
   * Déterminer le niveau de risque basé sur le score
   */
  getRiskLevel(score) {
    for (const [key, level] of Object.entries(this.riskLevels)) {
      if (score >= level.min && score <= level.max) {
        return level;
      }
    }
    return this.riskLevels.critical;
  }

  /**
   * Statistiques des vulns d'un domaine
   */
  getDomainVulnStats(domainId) {
    const vulns = db.prepare(`
      SELECT 
        v.severity,
        COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.domain_id = ?
      AND v.status != 'fixed'
      GROUP BY v.severity
    `).all(domainId);

    const stats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    vulns.forEach(v => {
      if (stats[v.severity] !== undefined) {
        stats[v.severity] = v.count;
      }
    });

    return stats;
  }

  /**
   * Générer un résumé du heatmap
   */
  generateSummary(heatmapData) {
    const summary = {
      total_domains: heatmapData.length,
      by_risk_level: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        minimal: 0
      },
      needs_immediate_attention: 0,
      average_score: 0
    };

    let totalScore = 0;

    heatmapData.forEach(domain => {
      // Compter par niveau de risque
      const level = this.getRiskLevel(domain.score);
      for (const [key, levelDef] of Object.entries(this.riskLevels)) {
        if (level.label === levelDef.label) {
          summary.by_risk_level[key]++;
          break;
        }
      }

      // Compter ceux qui nécessitent attention
      if (domain.needs_attention) {
        summary.needs_immediate_attention++;
      }

      totalScore += domain.score;
    });

    summary.average_score = heatmapData.length > 0 
      ? Math.round(totalScore / heatmapData.length) 
      : 0;

    return summary;
  }

  /**
   * Générer une grille pour affichage visuel
   */
  generateGrid(heatmapData) {
    // Organiser en grille (max 6 colonnes)
    const columns = 6;
    const grid = [];
    
    for (let i = 0; i < heatmapData.length; i += columns) {
      grid.push(heatmapData.slice(i, i + columns));
    }

    return grid;
  }

  /**
   * Générer la timeline des incidents
   */
  generateTimeline(userId, days = 30) {
    const now = Math.floor(Date.now() / 1000);
    const startDate = now - (days * 24 * 60 * 60);

    // Récupérer tous les scans de la période
    const scans = db.prepare(`
      SELECT 
        s.id,
        s.domain_id,
        s.created_at,
        s.status,
        d.url as domain_url,
        (SELECT COUNT(*) FROM vulnerabilities v 
         WHERE v.scan_id = s.id AND v.status != 'fixed') as vulns_found
      FROM scans s
      JOIN domains d ON s.domain_id = d.id
      WHERE s.user_id = ?
      AND s.created_at >= ?
      ORDER BY s.created_at DESC
    `).all(userId, startDate);

    const timeline = scans.map(scan => {
      const vulnStats = db.prepare(`
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        WHERE scan_id = ?
        AND status != 'fixed'
        GROUP BY severity
      `).all(scan.id);

      const stats = { critical: 0, high: 0, medium: 0, low: 0 };
      vulnStats.forEach(v => {
        if (stats[v.severity] !== undefined) {
          stats[v.severity] = v.count;
        }
      });

      // Déterminer le type d'événement
      let eventType = 'scan_completed';
      let severity = 'info';
      
      if (stats.critical > 0) {
        eventType = 'critical_found';
        severity = 'critical';
      } else if (stats.high > 0) {
        eventType = 'high_found';
        severity = 'high';
      } else if (scan.vulns_found === 0) {
        eventType = 'clean_scan';
        severity = 'success';
      }

      return {
        timestamp: scan.created_at,
        event_type: eventType,
        severity,
        domain: scan.domain_url,
        domain_id: scan.domain_id,
        scan_id: scan.id,
        vulns_found: scan.vulns_found,
        breakdown: stats,
        message: this.generateEventMessage(eventType, scan.vulns_found, stats)
      };
    });

    return {
      timeline,
      summary: {
        total_events: timeline.length,
        critical_events: timeline.filter(e => e.severity === 'critical').length,
        clean_scans: timeline.filter(e => e.event_type === 'clean_scan').length
      }
    };
  }

  /**
   * Générer un message pour l'événement
   */
  generateEventMessage(eventType, vulnsFound, stats) {
    switch (eventType) {
      case 'critical_found':
        return `🔴 ${stats.critical} critical vulnerabilities detected`;
      case 'high_found':
        return `🟠 ${stats.high} high severity issues found`;
      case 'clean_scan':
        return `✅ No vulnerabilities detected`;
      default:
        return `📊 Scan completed: ${vulnsFound} issues found`;
    }
  }

  /**
   * Générer des données pour graphique de tendance
   */
  generateTrendData(userId, days = 30) {
    const now = Math.floor(Date.now() / 1000);
    const startDate = now - (days * 24 * 60 * 60);

    // Récupérer les scans avec leur score
    const scans = db.prepare(`
      SELECT 
        s.id,
        s.created_at,
        s.domain_id
      FROM scans s
      WHERE s.user_id = ?
      AND s.created_at >= ?
      ORDER BY s.created_at ASC
    `).all(userId, startDate);

    const trendData = scans.map(scan => {
      // Calculer le score à ce moment
      const vulns = db.prepare(`
        SELECT severity, COUNT(*) as count
        FROM vulnerabilities
        WHERE scan_id = ?
        AND status != 'fixed'
        GROUP BY severity
      `).all(scan.id);

      let penalty = 0;
      vulns.forEach(v => {
        const weights = { critical: 100, high: 40, medium: 15, low: 5, info: 1 };
        penalty += (weights[v.severity] || 0) * v.count;
      });

      const score = Math.max(0, 1000 - penalty);

      return {
        date: scan.created_at * 1000, // milliseconds pour Chart.js
        score: Math.round(score),
        scan_id: scan.id
      };
    });

    return trendData;
  }

  /**
   * Générer des données pour comparaison multi-domaines
   */
  generateDomainComparison(userId) {
    const domains = db.prepare(`
      SELECT id, url, name
      FROM domains
      WHERE user_id = ?
    `).all(userId);

    const comparison = domains.map(domain => {
      const score = scoreService.calculateDomainScore(domain.id);
      const stats = this.getDomainVulnStats(domain.id);
      
      // Calculer le dernier scan
      const lastScan = db.prepare(`
        SELECT created_at
        FROM scans
        WHERE domain_id = ?
        ORDER BY created_at DESC
        LIMIT 1
      `).get(domain.id);

      return {
        domain_id: domain.id,
        domain_name: domain.name || domain.url,
        domain_url: domain.url,
        score: score.score,
        category: score.category,
        critical: stats.critical,
        high: stats.high,
        medium: stats.medium,
        low: stats.low,
        total_vulns: score.total_vulnerabilities,
        last_scan: lastScan?.created_at || null
      };
    });

    // Trier par score (worst first)
    comparison.sort((a, b) => a.score - b.score);

    return comparison;
  }
}

module.exports = new RiskHeatmapService();
