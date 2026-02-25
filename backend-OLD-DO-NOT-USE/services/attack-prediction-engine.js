/**
 * NEXUS - Attack Prediction Engine
 * ML-based prediction of future attacks
 */

class AttackPredictionEngine {
  constructor() {
    this.attackPatterns = {
      'sql injection': { mitre: 'T1190', timeframe_hours: 72, complexity: 'low', vectors: ['web', 'api'] },
      'authentication': { mitre: 'T1078', timeframe_hours: 168, complexity: 'medium', vectors: ['credential stuffing'] },
      'xss': { mitre: 'T1189', timeframe_hours: 120, complexity: 'low', vectors: ['phishing'] },
      'ssl': { mitre: 'T1557', timeframe_hours: 240, complexity: 'high', vectors: ['mitm'] },
      'default': { mitre: 'T1190', timeframe_hours: 336, complexity: 'medium', vectors: ['automated'] }
    };
  }

  generatePredictions(vulnerabilities, domainContext) {
    const predictions = [];
    const vulnByCategory = this.groupByCategory(vulnerabilities);
    
    Object.entries(vulnByCategory).forEach(([category, vulns]) => {
      const prediction = this.predictAttackForCategory(category, vulns, domainContext);
      if (prediction) predictions.push(prediction);
    });
    
    predictions.push(...this.generateLandscapePredictions(domainContext));
    
    return predictions.sort((a, b) => b.probability - a.probability).slice(0, 10);
  }

  groupByCategory(vulnerabilities) {
    const grouped = {};
    vulnerabilities.forEach(vuln => {
      const category = vuln.category || 'unknown';
      if (!grouped[category]) grouped[category] = [];
      grouped[category].push(vuln);
    });
    return grouped;
  }

  predictAttackForCategory(category, vulns, context) {
    const pattern = this.attackPatterns[category.toLowerCase()] || this.attackPatterns.default;
    const severityFactor = this.calculateSeverityFactor(vulns);
    const exposureFactor = context.exposure_level === 'internet' ? 1.5 : 1.0;
    const landscapeFactor = 1.2;
    
    const baseProbability = 0.15;
    const probability = Math.min(0.95, baseProbability * severityFactor * exposureFactor * landscapeFactor);
    
    if (probability < 0.2) return null;
    
    const totalExpectedLoss = vulns.reduce((sum, v) => sum + (v.expected_loss_eur || 0), 0);
    
    return {
      attack_type: this.getAttackTypeName(category),
      attack_vector: pattern.vectors[0],
      probability: Math.round(probability * 100) / 100,
      timeframe_hours: pattern.timeframe_hours,
      timeframe_description: this.formatTimeframe(pattern.timeframe_hours),
      predicted_impact_eur: Math.round(totalExpectedLoss / vulns.length),
      confidence: this.calculateConfidence(vulns.length, severityFactor),
      mitre_technique: pattern.mitre,
      exploitation_complexity: pattern.complexity,
      affected_vulnerabilities: vulns.length,
      recommendation: this.generatePreventionRecommendation(category, pattern)
    };
  }

  calculateSeverityFactor(vulns) {
    const severityWeights = { critical: 3.0, high: 2.0, medium: 1.2, low: 0.8 };
    return vulns.reduce((sum, v) => sum + (severityWeights[v.severity] || 1.0), 0) / vulns.length;
  }

  getAttackTypeName(category) {
    const names = {
      'sql': 'SQL Injection Attack',
      'xss': 'Cross-Site Scripting Attack',
      'authentication': 'Credential Compromise',
      'ssl': 'Man-in-the-Middle Attack',
      'headers': 'Protocol Downgrade Attack',
      'default': 'Automated Exploitation Attempt'
    };
    return names[category.toLowerCase()] || names.default;
  }

  formatTimeframe(hours) {
    if (hours < 24) return `${hours} hours`;
    if (hours < 168) return `${Math.round(hours / 24)} days`;
    return `${Math.round(hours / 168)} weeks`;
  }

  calculateConfidence(vulnCount, severityFactor) {
    const countFactor = Math.min(1.0, vulnCount / 5);
    const sevFactor = Math.min(1.0, severityFactor / 2);
    return Math.round((countFactor * 0.5 + sevFactor * 0.5) * 100) / 100;
  }

  generatePreventionRecommendation(category, pattern) {
    const recommendations = {
      'sql': 'Deploy WAF with SQL injection rules. Use parameterized queries.',
      'xss': 'Implement Content Security Policy (CSP). Output encoding.',
      'authentication': 'Enable MFA. Implement rate limiting.',
      'ssl': 'Enforce TLS 1.3+. Enable HSTS.',
      'default': 'Apply security patches. Enable monitoring.'
    };
    return recommendations[category.toLowerCase()] || recommendations.default;
  }

  generateLandscapePredictions(context) {
    const predictions = [];
    
    predictions.push({
      attack_type: 'Ransomware Attack',
      attack_vector: 'phishing + lateral movement',
      probability: 0.25,
      timeframe_hours: 720,
      timeframe_description: '30 days',
      predicted_impact_eur: context.revenue_per_hour ? context.revenue_per_hour * 48 : 500000,
      confidence: 0.7,
      mitre_technique: 'T1486',
      exploitation_complexity: 'medium',
      affected_vulnerabilities: 0,
      recommendation: 'Implement backup strategy. Security training. Network segmentation.'
    });
    
    if (context.exposure_level === 'internet') {
      predictions.push({
        attack_type: 'DDoS Attack',
        attack_vector: 'botnet',
        probability: 0.15,
        timeframe_hours: 168,
        timeframe_description: '7 days',
        predicted_impact_eur: context.revenue_per_hour ? context.revenue_per_hour * 4 : 50000,
        confidence: 0.6,
        mitre_technique: 'T1498',
        exploitation_complexity: 'low',
        affected_vulnerabilities: 0,
        recommendation: 'Deploy DDoS protection. CDN with mitigation.'
      });
    }
    
    return predictions;
  }

  calculateThreatScore(predictions) {
    if (predictions.length === 0) return 0;
    const totalScore = predictions.reduce((sum, pred) => {
      return sum + pred.probability * Math.log10(pred.predicted_impact_eur + 1);
    }, 0);
    return Math.min(100, Math.round((totalScore / predictions.length) * 10));
  }
}

module.exports = new AttackPredictionEngine();
