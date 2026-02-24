/**
 * NEXUS - Business Impact Calculator
 * Converts technical vulnerabilities into financial risk
 */

class BusinessImpactCalculator {
  constructor() {
    this.breachCosts = {
      per_record: 150,
      legal_base: 50000,
      reputation_multiplier: 2.5
    };

    this.downtimeCosts = {
      small: 5000,
      medium: 15000,
      large: 50000,
      enterprise: 150000
    };
  }

  calculateImpact(vulnerability, domainContext) {
    const businessSize = this.determineBusinessSize(domainContext);
    const breachImpact = this.calculateBreachImpact(vulnerability, domainContext);
    const downtimeImpact = this.calculateDowntimeImpact(vulnerability, businessSize);
    const probability = this.calculateExploitProbability(vulnerability);
    
    const totalPotentialImpact = breachImpact + downtimeImpact;
    const expectedLoss = Math.round(totalPotentialImpact * probability);
    
    return {
      business_impact_eur: totalPotentialImpact,
      exploit_probability: probability,
      expected_loss_eur: expectedLoss,
      breakdown: {
        breach_cost: breachImpact,
        downtime_cost: downtimeImpact,
        legal_cost: this.breachCosts.legal_base,
        reputation_cost: Math.round(breachImpact * (this.breachCosts.reputation_multiplier - 1))
      },
      priority_score: this.calculatePriorityScore(expectedLoss, vulnerability.severity),
      recommendation: this.generateRecommendation(vulnerability, expectedLoss)
    };
  }

  determineBusinessSize(context) {
    if (!context || !context.revenue_per_hour) return 'medium';
    const hourlyRevenue = context.revenue_per_hour;
    if (hourlyRevenue > 100000) return 'enterprise';
    if (hourlyRevenue > 25000) return 'large';
    if (hourlyRevenue > 5000) return 'medium';
    return 'small';
  }

  calculateBreachImpact(vulnerability, context) {
    const dataBreachCategories = ['sql', 'authentication', 'access control', 'encryption', 'data'];
    const isDataBreachRisk = dataBreachCategories.some(cat => 
      vulnerability.category?.toLowerCase().includes(cat) ||
      vulnerability.title?.toLowerCase().includes(cat)
    );
    
    if (!isDataBreachRisk) return 0;
    
    const estimatedRecords = context.business_value ? context.business_value * 100 : 10000;
    const directCost = estimatedRecords * this.breachCosts.per_record;
    const legalCost = this.breachCosts.legal_base;
    const reputationCost = directCost * (this.breachCosts.reputation_multiplier - 1);
    
    return Math.round(directCost + legalCost + reputationCost);
  }

  calculateDowntimeImpact(vulnerability, businessSize) {
    const downtimeCategories = ['dos', 'denial', 'availability', 'server'];
    const isDowntimeRisk = downtimeCategories.some(cat => 
      vulnerability.category?.toLowerCase().includes(cat) ||
      vulnerability.title?.toLowerCase().includes(cat)
    );
    
    if (!isDowntimeRisk) return 0;
    
    const severityMultiplier = { critical: 8, high: 4, medium: 2, low: 0.5 };
    const estimatedHours = severityMultiplier[vulnerability.severity] || 2;
    const hourlyRate = this.downtimeCosts[businessSize];
    
    return Math.round(estimatedHours * hourlyRate);
  }

  calculateExploitProbability(vulnerability) {
    let probability = 0.1;
    
    const severityBonus = { critical: 0.6, high: 0.4, medium: 0.2, low: 0.1 };
    probability += severityBonus[vulnerability.severity] || 0.2;
    
    if (vulnerability.cvss_score) {
      probability += (vulnerability.cvss_score / 10) * 0.2;
    }
    
    if (vulnerability.affected_url && vulnerability.affected_url.startsWith('http')) {
      probability += 0.15;
    }
    
    if (vulnerability.cve_id) {
      probability += 0.1;
    }
    
    return Math.min(0.95, probability);
  }

  calculatePriorityScore(expectedLoss, severity) {
    const severityWeight = { critical: 10, high: 7, medium: 4, low: 2 };
    const financialScore = Math.log10(expectedLoss + 1) * 10;
    const severityScore = severityWeight[severity] || 5;
    
    return Math.round(financialScore + severityScore);
  }

  generateRecommendation(vulnerability, expectedLoss) {
    if (expectedLoss > 500000) {
      return {
        urgency: 'immediate',
        action: 'Drop everything - Fix within 24h',
        justification: `Risk exposure > 500K€. Potential business-critical impact.`
      };
    } else if (expectedLoss > 100000) {
      return {
        urgency: 'high',
        action: 'Prioritize - Fix within 7 days',
        justification: `Significant financial exposure. Schedule immediate remediation.`
      };
    } else if (expectedLoss > 20000) {
      return {
        urgency: 'medium',
        action: 'Plan - Fix within 30 days',
        justification: `Moderate risk. Include in next sprint.`
      };
    } else {
      return {
        urgency: 'low',
        action: 'Backlog - Fix when convenient',
        justification: `Low financial impact. Address during maintenance windows.`
      };
    }
  }

  calculateFixROI(vulnerability, fixEffortHours = 2) {
    const hourlyDeveloperCost = 100;
    const fixCost = fixEffortHours * hourlyDeveloperCost;
    const riskReduction = vulnerability.expected_loss_eur || 0;
    const roi = riskReduction > 0 ? ((riskReduction - fixCost) / fixCost) * 100 : 0;
    
    return {
      fix_cost_eur: fixCost,
      risk_reduction_eur: riskReduction,
      roi_percentage: Math.round(roi),
      payback_immediate: riskReduction > fixCost
    };
  }

  aggregateDomainRisk(vulnerabilities, domainContext) {
    let totalRiskExposure = 0;
    let totalExpectedLoss = 0;
    let criticalCount = 0;
    
    vulnerabilities.forEach(vuln => {
      const impact = this.calculateImpact(vuln, domainContext);
      totalRiskExposure += impact.business_impact_eur;
      totalExpectedLoss += impact.expected_loss_eur;
      if (vuln.severity === 'critical') criticalCount++;
    });
    
    return {
      total_risk_exposure_eur: Math.round(totalRiskExposure),
      total_expected_loss_eur: Math.round(totalExpectedLoss),
      critical_vulnerabilities: criticalCount,
      avg_exploit_probability: vulnerabilities.length > 0 
        ? vulnerabilities.reduce((sum, v) => sum + (v.exploit_probability || 0), 0) / vulnerabilities.length 
        : 0
    };
  }
}

module.exports = new BusinessImpactCalculator();
