/**
 * COMPETITIVE INTELLIGENCE SERVICE
 * Compare votre sécurité vs industrie, benchmarks, best practices
 */

const { logger } = require('../utils/error-handler');

class CompetitiveIntelligenceService {
  constructor() {
    this.industryBenchmarks = this.loadIndustryBenchmarks();
    this.competitorData = this.loadCompetitorInsights();
  }

  loadIndustryBenchmarks() {
    return {
      'E-commerce': {
        avgSecurityScore: 720,
        avgVulnerabilities: 12,
        commonIssues: ['XSS in checkout', 'CSRF on payment', 'SQLi in search'],
        complianceRequired: ['PCI-DSS Level 1', 'GDPR'],
        avgBreachCost: 380000,
        avgTimeToDetect: 197 // days
      },
      'SaaS': {
        avgSecurityScore: 780,
        avgVulnerabilities: 8,
        commonIssues: ['Authentication bypass', 'IDOR', 'API rate limit bypass'],
        complianceRequired: ['SOC2 Type II', 'ISO 27001'],
        avgBreachCost: 520000,
        avgTimeToDetect: 212
      },
      'Finance': {
        avgSecurityScore: 850,
        avgVulnerabilities: 5,
        commonIssues: ['Session fixation', 'Weak crypto', 'Missing MFA'],
        complianceRequired: ['PCI-DSS', 'SOX', 'GLBA'],
        avgBreachCost: 750000,
        avgTimeToDetect: 180
      },
      'Healthcare': {
        avgSecurityScore: 810,
        avgVulnerabilities: 7,
        commonIssues: ['PHI exposure', 'Weak access control', 'Audit log gaps'],
        complianceRequired: ['HIPAA', 'HITECH'],
        avgBreachCost: 920000,
        avgTimeToDetect: 236
      },
      'Technology': {
        avgSecurityScore: 790,
        avgVulnerabilities: 9,
        commonIssues: ['API abuse', 'Rate limit bypass', 'OAuth misconfiguration'],
        complianceRequired: ['ISO 27001', 'SOC2'],
        avgBreachCost: 410000,
        avgTimeToDetect: 189
      }
    };
  }

  loadCompetitorInsights() {
    return {
      'Top 10%': {
        avgScore: 900,
        scanFrequency: 'Daily',
        avgTimeToFix: '< 24 hours',
        bugBounty: true,
        pentestFrequency: 'Quarterly',
        wafCoverage: '100%'
      },
      'Top 25%': {
        avgScore: 850,
        scanFrequency: 'Weekly',
        avgTimeToFix: '< 48 hours',
        bugBounty: true,
        pentestFrequency: 'Semi-annual',
        wafCoverage: '80%'
      },
      'Top 50%': {
        avgScore: 780,
        scanFrequency: 'Bi-weekly',
        avgTimeToFix: '< 1 week',
        bugBounty: false,
        pentestFrequency: 'Annual',
        wafCoverage: '50%'
      },
      'Below Average': {
        avgScore: 650,
        scanFrequency: 'Monthly',
        avgTimeToFix: '> 2 weeks',
        bugBounty: false,
        pentestFrequency: 'Never or > 2 years',
        wafCoverage: '< 25%'
      }
    };
  }

  /**
   * Analyse comparative vs industrie
   */
  compareToIndustry(scanResults, industry = 'Technology') {
    const benchmark = this.industryBenchmarks[industry] || this.industryBenchmarks['Technology'];
    const userScore = scanResults.security_score || 0;
    const userVulns = scanResults.total_vulns || 0;

    const comparison = {
      industry,
      yourScore: userScore,
      industryAverage: benchmark.avgSecurityScore,
      scoreDifference: userScore - benchmark.avgSecurityScore,
      percentile: this.calculatePercentile(userScore, benchmark.avgSecurityScore),
      
      yourVulnerabilities: userVulns,
      industryAverage: benchmark.avgVulnerabilities,
      
      commonIndustryIssues: benchmark.commonIssues,
      complianceRequired: benchmark.complianceRequired,
      
      riskAssessment: {
        averageBreachCost: `$${benchmark.avgBreachCost.toLocaleString()}`,
        averageDetectionTime: `${benchmark.avgTimeToDetect} days`,
        yourRiskLevel: this.calculateRiskLevel(userScore, userVulns, benchmark)
      },
      
      recommendations: this.generateIndustryRecommendations(userScore, userVulns, benchmark)
    };

    return comparison;
  }

  /**
   * Calcule le percentile (où vous vous situez vs concurrence)
   */
  calculatePercentile(score, avg) {
    const stdDev = 80; // Standard deviation estimée
    const zScore = (score - avg) / stdDev;
    
    // Conversion z-score to percentile
    if (zScore >= 1.5) return 'Top 10%';
    if (zScore >= 0.7) return 'Top 25%';
    if (zScore >= 0) return 'Top 50%';
    if (zScore >= -0.7) return 'Bottom 50%';
    return 'Bottom 25%';
  }

  /**
   * Calcule niveau de risque vs industrie
   */
  calculateRiskLevel(score, vulns, benchmark) {
    let riskScore = 0;

    // Score vs average
    if (score < benchmark.avgSecurityScore - 100) riskScore += 40;
    else if (score < benchmark.avgSecurityScore) riskScore += 20;
    
    // Vulns vs average
    if (vulns > benchmark.avgVulnerabilities * 2) riskScore += 40;
    else if (vulns > benchmark.avgVulnerabilities) riskScore += 20;

    // Critical vulns
    riskScore += Math.min(20, vulns * 2);

    if (riskScore >= 70) return 'CRITICAL - Below industry standards';
    if (riskScore >= 50) return 'HIGH - Underperforming peers';
    if (riskScore >= 30) return 'MEDIUM - At industry average';
    if (riskScore >= 10) return 'LOW - Above industry average';
    return 'MINIMAL - Industry leader';
  }

  /**
   * Recommandations basées sur industrie
   */
  generateIndustryRecommendations(score, vulns, benchmark) {
    const recs = [];

    if (score < benchmark.avgSecurityScore) {
      recs.push({
        priority: 'HIGH',
        action: `Improve score by ${benchmark.avgSecurityScore - score} points to match industry average`,
        timeline: '30 days',
        impact: 'Reduces competitive disadvantage'
      });
    }

    if (vulns > benchmark.avgVulnerabilities) {
      recs.push({
        priority: 'HIGH',
        action: `Reduce vulnerabilities from ${vulns} to ${benchmark.avgVulnerabilities} (industry avg)`,
        timeline: '60 days',
        impact: 'Aligns with peer security posture'
      });
    }

    benchmark.complianceRequired.forEach(comp => {
      recs.push({
        priority: 'MEDIUM',
        action: `Ensure ${comp} compliance`,
        timeline: '90 days',
        impact: 'Required for industry operations'
      });
    });

    recs.push({
      priority: 'MEDIUM',
      action: 'Implement continuous scanning (industry best practice)',
      timeline: '30 days',
      impact: 'Reduces average detection time from 200+ to < 24 hours'
    });

    return recs;
  }

  /**
   * Compare vs top performers
   */
  compareToTopPerformers(scanResults) {
    const userScore = scanResults.security_score || 0;
    const top10 = this.competitorData['Top 10%'];
    const top25 = this.competitorData['Top 25%'];

    const analysis = {
      yourPosition: this.determinePosition(userScore),
      gapToTop10: {
        scoreGap: top10.avgScore - userScore,
        practicesGap: this.identifyPracticeGaps(scanResults, top10),
        estimatedTimeToClose: this.estimateTimeToClose(userScore, top10.avgScore)
      },
      gapToTop25: {
        scoreGap: top25.avgScore - userScore,
        practicesGap: this.identifyPracticeGaps(scanResults, top25)
      },
      actionPlan: this.generateClosingPlan(userScore, top10)
    };

    return analysis;
  }

  determinePosition(score) {
    if (score >= 900) return 'Top 10%';
    if (score >= 850) return 'Top 25%';
    if (score >= 780) return 'Top 50%';
    return 'Below average';
  }

  identifyPracticeGaps(current, target) {
    const gaps = [];

    if (target.scanFrequency === 'Daily' && !current.dailyScans) {
      gaps.push('Implement daily automated scanning');
    }

    if (target.bugBounty && !current.bugBounty) {
      gaps.push('Launch bug bounty program');
    }

    if (target.wafCoverage === '100%' && (!current.wafCoverage || current.wafCoverage < 100)) {
      gaps.push('Deploy WAF across all endpoints');
    }

    gaps.push('Reduce mean time to remediation to < 24 hours');
    gaps.push('Implement quarterly penetration testing');

    return gaps;
  }

  estimateTimeToClose(currentScore, targetScore) {
    const gap = targetScore - currentScore;
    const avgImprovementPerMonth = 15; // points per month avec effort constant
    const months = Math.ceil(gap / avgImprovementPerMonth);
    return `${months} months with consistent security investment`;
  }

  generateClosingPlan(currentScore, target) {
    return [
      {
        phase: 'Month 1-2',
        goal: 'Quick wins',
        actions: [
          'Fix all critical vulnerabilities',
          'Implement automated scanning',
          'Deploy basic WAF',
          'Enable security headers'
        ],
        expectedScoreGain: '+30-50 points'
      },
      {
        phase: 'Month 3-4',
        goal: 'Process improvement',
        actions: [
          'Establish security champion program',
          'Implement secure SDLC',
          'Deploy secrets management',
          'Enable MFA organization-wide'
        ],
        expectedScoreGain: '+40-60 points'
      },
      {
        phase: 'Month 5-6',
        goal: 'Advanced security',
        actions: [
          'Launch bug bounty program',
          'Quarterly pentest schedule',
          'Security training for all devs',
          'Implement SIEM/SOAR'
        ],
        expectedScoreGain: '+50-70 points'
      }
    ];
  }

  /**
   * Génère un rapport exécutif compétitif
   */
  generateExecutiveReport(scanResults, industry = 'Technology') {
    const industryComparison = this.compareToIndustry(scanResults, industry);
    const competitorComparison = this.compareToTopPerformers(scanResults);

    return {
      executiveSummary: `
Your security score of ${scanResults.security_score} places you in the ${industryComparison.percentile} 
for the ${industry} industry. You are ${Math.abs(industryComparison.scoreDifference)} points 
${industryComparison.scoreDifference >= 0 ? 'above' : 'below'} the industry average.

To reach Top 10% performer status (900+ score), you need to close a gap of 
${competitorComparison.gapToTop10.scoreGap} points, estimated at 
${competitorComparison.gapToTop10.estimatedTimeToClose}.

Key risks:
- Potential breach cost: ${industryComparison.riskAssessment.averageBreachCost}
- Risk level: ${industryComparison.riskAssessment.yourRiskLevel}
- Compliance requirements: ${industryComparison.complianceRequired.join(', ')}
      `.trim(),
      
      industryComparison,
      competitorComparison,
      
      priorityActions: [
        ...industryComparison.recommendations.slice(0, 3),
        ...competitorComparison.gapToTop10.practicesGap.slice(0, 2).map(gap => ({
          priority: 'HIGH',
          action: gap,
          timeline: '60 days',
          impact: 'Closes gap to top performers'
        }))
      ],
      
      roadmapToTop10: competitorComparison.actionPlan
    };
  }
}

module.exports = new CompetitiveIntelligenceService();
