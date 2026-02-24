/**
 * COMPLIANCE AUTOMATION SERVICE
 * Automatise la conformité ISO 27001, PCI-DSS, SOC 2, GDPR, HIPAA
 */

const db = require('../config/database');
const scoreService = require('./security-health-score');
const { logger } = require('../utils/error-handler');

class ComplianceService {
  constructor() {
    // Standards supportés avec leurs contrôles
    this.standards = {
      iso27001: {
        name: 'ISO 27001:2022',
        description: 'Information Security Management System',
        controls: this.getISO27001Controls(),
        required_score: 750
      },
      pci_dss: {
        name: 'PCI-DSS 4.0',
        description: 'Payment Card Industry Data Security Standard',
        controls: this.getPCIDSSControls(),
        required_score: 850
      },
      soc2: {
        name: 'SOC 2 Type II',
        description: 'Trust Services Criteria',
        controls: this.getSOC2Controls(),
        required_score: 800
      },
      gdpr: {
        name: 'GDPR',
        description: 'General Data Protection Regulation',
        controls: this.getGDPRControls(),
        required_score: 700
      },
      hipaa: {
        name: 'HIPAA',
        description: 'Health Insurance Portability and Accountability Act',
        controls: this.getHIPAAControls(),
        required_score: 850
      }
    };
  }

  /**
   * Évaluer la conformité pour un standard
   */
  async assessCompliance(userId, standardId) {
    if (!this.standards[standardId]) {
      throw new Error(`Unknown standard: ${standardId}`);
    }

    const standard = this.standards[standardId];
    const score = scoreService.calculateUserScore(userId);
    
    // Mapper les vulnérabilités aux contrôles
    const controlAssessment = await this.mapVulnerabilitiesToControls(userId, standard);
    
    // Calculer le taux de conformité
    const complianceRate = this.calculateComplianceRate(controlAssessment);
    
    // Déterminer le statut
    const status = this.determineComplianceStatus(score.score, complianceRate, standard.required_score);
    
    // Générer les recommandations
    const recommendations = this.generateComplianceRecommendations(controlAssessment, standard);
    
    // Gaps identifiés
    const gaps = this.identifyComplianceGaps(controlAssessment);
    
    return {
      standard: standard.name,
      standard_id: standardId,
      assessment_date: new Date().toISOString(),
      status,
      compliance_rate: complianceRate,
      security_score: score.score,
      required_score: standard.required_score,
      controls: {
        total: controlAssessment.length,
        compliant: controlAssessment.filter(c => c.status === 'compliant').length,
        partial: controlAssessment.filter(c => c.status === 'partial').length,
        non_compliant: controlAssessment.filter(c => c.status === 'non_compliant').length
      },
      gaps,
      recommendations,
      next_assessment: this.calculateNextAssessmentDate()
    };
  }

  /**
   * Mapper les vulnérabilités aux contrôles du standard
   */
  async mapVulnerabilitiesToControls(userId, standard) {
    const vulns = db.prepare(`
      SELECT v.*, s.domain_id
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      AND v.status != 'fixed'
    `).all(userId);

    const controlAssessment = standard.controls.map(control => {
      // Trouver les vulnérabilités qui affectent ce contrôle
      const affectingVulns = vulns.filter(v => 
        this.doesVulnAffectControl(v, control)
      );

      // Déterminer le statut du contrôle
      let status = 'compliant';
      if (affectingVulns.some(v => v.severity === 'critical')) {
        status = 'non_compliant';
      } else if (affectingVulns.some(v => ['high', 'medium'].includes(v.severity))) {
        status = 'partial';
      }

      return {
        id: control.id,
        name: control.name,
        description: control.description,
        category: control.category,
        status,
        affecting_vulnerabilities: affectingVulns.length,
        evidence: this.generateControlEvidence(control, affectingVulns)
      };
    });

    return controlAssessment;
  }

  /**
   * Vérifier si une vulnérabilité affecte un contrôle
   */
  doesVulnAffectControl(vuln, control) {
    // Mapping simple basé sur le type de vulnérabilité
    const mapping = {
      sql_injection: ['A.8.1', 'A.8.2', 'A.14.2'],
      xss: ['A.8.2', 'A.14.2'],
      csrf: ['A.9.4', 'A.14.2'],
      authentication: ['A.9.2', 'A.9.4'],
      authorization: ['A.9.2', 'A.9.4'],
      encryption: ['A.10.1'],
      'session-management': ['A.9.4'],
      'input-validation': ['A.14.2']
    };

    const affectedControls = mapping[vuln.type] || [];
    return affectedControls.includes(control.id);
  }

  /**
   * Calculer le taux de conformité
   */
  calculateComplianceRate(controlAssessment) {
    const compliant = controlAssessment.filter(c => c.status === 'compliant').length;
    const partial = controlAssessment.filter(c => c.status === 'partial').length;
    const total = controlAssessment.length;

    // Conformité complète = 100%, partielle = 50%
    const rate = ((compliant + (partial * 0.5)) / total) * 100;
    return Math.round(rate);
  }

  /**
   * Déterminer le statut de conformité
   */
  determineComplianceStatus(score, complianceRate, requiredScore) {
    if (score >= requiredScore && complianceRate >= 90) {
      return 'compliant';
    } else if (score >= requiredScore * 0.8 && complianceRate >= 70) {
      return 'partially_compliant';
    } else {
      return 'non_compliant';
    }
  }

  /**
   * Identifier les gaps de conformité
   */
  identifyComplianceGaps(controlAssessment) {
    return controlAssessment
      .filter(c => c.status !== 'compliant')
      .map(c => ({
        control: c.id,
        name: c.name,
        status: c.status,
        vulnerabilities: c.affecting_vulnerabilities,
        priority: c.status === 'non_compliant' ? 'high' : 'medium',
        remediation_time: this.estimateRemediationTime(c)
      }))
      .sort((a, b) => {
        // Trier par priorité puis par nombre de vulnérabilités
        if (a.priority !== b.priority) {
          return a.priority === 'high' ? -1 : 1;
        }
        return b.vulnerabilities - a.vulnerabilities;
      });
  }

  /**
   * Générer des recommandations de conformité
   */
  generateComplianceRecommendations(controlAssessment, standard) {
    const recommendations = [];
    
    const nonCompliant = controlAssessment.filter(c => c.status === 'non_compliant');
    if (nonCompliant.length > 0) {
      recommendations.push({
        priority: 'critical',
        title: `Address ${nonCompliant.length} non-compliant controls`,
        description: `These controls are critical for ${standard.name} compliance`,
        controls: nonCompliant.map(c => c.id).slice(0, 5),
        estimated_effort: `${nonCompliant.length * 8} hours`
      });
    }

    const partial = controlAssessment.filter(c => c.status === 'partial');
    if (partial.length > 0) {
      recommendations.push({
        priority: 'high',
        title: `Strengthen ${partial.length} partially compliant controls`,
        description: 'These controls need additional remediation',
        controls: partial.map(c => c.id).slice(0, 5),
        estimated_effort: `${partial.length * 4} hours`
      });
    }

    // Recommandation pour automatisation
    recommendations.push({
      priority: 'medium',
      title: 'Enable continuous compliance monitoring',
      description: 'Set up automated scans and alerts to maintain compliance',
      action: 'Configure weekly automated scans'
    });

    return recommendations;
  }

  /**
   * Générer des preuves pour un contrôle
   */
  generateControlEvidence(control, affectingVulns) {
    if (affectingVulns.length === 0) {
      return {
        status: 'compliant',
        description: 'No vulnerabilities affecting this control',
        last_scan: new Date().toISOString(),
        artifacts: ['Security scan results', 'Vulnerability assessment']
      };
    }

    return {
      status: 'needs_remediation',
      description: `${affectingVulns.length} vulnerabilities affecting this control`,
      vulnerabilities: affectingVulns.map(v => ({
        id: v.id,
        type: v.type,
        severity: v.severity,
        url: v.url
      })),
      remediation_plan: 'Fix identified vulnerabilities',
      artifacts: ['Vulnerability reports', 'Remediation tickets']
    };
  }

  /**
   * Estimer le temps de remédiation
   */
  estimateRemediationTime(control) {
    const baseTime = 8; // heures
    const multiplier = control.status === 'non_compliant' ? 1.5 : 1;
    const vulnTime = control.affecting_vulnerabilities * 2;
    
    return `${Math.ceil((baseTime + vulnTime) * multiplier)} hours`;
  }

  /**
   * Calculer la date du prochain assessment
   */
  calculateNextAssessmentDate() {
    const next = new Date();
    next.setMonth(next.getMonth() + 3); // Tous les 3 mois
    return next.toISOString().split('T')[0];
  }

  /**
   * Générer un rapport d'audit
   */
  generateAuditReport(userId, standardId) {
    const assessment = this.assessCompliance(userId, standardId);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    
    return {
      report_id: `AUDIT-${standardId.toUpperCase()}-${Date.now()}`,
      organization: user.organization_name || 'Organization',
      standard: assessment.standard,
      report_date: new Date().toISOString(),
      auditor: 'NEXUS Compliance Engine',
      
      executive_summary: {
        status: assessment.status,
        compliance_rate: `${assessment.compliance_rate}%`,
        security_score: `${assessment.security_score}/1000`,
        critical_findings: assessment.gaps.filter(g => g.priority === 'high').length,
        recommendation: this.getExecutiveRecommendation(assessment)
      },
      
      detailed_findings: assessment.gaps,
      
      control_summary: assessment.controls,
      
      recommendations: assessment.recommendations,
      
      attestation: {
        statement: this.generateAttestationStatement(assessment),
        valid_until: this.calculateNextAssessmentDate(),
        conditions: this.getAttestationConditions(assessment)
      }
    };
  }

  /**
   * Obtenir recommandation executive
   */
  getExecutiveRecommendation(assessment) {
    if (assessment.status === 'compliant') {
      return 'Continue current security practices and maintain compliance through regular monitoring.';
    } else if (assessment.status === 'partially_compliant') {
      return `Address ${assessment.gaps.length} compliance gaps to achieve full compliance. Estimated effort: ${assessment.recommendations[0]?.estimated_effort || '40 hours'}.`;
    } else {
      return 'Immediate action required. Significant compliance gaps present serious risk. Recommend prioritizing critical controls.';
    }
  }

  /**
   * Générer déclaration d'attestation
   */
  generateAttestationStatement(assessment) {
    const status = assessment.status;
    const standard = assessment.standard;
    
    if (status === 'compliant') {
      return `This organization demonstrates compliance with ${standard} requirements as of ${new Date().toLocaleDateString()}. All critical controls are in place and functioning effectively.`;
    } else {
      return `This organization is working towards ${standard} compliance. Current compliance rate: ${assessment.compliance_rate}%. Remediation plan in progress.`;
    }
  }

  /**
   * Obtenir conditions d'attestation
   */
  getAttestationConditions(assessment) {
    const conditions = [
      'Maintain continuous security monitoring',
      'Address identified gaps within specified timeframes',
      'Conduct quarterly compliance assessments'
    ];

    if (assessment.status !== 'compliant') {
      conditions.push('Achieve 90%+ compliance rate within 90 days');
      conditions.push('Remediate all critical findings within 30 days');
    }

    return conditions;
  }

  // ========== CONTRÔLES PAR STANDARD ==========

  getISO27001Controls() {
    return [
      { id: 'A.5.1', name: 'Information Security Policies', category: 'Organizational', description: 'Policies for information security' },
      { id: 'A.8.1', name: 'Responsibility for Assets', category: 'Asset Management', description: 'Assets must be identified and protection responsibilities defined' },
      { id: 'A.8.2', name: 'Information Classification', category: 'Asset Management', description: 'Information should be classified' },
      { id: 'A.9.2', name: 'User Access Management', category: 'Access Control', description: 'Access to information and systems must be controlled' },
      { id: 'A.9.4', name: 'User Access Control', category: 'Access Control', description: 'Unauthorized access to systems and applications must be prevented' },
      { id: 'A.10.1', name: 'Cryptographic Controls', category: 'Cryptography', description: 'Policy on the use of cryptographic controls' },
      { id: 'A.12.1', name: 'Security Operations', category: 'Operations', description: 'Ensure correct and secure operations' },
      { id: 'A.14.2', name: 'Security in Development', category: 'Development', description: 'Security must be integrated into development' },
      { id: 'A.16.1', name: 'Incident Management', category: 'Incident Response', description: 'Ensure consistent and effective response to security incidents' },
      { id: 'A.18.1', name: 'Compliance Review', category: 'Compliance', description: 'Compliance with legal and regulatory requirements' }
    ];
  }

  getPCIDSSControls() {
    return [
      { id: 'REQ-1', name: 'Install and maintain firewall', category: 'Network Security', description: 'Firewall configuration to protect cardholder data' },
      { id: 'REQ-2', name: 'Secure configurations', category: 'System Security', description: 'Do not use vendor-supplied defaults' },
      { id: 'REQ-3', name: 'Protect stored data', category: 'Data Protection', description: 'Protect stored cardholder data' },
      { id: 'REQ-4', name: 'Encrypt transmission', category: 'Data Protection', description: 'Encrypt transmission of cardholder data' },
      { id: 'REQ-6', name: 'Secure applications', category: 'Application Security', description: 'Develop and maintain secure systems and applications' },
      { id: 'REQ-8', name: 'Identify users', category: 'Access Control', description: 'Identify and authenticate access' },
      { id: 'REQ-10', name: 'Track access', category: 'Monitoring', description: 'Track and monitor all access to network resources' },
      { id: 'REQ-11', name: 'Test security', category: 'Testing', description: 'Regularly test security systems and processes' }
    ];
  }

  getSOC2Controls() {
    return [
      { id: 'CC1.1', name: 'Control Environment', category: 'Common Criteria', description: 'Entity demonstrates commitment to integrity and ethical values' },
      { id: 'CC6.1', name: 'Logical Access', category: 'Common Criteria', description: 'Entity implements logical access controls' },
      { id: 'CC6.6', name: 'Vulnerability Management', category: 'Common Criteria', description: 'Entity identifies and manages vulnerabilities' },
      { id: 'CC7.1', name: 'Detection of Security Events', category: 'Common Criteria', description: 'Entity detects and responds to security events' },
      { id: 'A1.2', name: 'Availability Monitoring', category: 'Availability', description: 'Entity monitors system availability' }
    ];
  }

  getGDPRControls() {
    return [
      { id: 'ART-5', name: 'Data Processing Principles', category: 'Principles', description: 'Lawfulness, fairness, transparency' },
      { id: 'ART-25', name: 'Data Protection by Design', category: 'Technical Measures', description: 'Security measures integrated from the start' },
      { id: 'ART-32', name: 'Security of Processing', category: 'Security', description: 'Appropriate technical and organizational measures' },
      { id: 'ART-33', name: 'Breach Notification', category: 'Breach Management', description: 'Notification of personal data breach' }
    ];
  }

  getHIPAAControls() {
    return [
      { id: '164.308', name: 'Administrative Safeguards', category: 'Administrative', description: 'Security management process' },
      { id: '164.310', name: 'Physical Safeguards', category: 'Physical', description: 'Facility access controls' },
      { id: '164.312', name: 'Technical Safeguards', category: 'Technical', description: 'Access control, encryption, audit controls' },
      { id: '164.316', name: 'Policies and Procedures', category: 'Documentation', description: 'Documentation and updates' }
    ];
  }
}

module.exports = new ComplianceService();
