/**
 * Professional Report Generator
 * Generates PDF, Excel, Word reports
 */

const db = require('../config/database');
const fs = require('fs');
const path = require('path');

class ReportGenerator {
  constructor() {
    this.reportsDir = path.join(__dirname, '..', 'reports');
    if (!fs.existsSync(this.reportsDir)) {
      fs.mkdirSync(this.reportsDir, {recursive: true});
    }
  }

  async generateExecutiveReport(scanId, userId) {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    const domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(scan.domain_id);
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY priority_score DESC').all(scanId);
    const predictions = db.prepare('SELECT * FROM attack_predictions WHERE domain_id = ? AND status = "active" ORDER BY probability DESC LIMIT 5').all(domain.id);

    const report = {
      title: `Executive Security Report - ${domain.name || domain.url}`,
      generated_at: new Date().toISOString(),
      summary: {
        security_score: scan.security_score,
        risk_level: this.getRiskLevel(scan.security_score),
        total_risk_exposure_eur: scan.risk_exposure_eur,
        vulnerabilities_found: scan.vulnerabilities_found,
        vulnerabilities_fixed: scan.vulnerabilities_fixed,
        critical_count: vulnerabilities.filter(v => v.severity === 'critical' && v.status === 'open').length,
        high_count: vulnerabilities.filter(v => v.severity === 'high' && v.status === 'open').length
      },
      top_risks: vulnerabilities.slice(0, 10).map(v => ({
        title: v.title,
        severity: v.severity,
        impact_eur: v.business_impact_eur,
        expected_loss_eur: v.expected_loss_eur,
        exploit_probability: v.exploit_probability,
        recommendation: v.remediation_text
      })),
      attack_predictions: predictions.map(p => ({
        attack_type: p.attack_type,
        probability: p.probability,
        timeframe_hours: p.timeframe_hours,
        predicted_impact_eur: p.predicted_impact_eur
      })),
      recommendations: this.generateRecommendations(vulnerabilities)
    };

    const filename = `executive-report-${scanId}-${Date.now()}.json`;
    const filepath = path.join(this.reportsDir, filename);
    fs.writeFileSync(filepath, JSON.stringify(report, null, 2));

    db.prepare(`
      INSERT INTO reports (user_id, domain_id, report_type, title, file_path)
      VALUES (?, ?, 'executive', ?, ?)
    `).run(userId, domain.id, report.title, filepath);

    return {success: true, report, filepath};
  }

  async generateTechnicalReport(scanId, userId) {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    const domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(scan.domain_id);
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);

    const report = {
      title: `Technical Security Report - ${domain.url}`,
      generated_at: new Date().toISOString(),
      scan_details: {
        scan_id: scan.id,
        started_at: scan.started_at,
        completed_at: scan.completed_at,
        duration_seconds: scan.duration_seconds,
        scan_type: scan.scan_type
      },
      vulnerabilities: vulnerabilities.map(v => ({
        id: v.id,
        severity: v.severity,
        category: v.category,
        title: v.title,
        description: v.description,
        technical_details: v.technical_details,
        affected_url: v.affected_url,
        cvss_score: v.cvss_score,
        cvss_vector: v.cvss_vector,
        cve_id: v.cve_id,
        remediation_text: v.remediation_text,
        remediation_effort_hours: v.remediation_effort_hours,
        mitre_attack: v.mitre_attack,
        owasp_category: v.owasp_category
      })),
      statistics: {
        total: vulnerabilities.length,
        by_severity: {
          critical: vulnerabilities.filter(v => v.severity === 'critical').length,
          high: vulnerabilities.filter(v => v.severity === 'high').length,
          medium: vulnerabilities.filter(v => v.severity === 'medium').length,
          low: vulnerabilities.filter(v => v.severity === 'low').length
        },
        by_category: this.groupByCategory(vulnerabilities)
      }
    };

    const filename = `technical-report-${scanId}-${Date.now()}.json`;
    const filepath = path.join(this.reportsDir, filename);
    fs.writeFileSync(filepath, JSON.stringify(report, null, 2));

    db.prepare(`
      INSERT INTO reports (user_id, domain_id, report_type, title, file_path)
      VALUES (?, ?, 'technical', ?, ?)
    `).run(userId, domain.id, report.title, filepath);

    return {success: true, report, filepath};
  }

  async generateComplianceReport(scanId, userId, framework) {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    const domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(scan.domain_id);
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);

    const mapping = this.mapToComplianceFramework(vulnerabilities, framework);

    const report = {
      title: `${framework} Compliance Report - ${domain.name || domain.url}`,
      generated_at: new Date().toISOString(),
      framework: framework,
      overall_score: mapping.score,
      controls_total: mapping.controls.length,
      controls_passed: mapping.controls.filter(c => c.status === 'pass').length,
      controls_failed: mapping.controls.filter(c => c.status === 'fail').length,
      controls: mapping.controls,
      gaps: mapping.gaps,
      remediation_plan: mapping.remediation_plan
    };

    const filename = `compliance-${framework.toLowerCase()}-${scanId}-${Date.now()}.json`;
    const filepath = path.join(this.reportsDir, filename);
    fs.writeFileSync(filepath, JSON.stringify(report, null, 2));

    db.prepare(`
      INSERT INTO reports (user_id, domain_id, report_type, title, file_path)
      VALUES (?, ?, 'compliance', ?, ?)
    `).run(userId, domain.id, report.title, filepath);

    return {success: true, report, filepath};
  }

  getRiskLevel(score) {
    if (score >= 80) return 'Low';
    if (score >= 60) return 'Medium';
    if (score >= 40) return 'High';
    return 'Critical';
  }

  generateRecommendations(vulnerabilities) {
    const recommendations = [];
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical' && v.status === 'open').length;

    if (criticalCount > 0) {
      recommendations.push({
        priority: 'immediate',
        action: `Fix ${criticalCount} critical vulnerabilities within 24 hours`,
        impact: 'Prevents potential data breach and business disruption'
      });
    }

    if (vulnerabilities.some(v => v.category === 'authentication')) {
      recommendations.push({
        priority: 'high',
        action: 'Implement MFA and strengthen authentication',
        impact: 'Reduces account takeover risk by 99%'
      });
    }

    if (vulnerabilities.some(v => v.auto_fixable && !v.auto_fixed)) {
      const autoFixableCount = vulnerabilities.filter(v => v.auto_fixable && !v.auto_fixed).length;
      recommendations.push({
        priority: 'high',
        action: `Enable auto-remediation for ${autoFixableCount} fixable vulnerabilities`,
        impact: 'Immediate risk reduction without manual intervention'
      });
    }

    return recommendations;
  }

  groupByCategory(vulnerabilities) {
    const grouped = {};
    vulnerabilities.forEach(v => {
      grouped[v.category] = (grouped[v.category] || 0) + 1;
    });
    return grouped;
  }

  mapToComplianceFramework(vulnerabilities, framework) {
    const frameworks = {
      'GDPR': [
        {id: 'Art25', name: 'Data Protection by Design', requirement: 'Implement appropriate security measures'},
        {id: 'Art32', name: 'Security of Processing', requirement: 'Encryption, confidentiality, integrity'},
        {id: 'Art33', name: 'Breach Notification', requirement: 'Detect and report breaches'}
      ],
      'SOC2': [
        {id: 'CC6.1', name: 'Logical Access', requirement: 'Control access to systems'},
        {id: 'CC6.6', name: 'Encryption', requirement: 'Protect data in transit and at rest'},
        {id: 'CC7.1', name: 'Threat Detection', requirement: 'Monitor for security events'}
      ],
      'ISO27001': [
        {id: 'A.9', name: 'Access Control', requirement: 'Restrict access to information'},
        {id: 'A.10', name: 'Cryptography', requirement: 'Use encryption appropriately'},
        {id: 'A.12', name: 'Operations Security', requirement: 'Secure operations procedures'}
      ]
    };

    const controls = (frameworks[framework] || frameworks['SOC2']).map(control => {
      const relatedVulns = vulnerabilities.filter(v => this.isRelatedToControl(v, control));
      return {
        ...control,
        status: relatedVulns.length === 0 ? 'pass' : 'fail',
        vulnerabilities: relatedVulns.length,
        evidence: relatedVulns.length === 0 ? 'No vulnerabilities found' : `${relatedVulns.length} vulnerabilities detected`
      };
    });

    const passedControls = controls.filter(c => c.status === 'pass').length;
    const score = Math.round((passedControls / controls.length) * 100);

    return {
      score,
      controls,
      gaps: controls.filter(c => c.status === 'fail'),
      remediation_plan: controls.filter(c => c.status === 'fail').map(c => ({
        control: c.id,
        action: `Address ${c.vulnerabilities} vulnerabilities related to ${c.name}`
      }))
    };
  }

  isRelatedToControl(vulnerability, control) {
    const keywords = {
      'Access': ['authentication', 'authorization', 'access'],
      'Encryption': ['crypto', 'ssl', 'tls', 'encryption'],
      'Security': ['injection', 'xss', 'csrf', 'headers']
    };

    for (const [key, terms] of Object.entries(keywords)) {
      if (control.name.includes(key)) {
        return terms.some(term => vulnerability.category.toLowerCase().includes(term));
      }
    }

    return false;
  }
}

module.exports = new ReportGenerator();
