/**
 * NEXUS LEGENDARY - Advanced Security Scanner Engine
 * Orchestrates 20+ specialized security scanners
 */

const db = require('../config/database');
const businessImpact = require('./business-impact-calculator');
const attackPrediction = require('./attack-prediction-engine');
const autoRemediation = require('./auto-remediation-engine');

// Import specialized scanners
const SQLInjectionScanner = require('../scanners/sql-injection-scanner');
const XSSScanner = require('../scanners/xss-scanner');
const AuthScanner = require('../scanners/authentication-scanner');
const AccessControlScanner = require('../scanners/access-control-scanner');
const SSRFScanner = require('../scanners/ssrf-scanner');
const XXEScanner = require('../scanners/xxe-scanner');
const CommandInjectionScanner = require('../scanners/command-injection-scanner');
const CryptoScanner = require('../scanners/crypto-scanner');
const HeadersScanner = require('../scanners/headers-scanner');
const SSLScanner = require('../scanners/ssl-scanner');
const APISecurityScanner = require('../scanners/api-security-scanner');
const FileUploadScanner = require('../scanners/file-upload-scanner');
const BusinessLogicScanner = require('../scanners/business-logic-scanner');
const InfrastructureScanner = require('../scanners/infrastructure-scanner');
const ComponentScanner = require('../scanners/component-scanner');
const CORSScanner = require('../scanners/cors-scanner');
const CSRFScanner = require('../scanners/csrf-scanner');
const ClickjackingScanner = require('../scanners/clickjacking-scanner');
const OpenRedirectScanner = require('../scanners/open-redirect-scanner');
const InfoDisclosureScanner = require('../scanners/info-disclosure-scanner');

class LegendaryScanner {
  constructor(domainId, scanId) {
    this.domainId = domainId;
    this.scanId = scanId;
    this.vulnerabilities = [];
    this.domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(domainId);
    this.businessContext = this.loadBusinessContext();
    
    // Initialize all specialized scanners
    this.scanners = {
      sql: new SQLInjectionScanner(this.domain),
      xss: new XSSScanner(this.domain),
      auth: new AuthScanner(this.domain),
      access: new AccessControlScanner(this.domain),
      ssrf: new SSRFScanner(this.domain),
      xxe: new XXEScanner(this.domain),
      command: new CommandInjectionScanner(this.domain),
      crypto: new CryptoScanner(this.domain),
      headers: new HeadersScanner(this.domain),
      ssl: new SSLScanner(this.domain),
      api: new APISecurityScanner(this.domain),
      fileUpload: new FileUploadScanner(this.domain),
      businessLogic: new BusinessLogicScanner(this.domain),
      infrastructure: new InfrastructureScanner(this.domain),
      components: new ComponentScanner(this.domain),
      cors: new CORSScanner(this.domain),
      csrf: new CSRFScanner(this.domain),
      clickjacking: new ClickjackingScanner(this.domain),
      openRedirect: new OpenRedirectScanner(this.domain),
      infoDisclosure: new InfoDisclosureScanner(this.domain)
    };
  }

  loadBusinessContext() {
    const context = db.prepare(`
      SELECT bc.*, d.revenue_per_hour, d.business_value, d.criticality
      FROM business_context bc
      JOIN domains d ON d.user_id = bc.user_id
      WHERE d.id = ?
    `).get(this.domainId);

    return context || {
      revenue_per_hour: this.domain.revenue_per_hour || 15000,
      business_value: this.domain.business_value || 1000000,
      criticality: this.domain.criticality || 'medium',
      exposure_level: 'internet'
    };
  }

  async performLegendaryScan() {
    try {
      console.log(`🚀 Starting LEGENDARY scan for domain ${this.domain.url}`);
      
      // Phase 1: Infrastructure & Reconnaissance (0-15%)
      this.updateProgress(5, 'running', 'Infrastructure reconnaissance');
      await this.runScanner('infrastructure', 'Infrastructure Security');
      
      this.updateProgress(10, 'running', 'SSL/TLS analysis');
      await this.runScanner('ssl', 'SSL/TLS Configuration');
      
      this.updateProgress(15, 'running', 'Component analysis');
      await this.runScanner('components', 'Vulnerable Components');

      // Phase 2: Configuration & Headers (15-30%)
      this.updateProgress(20, 'running', 'Security headers');
      await this.runScanner('headers', 'Security Headers');
      
      this.updateProgress(25, 'running', 'CORS configuration');
      await this.runScanner('cors', 'CORS Misconfiguration');
      
      this.updateProgress(30, 'running', 'Cryptography');
      await this.runScanner('crypto', 'Cryptographic Issues');

      // Phase 3: Injection Vulnerabilities (30-50%)
      this.updateProgress(35, 'running', 'SQL injection testing');
      await this.runScanner('sql', 'SQL Injection');
      
      this.updateProgress(40, 'running', 'XSS testing');
      await this.runScanner('xss', 'Cross-Site Scripting');
      
      this.updateProgress(45, 'running', 'Command injection');
      await this.runScanner('command', 'OS Command Injection');
      
      this.updateProgress(50, 'running', 'XXE testing');
      await this.runScanner('xxe', 'XML External Entity');

      // Phase 4: Access Control & Authentication (50-65%)
      this.updateProgress(55, 'running', 'Authentication testing');
      await this.runScanner('auth', 'Authentication & Session');
      
      this.updateProgress(60, 'running', 'Access control');
      await this.runScanner('access', 'Broken Access Control');
      
      this.updateProgress(65, 'running', 'CSRF testing');
      await this.runScanner('csrf', 'Cross-Site Request Forgery');

      // Phase 5: Server-Side Attacks (65-75%)
      this.updateProgress(68, 'running', 'SSRF testing');
      await this.runScanner('ssrf', 'Server-Side Request Forgery');
      
      this.updateProgress(71, 'running', 'File upload security');
      await this.runScanner('fileUpload', 'File Upload Vulnerabilities');
      
      this.updateProgress(75, 'running', 'Information disclosure');
      await this.runScanner('infoDisclosure', 'Sensitive Data Exposure');

      // Phase 6: Client-Side & Business Logic (75-85%)
      this.updateProgress(78, 'running', 'Clickjacking');
      await this.runScanner('clickjacking', 'Clickjacking');
      
      this.updateProgress(81, 'running', 'Open redirects');
      await this.runScanner('openRedirect', 'Open Redirect');
      
      this.updateProgress(85, 'running', 'Business logic flaws');
      await this.runScanner('businessLogic', 'Business Logic Issues');

      // Phase 7: API Security (85-90%)
      this.updateProgress(88, 'running', 'API security');
      await this.runScanner('api', 'API Security (OWASP API Top 10)');

      // Phase 8: Business Impact & Intelligence (90-95%)
      this.updateProgress(90, 'running', 'Calculating business impact');
      this.calculateBusinessImpacts();
      
      this.updateProgress(92, 'running', 'Generating attack predictions');
      const predictions = attackPrediction.generatePredictions(this.vulnerabilities, this.businessContext);
      this.savePredictions(predictions);

      // Phase 9: Auto-Remediation (95-98%)
      this.updateProgress(95, 'running', 'Auto-remediation');
      await this.attemptAutoRemediation();

      // Phase 10: Finalization (98-100%)
      this.updateProgress(98, 'running', 'Finalizing scan');
      const score = this.calculateSecurityScore();
      const riskMetrics = this.calculateRiskMetrics();

      this.saveVulnerabilities();
      this.updateProgress(100, 'completed', 'Scan completed', score, riskMetrics);
      this.saveHistory(score, riskMetrics);
      
      console.log(`✅ LEGENDARY scan completed: ${this.vulnerabilities.length} vulnerabilities found`);
      
      return { 
        score, 
        vulnerabilities: this.vulnerabilities, 
        predictions,
        riskMetrics 
      };

    } catch (error) {
      console.error('❌ Legendary scan error:', error);
      this.updateProgress(0, 'failed', `Error: ${error.message}`);
      throw error;
    }
  }

  async runScanner(scannerKey, scannerName) {
    try {
      const scanner = this.scanners[scannerKey];
      if (!scanner) {
        console.warn(`⚠️  Scanner ${scannerKey} not found`);
        return;
      }

      console.log(`  🔍 Running ${scannerName}...`);
      const findings = await scanner.scan();
      
      if (findings && findings.length > 0) {
        console.log(`    ✓ Found ${findings.length} issue(s)`);
        findings.forEach(finding => {
          this.addVulnerability({
            ...finding,
            scanner: scannerName
          });
        });
      } else {
        console.log(`    ✓ No issues found`);
      }
    } catch (error) {
      console.error(`    ✗ Error in ${scannerName}:`, error.message);
      // Continue with other scanners even if one fails
    }
  }

  addVulnerability(vuln) {
    this.vulnerabilities.push({
      ...vuln,
      domain_id: this.domainId,
      scan_id: this.scanId,
      affected_url: vuln.affected_url || this.domain.url,
      discovered_at: new Date().toISOString()
    });
  }

  calculateBusinessImpacts() {
    console.log('  💰 Calculating business impacts...');
    this.vulnerabilities = this.vulnerabilities.map(vuln => {
      const impact = businessImpact.calculateImpact(vuln, this.businessContext);
      return {
        ...vuln,
        business_impact_eur: impact.business_impact_eur,
        exploit_probability: impact.exploit_probability,
        expected_loss_eur: impact.expected_loss_eur,
        priority_score: impact.priority_score
      };
    });
    console.log('    ✓ Business impacts calculated');
  }

  async attemptAutoRemediation() {
    console.log('  🤖 Attempting auto-remediation...');
    let autoFixedCount = 0;

    for (const vuln of this.vulnerabilities) {
      if (vuln.auto_fixable) {
        const result = await autoRemediation.attemptAutoFix(vuln);
        if (result.fixed) {
          vuln.auto_fixed = 1;
          vuln.status = 'fixed';
          autoFixedCount++;
        }
      }
    }

    db.prepare('UPDATE scans SET vulnerabilities_fixed = ? WHERE id = ?')
      .run(autoFixedCount, this.scanId);
    
    console.log(`    ✓ Auto-fixed ${autoFixedCount} vulnerabilities`);
  }

  savePredictions(predictions) {
    console.log('  🔮 Saving attack predictions...');
    const stmt = db.prepare(`
      INSERT INTO attack_predictions 
      (domain_id, attack_type, attack_vector, probability, timeframe_hours, predicted_impact_eur, confidence, mitre_technique)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    predictions.forEach(pred => {
      stmt.run(
        this.domainId,
        pred.attack_type,
        pred.attack_vector,
        pred.probability,
        pred.timeframe_hours,
        pred.predicted_impact_eur,
        pred.confidence,
        pred.mitre_technique
      );
    });
    console.log(`    ✓ Saved ${predictions.length} predictions`);
  }

  saveVulnerabilities() {
    console.log('  💾 Saving vulnerabilities to database...');
    const stmt = db.prepare(`
      INSERT INTO vulnerabilities 
      (scan_id, domain_id, severity, category, title, description, affected_url, 
       remediation_text, cvss_score, business_impact_eur, exploit_probability, 
       expected_loss_eur, auto_fixable, auto_fixed, priority_score, status, mitre_attack, owasp_category)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    this.vulnerabilities.forEach(v => {
      stmt.run(
        v.scan_id || this.scanId,
        v.domain_id || this.domainId,
        v.severity,
        v.category,
        v.title,
        v.description || '',
        v.affected_url || '',
        v.remediation_text || v.remediation || '',
        v.cvss_score || 0,
        v.business_impact_eur || 0,
        v.exploit_probability || 0,
        v.expected_loss_eur || 0,
        v.auto_fixable || 0,
        v.auto_fixed || 0,
        v.priority_score || 0,
        v.status || 'open',
        v.mitre_attack || '',
        v.owasp_category || ''
      );
    });
    console.log(`    ✓ Saved ${this.vulnerabilities.length} vulnerabilities`);
  }

  calculateSecurityScore() {
    if (this.vulnerabilities.filter(v => v.status === 'open').length === 0) return 100;

    const weights = { critical: 25, high: 15, medium: 8, low: 3 };
    let deduction = 0;

    this.vulnerabilities.forEach(v => {
      if (v.status === 'open') {
        deduction += weights[v.severity] || 0;
      }
    });

    return Math.max(0, 100 - deduction);
  }

  calculateRiskMetrics() {
    const openVulns = this.vulnerabilities.filter(v => v.status === 'open');
    const fixedVulns = this.vulnerabilities.filter(v => v.status === 'fixed');
    
    const totalRisk = openVulns.reduce((sum, v) => sum + (v.business_impact_eur || 0), 0);
    const totalExpectedLoss = openVulns.reduce((sum, v) => sum + (v.expected_loss_eur || 0), 0);

    return {
      total_risk_exposure_eur: Math.round(totalRisk),
      total_expected_loss_eur: Math.round(totalExpectedLoss),
      vulnerabilities_found: this.vulnerabilities.length,
      vulnerabilities_open: openVulns.length,
      vulnerabilities_fixed: fixedVulns.length
    };
  }

  updateProgress(progress, status, phase = '', score = null, metrics = null) {
    const update = { progress, status, phase };

    if (status === 'completed' && metrics) {
      update.completed_at = new Date().toISOString();
      update.security_score = score;
      update.vulnerabilities_found = metrics.vulnerabilities_found;
      update.risk_exposure_eur = metrics.total_risk_exposure_eur;
      update.duration_seconds = Math.floor((Date.now() - new Date(this.startTime).getTime()) / 1000);
    }

    const fields = Object.keys(update).map(k => `${k} = ?`).join(', ');
    const values = [...Object.values(update), this.scanId];

    db.prepare(`UPDATE scans SET ${fields} WHERE id = ?`).run(...values);
  }

  saveHistory(score, metrics) {
    const vulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    this.vulnerabilities.forEach(v => {
      if (v.status === 'open') vulnCounts[v.severity]++;
    });

    db.prepare(`
      INSERT INTO scan_history 
      (domain_id, security_score, risk_exposure_eur, vulnerabilities_total, 
       vulnerabilities_critical, vulnerabilities_high, vulnerabilities_medium, 
       vulnerabilities_low, vulnerabilities_fixed)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      this.domainId,
      score,
      metrics.total_risk_exposure_eur,
      metrics.vulnerabilities_found,
      vulnCounts.critical,
      vulnCounts.high,
      vulnCounts.medium,
      vulnCounts.low,
      metrics.vulnerabilities_fixed
    );
  }
}

module.exports = LegendaryScanner;
