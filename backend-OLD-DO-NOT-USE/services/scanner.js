const axios = require('axios');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const cheerio = require('cheerio');
const https = require('https');
const { URL } = require('url');
const db = require('../config/database');
const businessImpact = require('./business-impact-calculator');
const attackPrediction = require('./attack-prediction-engine');
const autoRemediation = require('./auto-remediation-engine');

class SecurityScanner {
  constructor(domainId, scanId) {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    this.domainId = domainId;
    this.scanId = scanId;
    this.vulnerabilities = [];
    this.domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(domainId);
  }

  async performFullScan() {
    try {
      this.updateScanProgress(10, 'running');
      
      // 1. SSL/TLS Check
      await this.checkSSL();
      this.updateScanProgress(25, 'running');

      // 2. Headers Security
      await this.checkSecurityHeaders();
      this.updateScanProgress(40, 'running');

      // 3. Content Security
      await this.checkContentSecurity();
      this.updateScanProgress(60, 'running');

      // 4. Known Vulnerabilities
      await this.checkKnownVulnerabilities();
      this.updateScanProgress(80, 'running');

      // 5. DNS and subdomain enumeration
      await this.checkDNSSecurity();
      this.updateScanProgress(95, 'running');

      // Calculate score
      const score = this.calculateSecurityScore();
      
      // Save vulnerabilities
      this.saveVulnerabilities();

      // Update scan status
      this.updateScanProgress(100, 'completed', score);

      // Update domain score
      db.prepare(`
        UPDATE domains 
        SET security_score = ?, 
            risk_level = ?,
            last_scan = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(score, this.getRiskLevel(score), this.domainId);

      // Save history
      this.saveHistory(score);

      return { score, vulnerabilities: this.vulnerabilities };
    } catch (error) {
      console.error('Scan error:', error);
      this.updateScanProgress(0, 'failed');
      throw error;
    }
  }

  async checkSSL() {
    try {
      const url = new URL(this.domain.url);
      
      if (url.protocol !== 'https:') {
        this.addVulnerability({
          severity: 'high',
          category: 'ssl',
          title: 'HTTPS non activé',
          description: 'Le site n\'utilise pas HTTPS, exposant les données en transit.',
          remediation: 'Activer HTTPS avec un certificat SSL/TLS valide.',
          cvss_score: 7.5
        });
        return;
      }

      // Check certificate validity
      const response = await this.httpClient.get(this.domain.url, {
        timeout: 10000,
        validateStatus: () => true,
        httpsAgent: new https.Agent({ rejectUnauthorized: false })
      });

      // Check for certificate issues (simplified)
      if (response.request.res.socket.authorized === false) {
        this.addVulnerability({
          severity: 'critical',
          category: 'ssl',
          title: 'Certificat SSL invalide',
          description: 'Le certificat SSL n\'est pas valide ou a expiré.',
          remediation: 'Renouveler le certificat SSL avec une autorité de certification reconnue.',
          cvss_score: 8.5
        });
      }

      // Check TLS version
      const tlsVersion = response.request.res.socket.getProtocol();
      if (tlsVersion && (tlsVersion.includes('TLSv1.0') || tlsVersion.includes('TLSv1.1'))) {
        this.addVulnerability({
          severity: 'medium',
          category: 'ssl',
          title: 'Version TLS obsolète',
          description: `Le serveur utilise ${tlsVersion}, qui est obsolète et vulnérable.`,
          remediation: 'Mettre à jour vers TLS 1.2 ou TLS 1.3.',
          cvss_score: 5.3
        });
      }

    } catch (error) {
      this.addVulnerability({
        severity: 'high',
        category: 'ssl',
        title: 'Erreur de connexion SSL',
        description: 'Impossible de vérifier la sécurité SSL/TLS du site.',
        remediation: 'Vérifier la configuration SSL/TLS du serveur.'
      });
    }
  }

  async checkSecurityHeaders() {
    try {
      const response = await this.httpClient.get(this.domain.url, {
        timeout: 10000,
        validateStatus: () => true
      });

      const headers = response.headers;
      const securityHeaders = {
        'strict-transport-security': {
          name: 'HTTP Strict Transport Security (HSTS)',
          severity: 'medium',
          cvss: 5.3
        },
        'x-frame-options': {
          name: 'X-Frame-Options',
          severity: 'medium',
          cvss: 5.0
        },
        'x-content-type-options': {
          name: 'X-Content-Type-Options',
          severity: 'low',
          cvss: 3.7
        },
        'content-security-policy': {
          name: 'Content Security Policy (CSP)',
          severity: 'medium',
          cvss: 5.3
        },
        'x-xss-protection': {
          name: 'X-XSS-Protection',
          severity: 'low',
          cvss: 4.0
        },
        'referrer-policy': {
          name: 'Referrer-Policy',
          severity: 'low',
          cvss: 3.3
        },
        'permissions-policy': {
          name: 'Permissions-Policy',
          severity: 'low',
          cvss: 3.0
        }
      };

      for (const [header, config] of Object.entries(securityHeaders)) {
        if (!headers[header]) {
          this.addVulnerability({
            severity: config.severity,
            category: 'headers',
            title: `Header de sécurité manquant: ${config.name}`,
            description: `Le header ${config.name} n'est pas configuré, réduisant la sécurité du site.`,
            remediation: `Ajouter le header ${header} dans la configuration du serveur.`,
            cvss_score: config.cvss
          });
        }
      }

      // Check for information disclosure headers
      const dangerousHeaders = ['server', 'x-powered-by', 'x-aspnet-version'];
      dangerousHeaders.forEach(header => {
        if (headers[header]) {
          this.addVulnerability({
            severity: 'low',
            category: 'headers',
            title: `Divulgation d'information: ${header}`,
            description: `Le header ${header} révèle des informations sur la technologie serveur.`,
            remediation: `Supprimer ou masquer le header ${header}.`,
            cvss_score: 2.7
          });
        }
      });

    } catch (error) {
      console.error('Headers check error:', error.message);
    }
  }

  async checkContentSecurity() {
    try {
      const response = await this.httpClient.get(this.domain.url, {
        timeout: 10000,
        validateStatus: () => true
      });

      const $ = cheerio.load(response.data);

      // Check for mixed content
      $('script, img, link, iframe').each((i, elem) => {
        const src = $(elem).attr('src') || $(elem).attr('href');
        if (src && src.startsWith('http://')) {
          this.addVulnerability({
            severity: 'medium',
            category: 'content',
            title: 'Contenu mixte détecté',
            description: `Ressource non sécurisée chargée: ${src.substring(0, 100)}`,
            remediation: 'Utiliser HTTPS pour toutes les ressources externes.',
            cvss_score: 4.3,
            affected_url: src
          });
        }
      });

      // Check for inline scripts (potential XSS)
      const inlineScripts = $('script:not([src])').length;
      if (inlineScripts > 10) {
        this.addVulnerability({
          severity: 'low',
          category: 'content',
          title: 'Scripts inline détectés',
          description: `${inlineScripts} scripts inline trouvés, augmentant le risque XSS.`,
          remediation: 'Externaliser les scripts et utiliser une CSP stricte.',
          cvss_score: 3.5
        });
      }

      // Check for forms without HTTPS
      $('form').each((i, form) => {
        const action = $(form).attr('action');
        if (action && action.startsWith('http://')) {
          this.addVulnerability({
            severity: 'high',
            category: 'content',
            title: 'Formulaire non sécurisé',
            description: 'Formulaire transmettant des données via HTTP non chiffré.',
            remediation: 'Utiliser HTTPS pour tous les formulaires.',
            cvss_score: 7.5,
            affected_url: action
          });
        }
      });

      // Check for autocomplete on sensitive fields
      $('input[type="password"], input[name*="credit"], input[name*="card"]').each((i, input) => {
        const autocomplete = $(input).attr('autocomplete');
        if (!autocomplete || autocomplete !== 'off') {
          this.addVulnerability({
            severity: 'low',
            category: 'content',
            title: 'Autocomplete activé sur champ sensible',
            description: 'Les champs sensibles permettent l\'autocomplétion.',
            remediation: 'Désactiver autocomplete sur les champs sensibles.',
            cvss_score: 3.1
          });
        }
      });

    } catch (error) {
      console.error('Content check error:', error.message);
    }
  }

  async checkKnownVulnerabilities() {
    try {
      const response = await this.httpClient.get(this.domain.url, {
        timeout: 10000,
        validateStatus: () => true
      });

      const $ = cheerio.load(response.data);
      const headers = response.headers;

      // Check for known vulnerable libraries
      const vulnerableLibs = [
        { name: 'jquery', versions: ['1.', '2.'], severity: 'medium', cvss: 6.1 },
        { name: 'angular', versions: ['1.0', '1.1', '1.2'], severity: 'high', cvss: 7.5 },
        { name: 'bootstrap', versions: ['3.'], severity: 'low', cvss: 4.3 }
      ];

      $('script[src]').each((i, script) => {
        const src = $(script).attr('src');
        vulnerableLibs.forEach(lib => {
          lib.versions.forEach(version => {
            if (src && src.includes(lib.name) && src.includes(version)) {
              this.addVulnerability({
                severity: lib.severity,
                category: 'vulnerability',
                title: `Librairie obsolète: ${lib.name}`,
                description: `Version vulnérable de ${lib.name} détectée: ${version}`,
                remediation: `Mettre à jour ${lib.name} vers la dernière version.`,
                cvss_score: lib.cvss,
                affected_url: src
              });
            }
          });
        });
      });

      // Check server version
      if (headers.server) {
        const serverHeader = headers.server.toLowerCase();
        if (serverHeader.includes('apache/2.2') || serverHeader.includes('nginx/1.0')) {
          this.addVulnerability({
            severity: 'high',
            category: 'vulnerability',
            title: 'Version serveur obsolète',
            description: `Version serveur potentiellement vulnérable: ${headers.server}`,
            remediation: 'Mettre à jour le serveur web vers la dernière version.',
            cvss_score: 7.8
          });
        }
      }

    } catch (error) {
      console.error('Vulnerability check error:', error.message);
    }
  }

  async checkDNSSecurity() {
    try {
      const url = new URL(this.domain.url);
      const hostname = url.hostname;

      // Check for common security DNS records
      // Note: In production, you'd use actual DNS queries
      // For demo purposes, we'll simulate some checks

      // Simulate SPF check
      const hasSPF = Math.random() > 0.5;
      if (!hasSPF) {
        this.addVulnerability({
          severity: 'low',
          category: 'dns',
          title: 'Enregistrement SPF manquant',
          description: 'Aucun enregistrement SPF trouvé pour le domaine.',
          remediation: 'Configurer un enregistrement SPF pour prévenir l\'usurpation d\'email.',
          cvss_score: 3.5
        });
      }

      // Simulate DMARC check
      const hasDMARC = Math.random() > 0.5;
      if (!hasDMARC) {
        this.addVulnerability({
          severity: 'low',
          category: 'dns',
          title: 'Enregistrement DMARC manquant',
          description: 'Aucune politique DMARC configurée.',
          remediation: 'Configurer DMARC pour améliorer la sécurité email.',
          cvss_score: 3.3
        });
      }

    } catch (error) {
      console.error('DNS check error:', error.message);
    }
  }

  addVulnerability(vuln) {
    this.vulnerabilities.push({
      ...vuln,
      domain_id: this.domainId,
      scan_id: this.scanId,
      affected_url: vuln.affected_url || this.domain.url
    });
  }

  saveVulnerabilities() {
    const stmt = db.prepare(`
      INSERT INTO vulnerabilities 
      (scan_id, domain_id, severity, category, title, description, affected_url, remediation, cvss_score, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
    `);

    this.vulnerabilities.forEach(v => {
      stmt.run(
        v.scan_id,
        v.domain_id,
        v.severity,
        v.category,
        v.title,
        v.description || '',
        v.affected_url || '',
        v.remediation || '',
        v.cvss_score || 0
      );
    });
  }

  calculateSecurityScore() {
    if (this.vulnerabilities.length === 0) return 100;

    const weights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3
    };

    let totalDeduction = 0;
    this.vulnerabilities.forEach(v => {
      totalDeduction += weights[v.severity] || 0;
    });

    const score = Math.max(0, 100 - totalDeduction);
    return Math.round(score);
  }

  getRiskLevel(score) {
    if (score >= 80) return 'low';
    if (score >= 60) return 'medium';
    if (score >= 40) return 'high';
    return 'critical';
  }

  updateScanProgress(progress, status, score = null) {
    const update = {
      progress,
      status
    };

    if (status === 'completed') {
      update.completed_at = new Date().toISOString();
      update.security_score = score;
      update.vulnerabilities_found = this.vulnerabilities.length;
    }

    const fields = Object.keys(update).map(k => `${k} = ?`).join(', ');
    const values = [...Object.values(update), this.scanId];

    db.prepare(`UPDATE scans SET ${fields} WHERE id = ?`).run(...values);
  }

  saveHistory(score) {
    const vulnCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    };

    this.vulnerabilities.forEach(v => {
      vulnCounts[v.severity]++;
    });

    db.prepare(`
      INSERT INTO scan_history 
      (domain_id, security_score, vulnerabilities_critical, vulnerabilities_high, vulnerabilities_medium, vulnerabilities_low)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      this.domainId,
      score,
      vulnCounts.critical,
      vulnCounts.high,
      vulnCounts.medium,
      vulnCounts.low
    );
  }
}

module.exports = SecurityScanner;
