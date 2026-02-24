/**
 * Threat Intelligence Feed Aggregator
 * Real-time threat intelligence from multiple sources
 */

const axios = require('axios');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const db = require('../config/database');

class ThreatIntelligenceFeed {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    this.sources = {
      nvd: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
      github_advisories: 'https://api.github.com/advisories',
      alienvault_otx: 'https://otx.alienvault.com/api/v1/pulses/subscribed',
      cisa_alerts: 'https://www.cisa.gov/uscert/ncas/alerts.xml'
    };
    
    this.updateInterval = 3600000; // 1 hour
    this.lastUpdate = null;
  }

  async fetchNVDFeeds() {
    try {
      const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
      
      const response = await this.httpClient.get(this.sources.nvd, {
        params: {
          pubStartDate: since,
          resultsPerPage: 100
        },
        timeout: 10000
      });

      const vulnerabilities = response.data.vulnerabilities || [];
      
      return vulnerabilities.map(item => {
        const cve = item.cve;
        return {
          source: 'NVD',
          cve_id: cve.id,
          title: cve.descriptions?.[0]?.value || 'No description',
          severity: this.mapCVSSSeverity(cve.metrics),
          published_date: cve.published,
          description: cve.descriptions?.[0]?.value,
          cvss_score: cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore,
          affected_products: this.extractProducts(cve.configurations)
        };
      });
    } catch (error) {
      console.error('NVD feed error:', error.message);
      return [];
    }
  }

  async fetchGitHubAdvisories() {
    try {
      const response = await this.httpClient.get(this.sources.github_advisories, {
        headers: {
          'Accept': 'application/vnd.github+json',
          'Authorization': process.env.GITHUB_TOKEN ? `token ${process.env.GITHUB_TOKEN}` : undefined
        },
        params: {
          per_page: 50,
          state: 'published'
        },
        timeout: 10000
      });

      return response.data.map(advisory => ({
        source: 'GitHub Security Advisory',
        cve_id: advisory.cve_id,
        ghsa_id: advisory.ghsa_id,
        title: advisory.summary,
        severity: advisory.severity,
        published_date: advisory.published_at,
        description: advisory.description,
        affected_products: advisory.vulnerabilities?.map(v => v.package?.name).filter(Boolean),
        patched_versions: advisory.vulnerabilities?.map(v => v.patched_versions).flat().filter(Boolean)
      }));
    } catch (error) {
      console.error('GitHub advisories error:', error.message);
      return [];
    }
  }

  async fetchCustomThreats() {
    // Simulated real-time threat data (in production, connect to real feeds)
    return [
      {
        source: 'NEXUS Threat Intel',
        threat_type: 'active_exploit',
        title: 'Widespread SQLi Campaign Targeting E-commerce',
        severity: 'critical',
        published_date: new Date().toISOString(),
        description: 'Automated SQLi attacks targeting product search pages in e-commerce platforms.',
        indicators: ['GET /search?q=\' OR 1=1--', 'User-Agent: sqlmap/1.7'],
        affected_industries: ['retail', 'e-commerce'],
        mitigation: 'Deploy WAF rules, enable parameterized queries, monitor for SQLi patterns'
      },
      {
        source: 'NEXUS Threat Intel',
        threat_type: 'vulnerability_trend',
        title: 'XSS Vulnerabilities Increasing in React Applications',
        severity: 'high',
        published_date: new Date().toISOString(),
        description: 'DOM-based XSS through dangerouslySetInnerHTML misuse trending.',
        affected_products: ['React < 18.0', 'Next.js < 13.0'],
        mitigation: 'Audit React code for XSS sinks, implement DOMPurify, upgrade frameworks'
      }
    ];
  }

  async aggregateFeeds() {
    console.log('📡 Aggregating threat intelligence feeds...');

    const feeds = await Promise.allSettled([
      this.fetchNVDFeeds(),
      this.fetchGitHubAdvisories(),
      this.fetchCustomThreats()
    ]);

    let allThreats = [];

    feeds.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        allThreats = allThreats.concat(result.value);
      } else {
        console.error(`Feed ${index} failed:`, result.reason);
      }
    });

    console.log(`✅ Aggregated ${allThreats.length} threat intelligence items`);
    
    return allThreats;
  }

  async ingestThreats(threats) {
    console.log('💾 Ingesting threats into database...');

    const stmt = db.prepare(`
      INSERT OR REPLACE INTO threat_intelligence 
      (source, intel_type, severity, title, description, iocs, published_date, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
    `);

    let ingested = 0;

    threats.forEach(threat => {
      try {
        stmt.run(
          threat.source,
          threat.threat_type || 'vulnerability',
          threat.severity || 'medium',
          threat.title,
          threat.description,
          JSON.stringify(threat.indicators || []),
          threat.published_date
        );
        ingested++;
      } catch (error) {
        console.error('Ingest error:', error.message);
      }
    });

    console.log(`✅ Ingested ${ingested} threats`);
    this.lastUpdate = new Date();

    return ingested;
  }

  async correlateWithScans(domainId) {
    const threats = db.prepare(`
      SELECT * FROM threat_intelligence 
      WHERE status = 'active' 
      AND datetime(published_date) > datetime('now', '-30 days')
      ORDER BY severity DESC, published_date DESC
    `).all();

    const vulnerabilities = db.prepare(`
      SELECT DISTINCT category, title, description, cve_id 
      FROM vulnerabilities 
      WHERE domain_id = ? AND status = 'open'
    `).all(domainId);

    const correlations = [];

    vulnerabilities.forEach(vuln => {
      threats.forEach(threat => {
        const correlation = this.calculateCorrelation(vuln, threat);
        
        if (correlation.relevance_score > 0.5) {
          correlations.push({
            vulnerability: vuln,
            threat: threat,
            relevance_score: correlation.relevance_score,
            reasoning: correlation.reasoning
          });
        }
      });
    });

    return correlations.sort((a, b) => b.relevance_score - a.relevance_score);
  }

  calculateCorrelation(vuln, threat) {
    let score = 0;
    const reasons = [];

    // CVE match
    if (vuln.cve_id && threat.cve_id && vuln.cve_id === threat.cve_id) {
      score += 1.0;
      reasons.push('Exact CVE match');
    }

    // Category/type match
    const vulnCategory = vuln.category.toLowerCase();
    const threatType = (threat.intel_type || '').toLowerCase();
    const threatTitle = threat.title.toLowerCase();

    if (threatTitle.includes(vulnCategory) || threatType.includes(vulnCategory)) {
      score += 0.4;
      reasons.push('Category correlation');
    }

    // Keyword matching
    const vulnKeywords = this.extractKeywords(vuln.title + ' ' + vuln.description);
    const threatKeywords = this.extractKeywords(threat.title + ' ' + threat.description);
    
    const commonKeywords = vulnKeywords.filter(k => threatKeywords.includes(k));
    if (commonKeywords.length > 0) {
      score += Math.min(0.3, commonKeywords.length * 0.1);
      reasons.push(`${commonKeywords.length} keyword match(es)`);
    }

    // Severity correlation
    if (vuln.severity === threat.severity) {
      score += 0.1;
      reasons.push('Same severity level');
    }

    return {
      relevance_score: Math.min(1.0, score),
      reasoning: reasons.join(', ')
    };
  }

  extractKeywords(text) {
    if (!text) return [];
    const stopwords = ['the', 'is', 'at', 'which', 'on', 'in', 'to', 'a', 'an', 'and', 'or'];
    return text.toLowerCase()
      .replace(/[^\w\s]/g, ' ')
      .split(/\s+/)
      .filter(word => word.length > 3 && !stopwords.includes(word))
      .slice(0, 20);
  }

  mapCVSSSeverity(metrics) {
    const score = metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore || 0;
    
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  }

  extractProducts(configurations) {
    if (!configurations?.nodes) return [];
    
    const products = [];
    configurations.nodes.forEach(node => {
      node.cpeMatch?.forEach(match => {
        if (match.criteria) {
          products.push(match.criteria.split(':')[4]); // Extract product name
        }
      });
    });
    
    return [...new Set(products)].slice(0, 5);
  }

  async startAutoUpdate() {
    console.log('🔄 Starting automatic threat intelligence updates...');
    
    // Initial update
    await this.updateFeeds();

    // Schedule periodic updates
    setInterval(async () => {
      await this.updateFeeds();
    }, this.updateInterval);
  }

  async updateFeeds() {
    try {
      const threats = await this.aggregateFeeds();
      await this.ingestThreats(threats);
      
      console.log(`✅ Threat intelligence updated at ${new Date().toISOString()}`);
    } catch (error) {
      console.error('❌ Threat intelligence update failed:', error);
    }
  }

  async getActiveThreats(filters = {}) {
    let query = 'SELECT * FROM threat_intelligence WHERE status = ?';
    const params = ['active'];

    if (filters.severity) {
      query += ' AND severity = ?';
      params.push(filters.severity);
    }

    if (filters.since) {
      query += ' AND datetime(published_date) > datetime(?)';
      params.push(filters.since);
    }

    query += ' ORDER BY published_date DESC LIMIT ?';
    params.push(filters.limit || 50);

    return db.prepare(query).all(...params);
  }

  async getStats() {
    const stats = db.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical_count,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_count,
        SUM(CASE WHEN datetime(published_date) > datetime('now', '-24 hours') THEN 1 ELSE 0 END) as last_24h
      FROM threat_intelligence
      WHERE status = 'active'
    `).get();

    return {
      ...stats,
      last_update: this.lastUpdate,
      next_update: this.lastUpdate ? new Date(this.lastUpdate.getTime() + this.updateInterval) : null
    };
  }
}

module.exports = new ThreatIntelligenceFeed();
