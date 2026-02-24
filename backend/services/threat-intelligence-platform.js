/**
 * Threat Intelligence Platform
 * Communauté partage threat data en temps réel
 * 
 * INNOVATION: Collective Intelligence pour Sécurité
 * - Real-time threat feeds
 * - Community-sourced IOCs (Indicators of Compromise)
 * - Attack pattern sharing
 * - 0-day early warning system
 * - Threat actor profiling
 * - Reputation scoring
 * - Automated blocking
 * 
 * IMPACT: Network effect MASSIF - Plus d'users = Meilleure intelligence
 * MARKET: Threat intel = $10B market, dominated by expensive vendors
 * NEXUS: DEMOCRATIZE threat intelligence
 */

const db = require('../config/database');
const crypto = require('crypto');

class ThreatIntelligencePlatform {
  constructor() {
    // Threat categories
    this.threatCategories = [
      'malware',
      'ransomware',
      'phishing',
      'botnet',
      'ddos',
      'apt',
      'cryptomining',
      'data_breach',
      'zero_day'
    ];

    // IOC types
    this.iocTypes = [
      'ip_address',
      'domain',
      'url',
      'file_hash',
      'email',
      'user_agent',
      'ssl_cert'
    ];

    // Reputation scoring
    this.reputationScores = {
      malicious: -100,
      suspicious: -50,
      unknown: 0,
      trusted: 50,
      verified: 100
    };

    // Global threat feed (in-memory cache)
    this.threatFeed = new Map();
    
    // Initialize
    this.initializeThreatFeed();
  }

  /**
   * Submit threat intelligence from scan
   */
  async submitThreatIntelligence(userId, threatData) {
    const threatId = this.generateThreatId();

    // Validate threat data
    const validated = this.validateThreatData(threatData);

    if (!validated.isValid) {
      throw new Error(`Invalid threat data: ${validated.errors.join(', ')}`);
    }

    // Create threat entry
    const threat = {
      id: threatId,
      submitted_by: userId,
      category: threatData.category,
      severity: threatData.severity,
      
      // IOCs (Indicators of Compromise)
      iocs: JSON.stringify(threatData.iocs || []),
      
      // Attack details
      attack_vector: threatData.attackVector,
      attack_pattern: threatData.attackPattern,
      exploit_used: threatData.exploitUsed,
      
      // Technical details
      source_ip: threatData.sourceIp,
      target_url: threatData.targetUrl,
      payload: threatData.payload,
      user_agent: threatData.userAgent,
      
      // Metadata
      confidence: threatData.confidence || 'medium',
      first_seen: Date.now() / 1000,
      last_seen: Date.now() / 1000,
      occurrence_count: 1,
      
      // Community validation
      upvotes: 0,
      downvotes: 0,
      verified: false,
      
      created_at: Date.now() / 1000
    };

    // Save to database
    db.prepare(`
      INSERT INTO threat_intelligence (
        id, submitted_by, category, severity, iocs, attack_vector,
        attack_pattern, source_ip, target_url, confidence, 
        first_seen, last_seen, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      threat.id, threat.submitted_by, threat.category, threat.severity,
      threat.iocs, threat.attack_vector, threat.attack_pattern,
      threat.source_ip, threat.target_url, threat.confidence,
      threat.first_seen, threat.last_seen, threat.created_at
    );

    // Add to global feed
    this.addToThreatFeed(threat);

    // Notify community
    await this.notifyThreatDetected(threat);

    // Award points to submitter
    const GamificationSystem = require('./gamification-system');
    await GamificationSystem.awardPoints(userId, 'submitThreatIntel', 1);

    console.log(`🚨 Threat intelligence submitted: ${threat.category} - ${threat.severity}`);

    return {
      success: true,
      threatId,
      shared: true,
      communityPoints: 100
    };
  }

  /**
   * Check if IP/domain/URL is malicious
   */
  async checkReputation(indicator, type) {
    // Check local database
    const localThreats = db.prepare(`
      SELECT * FROM threat_intelligence 
      WHERE iocs LIKE ?
      ORDER BY last_seen DESC
      LIMIT 10
    `).all(`%${indicator}%`);

    if (localThreats.length > 0) {
      // Calculate reputation score
      const score = this.calculateReputationScore(localThreats);
      
      return {
        indicator,
        type,
        reputation: this.getReputationLevel(score),
        score,
        threats: localThreats.map(t => ({
          category: t.category,
          severity: t.severity,
          lastSeen: t.last_seen,
          confidence: t.confidence
        })),
        recommendation: this.getRecommendation(score)
      };
    }

    // Check global threat feed (community data)
    if (this.threatFeed.has(indicator)) {
      const threat = this.threatFeed.get(indicator);
      
      return {
        indicator,
        type,
        reputation: 'malicious',
        score: -100,
        threats: [threat],
        recommendation: 'BLOCK immediately - Known malicious'
      };
    }

    // No threat data found
    return {
      indicator,
      type,
      reputation: 'unknown',
      score: 0,
      threats: [],
      recommendation: 'Monitor - No threat data available'
    };
  }

  /**
   * Get real-time threat feed
   */
  async getThreatFeed(filters = {}) {
    let query = 'SELECT * FROM threat_intelligence WHERE 1=1';
    const params = [];

    if (filters.category) {
      query += ' AND category = ?';
      params.push(filters.category);
    }

    if (filters.severity) {
      query += ' AND severity = ?';
      params.push(filters.severity);
    }

    if (filters.since) {
      query += ' AND last_seen >= ?';
      params.push(filters.since);
    }

    if (filters.verified) {
      query += ' AND verified = 1';
    }

    query += ' ORDER BY last_seen DESC LIMIT ?';
    params.push(filters.limit || 100);

    const threats = db.prepare(query).all(...params);

    return {
      threats: threats.map(t => ({
        id: t.id,
        category: t.category,
        severity: t.severity,
        iocs: JSON.parse(t.iocs || '[]'),
        attackVector: t.attack_vector,
        confidence: t.confidence,
        lastSeen: t.last_seen,
        occurrences: t.occurrence_count,
        verified: t.verified === 1
      })),
      total: threats.length,
      updatedAt: Date.now()
    };
  }

  /**
   * Search threat intelligence
   */
  async searchThreats(query, options = {}) {
    const searchResults = db.prepare(`
      SELECT * FROM threat_intelligence 
      WHERE 
        category LIKE ? OR
        attack_vector LIKE ? OR
        attack_pattern LIKE ? OR
        source_ip LIKE ? OR
        target_url LIKE ?
      ORDER BY last_seen DESC
      LIMIT ?
    `).all(
      `%${query}%`, `%${query}%`, `%${query}%`,
      `%${query}%`, `%${query}%`,
      options.limit || 50
    );

    return {
      query,
      results: searchResults.length,
      threats: searchResults
    };
  }

  /**
   * Vote on threat intelligence (community validation)
   */
  async voteThreat(userId, threatId, vote) {
    if (vote !== 'up' && vote !== 'down') {
      throw new Error('Invalid vote');
    }

    // Check if already voted
    const existing = db.prepare(
      'SELECT * FROM threat_votes WHERE user_id = ? AND threat_id = ?'
    ).get(userId, threatId);

    if (existing) {
      throw new Error('Already voted on this threat');
    }

    // Record vote
    db.prepare(`
      INSERT INTO threat_votes (user_id, threat_id, vote, created_at)
      VALUES (?, ?, ?, ?)
    `).run(userId, threatId, vote, Date.now() / 1000);

    // Update threat counts
    if (vote === 'up') {
      db.prepare('UPDATE threat_intelligence SET upvotes = upvotes + 1 WHERE id = ?')
        .run(threatId);
    } else {
      db.prepare('UPDATE threat_intelligence SET downvotes = downvotes + 1 WHERE id = ?')
        .run(threatId);
    }

    // Check if should be verified (10+ upvotes, 0 downvotes)
    const threat = db.prepare('SELECT * FROM threat_intelligence WHERE id = ?').get(threatId);
    
    if (threat.upvotes >= 10 && threat.downvotes === 0 && !threat.verified) {
      db.prepare('UPDATE threat_intelligence SET verified = 1 WHERE id = ?').run(threatId);
      console.log(`✅ Threat ${threatId} verified by community`);
    }

    return { success: true };
  }

  /**
   * Get threat statistics
   */
  async getThreatStatistics(period = 'week') {
    const since = this.getPeriodTimestamp(period);

    const stats = {
      total: 0,
      byCategory: {},
      bySeverity: {},
      trending: [],
      topTargets: [],
      topSources: []
    };

    // Total threats
    const total = db.prepare(
      'SELECT COUNT(*) as count FROM threat_intelligence WHERE last_seen >= ?'
    ).get(since);
    stats.total = total.count;

    // By category
    const byCategory = db.prepare(`
      SELECT category, COUNT(*) as count 
      FROM threat_intelligence 
      WHERE last_seen >= ?
      GROUP BY category
      ORDER BY count DESC
    `).all(since);
    
    byCategory.forEach(row => {
      stats.byCategory[row.category] = row.count;
    });

    // By severity
    const bySeverity = db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM threat_intelligence 
      WHERE last_seen >= ?
      GROUP BY severity
      ORDER BY count DESC
    `).all(since);
    
    bySeverity.forEach(row => {
      stats.bySeverity[row.severity] = row.count;
    });

    // Trending threats (most occurrences in period)
    stats.trending = db.prepare(`
      SELECT category, attack_vector, COUNT(*) as occurrences
      FROM threat_intelligence
      WHERE last_seen >= ?
      GROUP BY category, attack_vector
      ORDER BY occurrences DESC
      LIMIT 10
    `).all(since);

    return stats;
  }

  /**
   * Automated threat blocking
   */
  async enableAutomatedBlocking(userId, config = {}) {
    const blockingId = this.generateBlockingId();

    // Configure automated blocking rules
    const rules = {
      id: blockingId,
      user_id: userId,
      enabled: true,
      
      // Thresholds
      block_malicious: config.blockMalicious !== false,
      block_suspicious: config.blockSuspicious || false,
      min_confidence: config.minConfidence || 'high',
      min_reputation_score: config.minReputationScore || -75,
      
      // Actions
      action_type: config.actionType || 'block', // block, alert, log
      notification: config.notification !== false,
      
      created_at: Date.now() / 1000
    };

    db.prepare(`
      INSERT INTO threat_blocking_rules (
        id, user_id, enabled, block_malicious, block_suspicious,
        min_confidence, action_type, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      rules.id, rules.user_id, rules.enabled, rules.block_malicious,
      rules.block_suspicious, rules.min_confidence, rules.action_type,
      rules.created_at
    );

    console.log(`🛡️ Automated threat blocking enabled for user ${userId}`);

    return {
      success: true,
      blockingId,
      rules
    };
  }

  /**
   * Export threat intelligence (STIX format)
   */
  async exportThreatIntel(threatIds, format = 'stix') {
    const threats = db.prepare(
      `SELECT * FROM threat_intelligence WHERE id IN (${threatIds.map(() => '?').join(',')})`
    ).all(...threatIds);

    if (format === 'stix') {
      return this.convertToSTIX(threats);
    } else if (format === 'json') {
      return threats;
    } else if (format === 'csv') {
      return this.convertToCSV(threats);
    }

    throw new Error('Unsupported format');
  }

  /**
   * Threat actor profiling
   */
  async getThreatActorProfile(actorId) {
    // Aggregate threat data by actor
    const profile = {
      actorId,
      name: 'Unknown Actor',
      
      // Activity
      totalAttacks: 0,
      firstSeen: null,
      lastSeen: null,
      
      // Tactics
      preferredVectors: [],
      targetedIndustries: [],
      attackPatterns: [],
      
      // IOCs
      knownIPs: [],
      knownDomains: [],
      
      // Sophistication
      sophisticationLevel: 'unknown',
      
      // Attribution
      suspectedOrigin: 'unknown',
      motivation: 'unknown'
    };

    // Query threats associated with actor
    // (would need actor tracking implementation)

    return profile;
  }

  /**
   * Helper methods
   */
  validateThreatData(data) {
    const errors = [];

    if (!data.category || !this.threatCategories.includes(data.category)) {
      errors.push('Invalid category');
    }

    if (!data.severity || !['critical', 'high', 'medium', 'low'].includes(data.severity)) {
      errors.push('Invalid severity');
    }

    if (!data.iocs || data.iocs.length === 0) {
      errors.push('At least one IOC required');
    }

    return {
      isValid: errors.length === 0,
      errors
    };
  }

  calculateReputationScore(threats) {
    let score = 0;
    
    threats.forEach(threat => {
      if (threat.verified) {
        score -= 50; // Verified threats heavily penalize
      }
      
      if (threat.severity === 'critical') score -= 40;
      else if (threat.severity === 'high') score -= 25;
      else if (threat.severity === 'medium') score -= 10;
      else score -= 5;
      
      // Confidence factor
      if (threat.confidence === 'high') score *= 1.5;
      else if (threat.confidence === 'low') score *= 0.5;
    });

    return Math.max(-100, Math.min(100, Math.round(score)));
  }

  getReputationLevel(score) {
    if (score <= -75) return 'malicious';
    if (score <= -25) return 'suspicious';
    if (score <= 25) return 'unknown';
    if (score <= 75) return 'trusted';
    return 'verified';
  }

  getRecommendation(score) {
    if (score <= -75) return 'BLOCK immediately - High confidence malicious';
    if (score <= -25) return 'ALERT and monitor - Suspicious activity';
    if (score <= 25) return 'LOG and watch - Unknown reputation';
    if (score <= 75) return 'ALLOW - Trusted source';
    return 'WHITELIST - Verified safe';
  }

  addToThreatFeed(threat) {
    // Add all IOCs to quick lookup
    const iocs = JSON.parse(threat.iocs || '[]');
    
    iocs.forEach(ioc => {
      this.threatFeed.set(ioc.value, {
        category: threat.category,
        severity: threat.severity,
        lastSeen: threat.last_seen
      });
    });
  }

  async notifyThreatDetected(threat) {
    // Notify all users with automated blocking enabled
    console.log(`🚨 Community threat alert: ${threat.category} - ${threat.severity}`);
  }

  getPeriodTimestamp(period) {
    const now = Date.now() / 1000;
    const periods = {
      day: 24 * 3600,
      week: 7 * 24 * 3600,
      month: 30 * 24 * 3600,
      year: 365 * 24 * 3600
    };
    
    return now - (periods[period] || periods.week);
  }

  convertToSTIX(threats) {
    // STIX 2.1 format conversion
    return {
      type: 'bundle',
      id: `bundle--${crypto.randomUUID()}`,
      objects: threats.map(t => ({
        type: 'indicator',
        id: `indicator--${t.id}`,
        created: new Date(t.created_at * 1000).toISOString(),
        modified: new Date(t.last_seen * 1000).toISOString(),
        pattern: this.createSTIXPattern(t),
        valid_from: new Date(t.first_seen * 1000).toISOString(),
        labels: [t.category, t.severity]
      }))
    };
  }

  createSTIXPattern(threat) {
    return `[ipv4-addr:value = '${threat.source_ip}']`;
  }

  convertToCSV(threats) {
    const headers = 'ID,Category,Severity,Source IP,Target URL,Last Seen\n';
    const rows = threats.map(t => 
      `${t.id},${t.category},${t.severity},${t.source_ip},${t.target_url},${t.last_seen}`
    ).join('\n');
    
    return headers + rows;
  }

  initializeThreatFeed() {
    // Load recent threats into memory
    const recentThreats = db.prepare(`
      SELECT * FROM threat_intelligence 
      WHERE last_seen >= ? 
      ORDER BY last_seen DESC 
      LIMIT 10000
    `).all(Date.now() / 1000 - (7 * 24 * 3600)); // Last 7 days

    recentThreats.forEach(threat => {
      this.addToThreatFeed(threat);
    });

    console.log(`✅ Threat feed initialized: ${this.threatFeed.size} indicators`);
  }

  generateThreatId() {
    return 'threat_' + crypto.randomBytes(8).toString('hex');
  }

  generateBlockingId() {
    return 'block_' + crypto.randomBytes(8).toString('hex');
  }
}

module.exports = new ThreatIntelligencePlatform();
