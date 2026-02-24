/**
 * LICENSE & QUOTA ENFORCEMENT SERVICE
 * Gère les limitations par plan et force les upgrades
 */

const db = require('../config/database');
const { logger } = require('../utils/error-handler');
const crypto = require('crypto');

class LicenseService {
  constructor() {
    // Limites par plan
    this.limits = {
      free: {
        domains: 1,
        scans_per_month: 5,
        users: 1,
        api_calls_per_day: 0,
        features: {
          ai: false,
          compliance: false,
          api_access: false,
          integrations: false,
          white_label: false,
          sso: false
        }
      },
      starter: {
        domains: 10,
        scans_per_month: 100,
        users: 3,
        api_calls_per_day: 1000,
        features: {
          ai: false,
          compliance: false,
          api_access: false,
          integrations: true,
          white_label: false,
          sso: false
        }
      },
      professional: {
        domains: 50,
        scans_per_month: 500,
        users: 10,
        api_calls_per_day: 10000,
        features: {
          ai: true,
          compliance: false,
          api_access: true,
          integrations: true,
          white_label: false,
          sso: false
        }
      },
      business: {
        domains: 200,
        scans_per_month: 2000,
        users: 50,
        api_calls_per_day: 50000,
        features: {
          ai: true,
          compliance: true,
          api_access: true,
          integrations: true,
          white_label: true,
          sso: false
        }
      },
      enterprise: {
        domains: -1, // unlimited
        scans_per_month: -1,
        users: -1,
        api_calls_per_day: -1,
        features: {
          ai: true,
          compliance: true,
          api_access: true,
          integrations: true,
          white_label: true,
          sso: true
        }
      }
    };

    // Grace period (jours)
    this.gracePeriod = 3;
  }

  /**
   * Générer une clé de licence unique
   */
  generateLicenseKey(userId, plan) {
    const timestamp = Date.now();
    const data = `${userId}-${plan}-${timestamp}`;
    const hash = crypto.createHash('sha256').update(data).digest('hex');
    
    // Format: NEXUS-XXXX-XXXX-XXXX-XXXX
    const key = `NEXUS-${hash.substr(0, 4)}-${hash.substr(4, 4)}-${hash.substr(8, 4)}-${hash.substr(12, 4)}`.toUpperCase();
    
    return {
      key,
      hash,
      created_at: timestamp
    };
  }

  /**
   * Vérifier si un user peut effectuer une action
   */
  async canPerformAction(userId, actionType) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    
    if (!user) {
      return { allowed: false, reason: 'User not found' };
    }

    // Vérifier la suspension
    if (user.subscription_status === 'suspended') {
      return { 
        allowed: false, 
        reason: 'Account suspended due to payment failure',
        upgrade_required: true
      };
    }

    const plan = user.plan || 'free';
    const limits = this.limits[plan];

    // Switch selon le type d'action
    switch (actionType) {
      case 'add_domain':
        return this.checkDomainLimit(userId, limits);
      
      case 'start_scan':
        return this.checkScanLimit(userId, limits);
      
      case 'add_user':
        return this.checkUserLimit(userId, limits);
      
      case 'api_call':
        return this.checkApiLimit(userId, limits);
      
      default:
        return { allowed: true };
    }
  }

  /**
   * Vérifier limite domains
   */
  checkDomainLimit(userId, limits) {
    if (limits.domains === -1) {
      return { allowed: true, remaining: -1 };
    }

    const count = db.prepare(
      'SELECT COUNT(*) as count FROM domains WHERE user_id = ?'
    ).get(userId).count;

    const allowed = count < limits.domains;
    const remaining = Math.max(0, limits.domains - count);

    return {
      allowed,
      remaining,
      limit: limits.domains,
      usage: count,
      reason: allowed ? null : 'Domain limit reached',
      upgrade_required: !allowed
    };
  }

  /**
   * Vérifier limite scans
   */
  checkScanLimit(userId, limits) {
    if (limits.scans_per_month === -1) {
      return { allowed: true, remaining: -1 };
    }

    // Compter scans du mois en cours
    const monthStart = Math.floor(Date.now() / 1000) - (30 * 24 * 60 * 60);
    
    const count = db.prepare(`
      SELECT COUNT(*) as count 
      FROM scans 
      WHERE user_id = ? AND started_at > ?
    `).get(userId, monthStart).count;

    const allowed = count < limits.scans_per_month;
    const remaining = Math.max(0, limits.scans_per_month - count);

    // Grace period check
    if (!allowed) {
      const gracePeriodEnd = this.getGracePeriodEnd(userId);
      const now = Math.floor(Date.now() / 1000);
      
      if (gracePeriodEnd && now < gracePeriodEnd) {
        return {
          allowed: true,
          remaining: 0,
          in_grace_period: true,
          grace_ends_at: gracePeriodEnd,
          reason: `Grace period active until ${new Date(gracePeriodEnd * 1000).toLocaleString()}`
        };
      }
    }

    return {
      allowed,
      remaining,
      limit: limits.scans_per_month,
      usage: count,
      reason: allowed ? null : 'Scan limit reached for this month',
      upgrade_required: !allowed,
      percentage_used: Math.round((count / limits.scans_per_month) * 100)
    };
  }

  /**
   * Vérifier limite users
   */
  checkUserLimit(userId, limits) {
    if (limits.users === -1) {
      return { allowed: true, remaining: -1 };
    }

    const count = db.prepare(
      'SELECT COUNT(*) as count FROM organization_members WHERE organization_id = (SELECT organization_id FROM users WHERE id = ?)'
    ).get(userId).count || 1;

    const allowed = count < limits.users;
    const remaining = Math.max(0, limits.users - count);

    return {
      allowed,
      remaining,
      limit: limits.users,
      usage: count,
      reason: allowed ? null : 'User limit reached',
      upgrade_required: !allowed
    };
  }

  /**
   * Vérifier limite API calls
   */
  checkApiLimit(userId, limits) {
    if (limits.api_calls_per_day === -1) {
      return { allowed: true, remaining: -1 };
    }

    const dayStart = Math.floor(Date.now() / 1000) - (24 * 60 * 60);
    
    const count = db.prepare(`
      SELECT COUNT(*) as count 
      FROM api_calls 
      WHERE user_id = ? AND created_at > ?
    `).get(userId, dayStart)?.count || 0;

    const allowed = count < limits.api_calls_per_day;
    const remaining = Math.max(0, limits.api_calls_per_day - count);

    return {
      allowed,
      remaining,
      limit: limits.api_calls_per_day,
      usage: count,
      reason: allowed ? null : 'API call limit reached for today',
      upgrade_required: !allowed
    };
  }

  /**
   * Vérifier si un user a accès à une feature
   */
  canUseFeature(userId, featureName) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    
    if (!user) {
      return { allowed: false, reason: 'User not found' };
    }

    const plan = user.plan || 'free';
    const limits = this.limits[plan];
    const hasFeature = limits.features[featureName];

    return {
      allowed: hasFeature === true,
      reason: hasFeature ? null : `Feature '${featureName}' not available in ${plan} plan`,
      upgrade_required: !hasFeature,
      available_in: this.getLowestPlanWithFeature(featureName)
    };
  }

  /**
   * Obtenir le plan le plus bas qui a cette feature
   */
  getLowestPlanWithFeature(featureName) {
    const plans = ['starter', 'professional', 'business', 'enterprise'];
    
    for (const plan of plans) {
      if (this.limits[plan].features[featureName]) {
        return plan;
      }
    }
    
    return null;
  }

  /**
   * Obtenir la fin de la grace period
   */
  getGracePeriodEnd(userId) {
    const graceRecord = db.prepare(
      'SELECT grace_period_ends_at FROM users WHERE id = ?'
    ).get(userId);

    return graceRecord?.grace_period_ends_at || null;
  }

  /**
   * Activer grace period
   */
  activateGracePeriod(userId) {
    const gracePeriodEnd = Math.floor(Date.now() / 1000) + (this.gracePeriod * 24 * 60 * 60);
    
    db.prepare(`
      UPDATE users 
      SET grace_period_ends_at = ?, updated_at = ?
      WHERE id = ?
    `).run(gracePeriodEnd, Math.floor(Date.now() / 1000), userId);

    logger.logInfo('Grace period activated', { userId, ends_at: gracePeriodEnd });

    return gracePeriodEnd;
  }

  /**
   * Obtenir l'usage complet d'un user
   */
  getUsageStats(userId) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    
    if (!user) {
      throw new Error('User not found');
    }

    const plan = user.plan || 'free';
    const limits = this.limits[plan];

    // Compter tout
    const monthStart = Math.floor(Date.now() / 1000) - (30 * 24 * 60 * 60);
    const dayStart = Math.floor(Date.now() / 1000) - (24 * 60 * 60);

    const domains = db.prepare(
      'SELECT COUNT(*) as count FROM domains WHERE user_id = ?'
    ).get(userId).count;

    const scans = db.prepare(
      'SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND started_at > ?'
    ).get(userId, monthStart).count;

    const apiCalls = db.prepare(
      'SELECT COUNT(*) as count FROM api_calls WHERE user_id = ? AND created_at > ?'
    ).get(userId, dayStart)?.count || 0;

    return {
      plan,
      limits: {
        domains: limits.domains,
        scans_per_month: limits.scans_per_month,
        api_calls_per_day: limits.api_calls_per_day,
        users: limits.users
      },
      usage: {
        domains: {
          used: domains,
          limit: limits.domains,
          remaining: limits.domains === -1 ? -1 : Math.max(0, limits.domains - domains),
          percentage: limits.domains === -1 ? 0 : Math.round((domains / limits.domains) * 100)
        },
        scans: {
          used: scans,
          limit: limits.scans_per_month,
          remaining: limits.scans_per_month === -1 ? -1 : Math.max(0, limits.scans_per_month - scans),
          percentage: limits.scans_per_month === -1 ? 0 : Math.round((scans / limits.scans_per_month) * 100)
        },
        api_calls: {
          used: apiCalls,
          limit: limits.api_calls_per_day,
          remaining: limits.api_calls_per_day === -1 ? -1 : Math.max(0, limits.api_calls_per_day - apiCalls),
          percentage: limits.api_calls_per_day === -1 ? 0 : Math.round((apiCalls / limits.api_calls_per_day) * 100)
        }
      },
      features: limits.features,
      upgrade_recommended: this.shouldRecommendUpgrade(userId, limits)
    };
  }

  /**
   * Déterminer si on doit recommander un upgrade
   */
  shouldRecommendUpgrade(userId, limits) {
    const monthStart = Math.floor(Date.now() / 1000) - (30 * 24 * 60 * 60);
    
    const scans = db.prepare(
      'SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND started_at > ?'
    ).get(userId, monthStart).count;

    // Recommander upgrade si usage > 80%
    if (limits.scans_per_month !== -1 && scans / limits.scans_per_month > 0.8) {
      return {
        recommended: true,
        reason: 'You are using 80%+ of your scan quota',
        suggested_plan: this.getSuggestedUpgradePlan(limits)
      };
    }

    return { recommended: false };
  }

  /**
   * Suggérer le prochain plan
   */
  getSuggestedUpgradePlan(currentLimits) {
    const plans = ['free', 'starter', 'professional', 'business', 'enterprise'];
    
    for (let i = 0; i < plans.length - 1; i++) {
      if (JSON.stringify(this.limits[plans[i]]) === JSON.stringify(currentLimits)) {
        return plans[i + 1];
      }
    }
    
    return null;
  }

  /**
   * Enregistrer un API call
   */
  recordApiCall(userId, endpoint, method) {
    try {
      db.prepare(`
        INSERT INTO api_calls (user_id, endpoint, method, created_at)
        VALUES (?, ?, ?, ?)
      `).run(userId, endpoint, method, Math.floor(Date.now() / 1000));
    } catch (err) {
      // Table might not exist yet, ignore
      logger.logWarning('Could not record API call', { error: err.message });
    }
  }
}

module.exports = new LicenseService();
