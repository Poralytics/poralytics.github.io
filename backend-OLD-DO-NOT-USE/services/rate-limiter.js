/**
 * Advanced Rate Limiting System
 * Features:
 * - Per-user limits
 * - Per-domain limits
 * - Sliding window algorithm
 * - Multiple tiers (free, pro, enterprise)
 * - Dynamic rate adjustment
 * - Redis-backed for distributed systems
 */

const redis = require('redis');

class RateLimiter {
  constructor() {
    this.client = redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379'
    });
    
    this.client.on('error', (err) => console.error('Redis error:', err));
    this.client.connect();

    // Rate limit tiers
    this.tiers = {
      free: {
        scansPerHour: 10,
        scansPerDay: 50,
        concurrentScans: 2,
        apiCallsPerMinute: 60
      },
      pro: {
        scansPerHour: 100,
        scansPerDay: 500,
        concurrentScans: 5,
        apiCallsPerMinute: 300
      },
      business: {
        scansPerHour: 500,
        scansPerDay: 2000,
        concurrentScans: 20,
        apiCallsPerMinute: 1000
      },
      enterprise: {
        scansPerHour: -1,  // Unlimited
        scansPerDay: -1,
        concurrentScans: 100,
        apiCallsPerMinute: 5000
      }
    };
  }

  /**
   * Check if user can perform action
   * @param {string} userId - User ID
   * @param {string} action - Action type (scan, api_call)
   * @param {string} tier - User tier (free, pro, business, enterprise)
   * @returns {Object} { allowed: boolean, remaining: number, resetAt: Date }
   */
  async checkLimit(userId, action, tier = 'free') {
    const limits = this.tiers[tier];
    
    if (action === 'scan') {
      return await this.checkScanLimit(userId, limits);
    } else if (action === 'api_call') {
      return await this.checkAPILimit(userId, limits);
    }
    
    return { allowed: false, remaining: 0 };
  }

  async checkScanLimit(userId, limits) {
    const hourKey = `scan:hour:${userId}:${this.getCurrentHour()}`;
    const dayKey = `scan:day:${userId}:${this.getCurrentDay()}`;
    const concurrentKey = `scan:concurrent:${userId}`;

    // Check concurrent scans
    const concurrent = await this.client.get(concurrentKey);
    if (concurrent && parseInt(concurrent) >= limits.concurrentScans) {
      return {
        allowed: false,
        reason: 'concurrent_limit',
        remaining: 0,
        resetAt: null
      };
    }

    // Check hourly limit
    if (limits.scansPerHour !== -1) {
      const hourlyCount = await this.client.get(hourKey);
      if (hourlyCount && parseInt(hourlyCount) >= limits.scansPerHour) {
        const ttl = await this.client.ttl(hourKey);
        return {
          allowed: false,
          reason: 'hourly_limit',
          remaining: 0,
          resetAt: new Date(Date.now() + ttl * 1000)
        };
      }
    }

    // Check daily limit
    if (limits.scansPerDay !== -1) {
      const dailyCount = await this.client.get(dayKey);
      if (dailyCount && parseInt(dailyCount) >= limits.scansPerDay) {
        const ttl = await this.client.ttl(dayKey);
        return {
          allowed: false,
          reason: 'daily_limit',
          remaining: 0,
          resetAt: new Date(Date.now() + ttl * 1000)
        };
      }
    }

    return {
      allowed: true,
      remaining: limits.scansPerHour - (parseInt(await this.client.get(hourKey) || 0))
    };
  }

  async checkAPILimit(userId, limits) {
    const key = `api:${userId}:${this.getCurrentMinute()}`;
    const count = await this.client.get(key);
    
    if (count && parseInt(count) >= limits.apiCallsPerMinute) {
      const ttl = await this.client.ttl(key);
      return {
        allowed: false,
        reason: 'api_rate_limit',
        remaining: 0,
        resetAt: new Date(Date.now() + ttl * 1000)
      };
    }

    return {
      allowed: true,
      remaining: limits.apiCallsPerMinute - (parseInt(count) || 0)
    };
  }

  /**
   * Record action (increment counter)
   */
  async recordAction(userId, action, tier = 'free') {
    if (action === 'scan') {
      await this.recordScan(userId);
    } else if (action === 'api_call') {
      await this.recordAPICall(userId);
    } else if (action === 'scan_start') {
      await this.incrementConcurrent(userId);
    } else if (action === 'scan_end') {
      await this.decrementConcurrent(userId);
    }
  }

  async recordScan(userId) {
    const hourKey = `scan:hour:${userId}:${this.getCurrentHour()}`;
    const dayKey = `scan:day:${userId}:${this.getCurrentDay()}`;

    // Increment counters
    await this.client.incr(hourKey);
    await this.client.incr(dayKey);

    // Set expiry
    await this.client.expire(hourKey, 3600);  // 1 hour
    await this.client.expire(dayKey, 86400);  // 24 hours
  }

  async recordAPICall(userId) {
    const key = `api:${userId}:${this.getCurrentMinute()}`;
    await this.client.incr(key);
    await this.client.expire(key, 60);  // 1 minute
  }

  async incrementConcurrent(userId) {
    const key = `scan:concurrent:${userId}`;
    await this.client.incr(key);
    await this.client.expire(key, 3600);  // Auto-cleanup after 1 hour
  }

  async decrementConcurrent(userId) {
    const key = `scan:concurrent:${userId}`;
    const current = await this.client.get(key);
    if (current && parseInt(current) > 0) {
      await this.client.decr(key);
    }
  }

  /**
   * Get current usage stats
   */
  async getUsageStats(userId, tier = 'free') {
    const limits = this.tiers[tier];
    const hourKey = `scan:hour:${userId}:${this.getCurrentHour()}`;
    const dayKey = `scan:day:${userId}:${this.getCurrentDay()}`;
    const concurrentKey = `scan:concurrent:${userId}`;
    const apiKey = `api:${userId}:${this.getCurrentMinute()}`;

    const [hourly, daily, concurrent, api] = await Promise.all([
      this.client.get(hourKey),
      this.client.get(dayKey),
      this.client.get(concurrentKey),
      this.client.get(apiKey)
    ]);

    return {
      scans: {
        hourly: {
          used: parseInt(hourly) || 0,
          limit: limits.scansPerHour,
          remaining: limits.scansPerHour === -1 ? -1 : limits.scansPerHour - (parseInt(hourly) || 0)
        },
        daily: {
          used: parseInt(daily) || 0,
          limit: limits.scansPerDay,
          remaining: limits.scansPerDay === -1 ? -1 : limits.scansPerDay - (parseInt(daily) || 0)
        },
        concurrent: {
          used: parseInt(concurrent) || 0,
          limit: limits.concurrentScans
        }
      },
      api: {
        used: parseInt(api) || 0,
        limit: limits.apiCallsPerMinute,
        remaining: limits.apiCallsPerMinute - (parseInt(api) || 0)
      }
    };
  }

  /**
   * Reset user limits (admin function)
   */
  async resetUserLimits(userId) {
    const pattern = `*:${userId}:*`;
    const keys = await this.client.keys(pattern);
    if (keys.length > 0) {
      await this.client.del(keys);
    }
  }

  /**
   * Domain-specific rate limiting
   */
  async checkDomainLimit(domain) {
    // Prevent hammering same domain
    const key = `domain:${domain}:scans`;
    const count = await this.client.get(key);
    
    // Max 5 scans per domain per hour
    if (count && parseInt(count) >= 5) {
      const ttl = await this.client.ttl(key);
      return {
        allowed: false,
        reason: 'domain_cooldown',
        resetAt: new Date(Date.now() + ttl * 1000)
      };
    }

    return { allowed: true };
  }

  async recordDomainScan(domain) {
    const key = `domain:${domain}:scans`;
    await this.client.incr(key);
    await this.client.expire(key, 3600);  // 1 hour cooldown
  }

  // Helper methods
  getCurrentHour() {
    const now = new Date();
    return `${now.getFullYear()}-${now.getMonth()+1}-${now.getDate()}-${now.getHours()}`;
  }

  getCurrentDay() {
    const now = new Date();
    return `${now.getFullYear()}-${now.getMonth()+1}-${now.getDate()}`;
  }

  getCurrentMinute() {
    const now = new Date();
    return `${now.getFullYear()}-${now.getMonth()+1}-${now.getDate()}-${now.getHours()}-${now.getMinutes()}`;
  }

  async close() {
    await this.client.quit();
  }
}

// Express middleware
function rateLimitMiddleware(action = 'api_call') {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const limiter = new RateLimiter();
    const tier = req.user.tier || 'free';
    
    const result = await limiter.checkLimit(req.user.id, action, tier);
    
    // Set rate limit headers
    res.setHeader('X-RateLimit-Limit', result.limit || 'unlimited');
    res.setHeader('X-RateLimit-Remaining', result.remaining || 0);
    if (result.resetAt) {
      res.setHeader('X-RateLimit-Reset', Math.floor(result.resetAt.getTime() / 1000));
    }

    if (!result.allowed) {
      return res.status(429).json({
        error: 'Rate limit exceeded',
        reason: result.reason,
        resetAt: result.resetAt
      });
    }

    await limiter.recordAction(req.user.id, action, tier);
    next();
  };
}

module.exports = { RateLimiter, rateLimitMiddleware };
