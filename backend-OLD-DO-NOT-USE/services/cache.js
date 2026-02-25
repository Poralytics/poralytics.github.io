/**
 * Intelligent Multi-Level Cache System
 * Features:
 * - L1: In-memory cache (fast, limited size)
 * - L2: Redis cache (distributed, persistent)
 * - Smart invalidation
 * - Cache warming
 * - Compression for large objects
 * - TTL management
 */

const redis = require('redis');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

class IntelligentCache {
  constructor(options = {}) {
    this.l1Cache = new Map();  // In-memory cache
    this.l1MaxSize = options.l1MaxSize || 100;  // Max 100 items in memory
    this.l1TTL = options.l1TTL || 60000;  // 1 minute default
    
    // Redis L2 cache
    this.redis = redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379'
    });
    this.redis.connect();
    
    this.compressionThreshold = options.compressionThreshold || 1024;  // 1KB
    
    // Cache statistics
    this.stats = {
      l1Hits: 0,
      l2Hits: 0,
      misses: 0,
      sets: 0,
      invalidations: 0
    };

    // Periodic L1 cleanup
    setInterval(() => this.cleanupL1(), 60000);  // Every minute
  }

  /**
   * Get from cache (checks L1 then L2)
   */
  async get(key, options = {}) {
    const cacheKey = this.generateKey(key);

    // Try L1 cache first
    const l1Result = this.getFromL1(cacheKey);
    if (l1Result !== null) {
      this.stats.l1Hits++;
      return l1Result;
    }

    // Try L2 cache (Redis)
    const l2Result = await this.getFromL2(cacheKey);
    if (l2Result !== null) {
      this.stats.l2Hits++;
      
      // Promote to L1 if hot
      if (!options.skipL1) {
        this.setToL1(cacheKey, l2Result, this.l1TTL);
      }
      
      return l2Result;
    }

    this.stats.misses++;
    return null;
  }

  /**
   * Set in cache (both L1 and L2)
   */
  async set(key, value, ttl = 3600) {
    const cacheKey = this.generateKey(key);
    this.stats.sets++;

    // Set in L1
    this.setToL1(cacheKey, value, Math.min(ttl * 1000, this.l1TTL));

    // Set in L2 (Redis)
    await this.setToL2(cacheKey, value, ttl);
  }

  /**
   * Delete from cache
   */
  async delete(key) {
    const cacheKey = this.generateKey(key);
    this.stats.invalidations++;

    // Delete from L1
    this.l1Cache.delete(cacheKey);

    // Delete from L2
    await this.redis.del(cacheKey);
  }

  /**
   * Delete multiple keys matching pattern
   */
  async deletePattern(pattern) {
    const keys = await this.redis.keys(pattern);
    if (keys.length > 0) {
      await this.redis.del(keys);
      this.stats.invalidations += keys.length;
    }

    // Also clean L1
    for (const [key] of this.l1Cache) {
      if (key.includes(pattern.replace('*', ''))) {
        this.l1Cache.delete(key);
      }
    }
  }

  /**
   * Cache-aside pattern: get or compute
   */
  async getOrCompute(key, computeFn, ttl = 3600) {
    // Try to get from cache
    let value = await this.get(key);
    
    if (value === null) {
      // Cache miss - compute value
      value = await computeFn();
      
      // Store in cache
      if (value !== null && value !== undefined) {
        await this.set(key, value, ttl);
      }
    }
    
    return value;
  }

  /**
   * Warm cache with data
   */
  async warm(entries) {
    for (const { key, value, ttl } of entries) {
      await this.set(key, value, ttl || 3600);
    }
  }

  /**
   * Get cache statistics
   */
  getStats() {
    const total = this.stats.l1Hits + this.stats.l2Hits + this.stats.misses;
    const hitRate = total > 0 ? ((this.stats.l1Hits + this.stats.l2Hits) / total * 100).toFixed(2) : 0;

    return {
      ...this.stats,
      hitRate: `${hitRate}%`,
      l1Size: this.l1Cache.size,
      total
    };
  }

  /**
   * Clear all caches
   */
  async clear() {
    this.l1Cache.clear();
    await this.redis.flushDb();
    this.resetStats();
  }

  resetStats() {
    this.stats = {
      l1Hits: 0,
      l2Hits: 0,
      misses: 0,
      sets: 0,
      invalidations: 0
    };
  }

  // L1 Cache operations
  getFromL1(key) {
    const item = this.l1Cache.get(key);
    if (!item) return null;

    // Check expiry
    if (Date.now() > item.expiry) {
      this.l1Cache.delete(key);
      return null;
    }

    return item.value;
  }

  setToL1(key, value, ttl) {
    // Evict oldest if cache is full
    if (this.l1Cache.size >= this.l1MaxSize) {
      const firstKey = this.l1Cache.keys().next().value;
      this.l1Cache.delete(firstKey);
    }

    this.l1Cache.set(key, {
      value,
      expiry: Date.now() + ttl
    });
  }

  cleanupL1() {
    const now = Date.now();
    for (const [key, item] of this.l1Cache) {
      if (now > item.expiry) {
        this.l1Cache.delete(key);
      }
    }
  }

  // L2 Cache operations (Redis)
  async getFromL2(key) {
    try {
      const data = await this.redis.get(key);
      if (!data) return null;

      const parsed = JSON.parse(data);
      
      // Decompress if needed
      if (parsed.compressed) {
        const decompressed = await gunzip(Buffer.from(parsed.data, 'base64'));
        return JSON.parse(decompressed.toString());
      }

      return parsed.data;
    } catch (error) {
      console.error('L2 cache get error:', error);
      return null;
    }
  }

  async setToL2(key, value, ttl) {
    try {
      const serialized = JSON.stringify(value);
      let toStore = { data: value, compressed: false };

      // Compress if large
      if (serialized.length > this.compressionThreshold) {
        const compressed = await gzip(serialized);
        toStore = {
          data: compressed.toString('base64'),
          compressed: true
        };
      }

      await this.redis.setEx(key, ttl, JSON.stringify(toStore));
    } catch (error) {
      console.error('L2 cache set error:', error);
    }
  }

  // Key generation
  generateKey(key) {
    if (typeof key === 'object') {
      return `cache:${crypto.createHash('md5').update(JSON.stringify(key)).digest('hex')}`;
    }
    return `cache:${key}`;
  }

  async close() {
    await this.redis.quit();
  }
}

// Middleware for auto-caching API responses
function cacheMiddleware(ttl = 60) {
  const cache = new IntelligentCache();

  return async (req, res, next) => {
    // Only cache GET requests
    if (req.method !== 'GET') {
      return next();
    }

    const cacheKey = `api:${req.originalUrl}`;
    
    // Try to get from cache
    const cached = await cache.get(cacheKey);
    if (cached) {
      res.setHeader('X-Cache', 'HIT');
      return res.json(cached);
    }

    // Intercept res.json
    const originalJson = res.json.bind(res);
    res.json = async function(data) {
      res.setHeader('X-Cache', 'MISS');
      
      // Cache the response
      await cache.set(cacheKey, data, ttl);
      
      return originalJson(data);
    };

    next();
  };
}

// Helper functions for common cache patterns
const CachePatterns = {
  // Cache scan results
  scanResults: (scanId) => `scan:${scanId}`,
  
  // Cache domain info
  domainInfo: (domainId) => `domain:${domainId}`,
  
  // Cache user data
  userData: (userId) => `user:${userId}`,
  
  // Cache analytics
  analytics: (type, period) => `analytics:${type}:${period}`,
  
  // Cache reports
  report: (reportId) => `report:${reportId}`
};

module.exports = { IntelligentCache, cacheMiddleware, CachePatterns };
