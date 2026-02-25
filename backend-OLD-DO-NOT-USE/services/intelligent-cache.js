/**
 * Intelligent Caching System with Redis (with graceful fallback)
 * Features:
 * - Multi-layer caching (L1 memory, L2 Redis)
 * - Smart invalidation strategies
 * - Cache warming
 * - Performance analytics
 * - Compression for large objects
 * - Graceful fallback to memory-only cache if Redis unavailable
 */

const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');

// Try to load Redis, fallback to memory cache
let redis = null;
let useRedis = false;

try {
  redis = require('redis');
  useRedis = true;
} catch (error) {
  console.warn('⚠️  Redis not available, using memory-only cache');
}

class IntelligentCache {
  constructor(options = {}) {
    this.useRedis = useRedis && (options.useRedis !== false);
    
    // Setup Redis if available
    if (this.useRedis) {
      try {
        this.redisClient = redis.createClient({
          url: options.redisUrl || process.env.REDIS_URL || 'redis://localhost:6379',
          socket: {
            reconnectStrategy: (retries) => {
              if (retries > 3) {
                console.warn('⚠️  Redis connection failed, falling back to memory cache');
                this.useRedis = false;
                return false; // Stop retrying
              }
              return Math.min(retries * 50, 500);
            }
          }
        });

        this.redisClient.on('error', (err) => {
          console.error('Redis Client Error:', err.message);
          this.useRedis = false;
        });
        
        this.redisClient.on('ready', () => {
          console.log('✅ Redis Cache connected');
          this.useRedis = true;
        });
      } catch (error) {
        console.warn('⚠️  Redis setup failed, using memory-only cache:', error.message);
        this.useRedis = false;
      }
    }

    // L1 Cache (Memory) - Ultra fast for hot data
    this.memoryCache = new Map();
    this.memoryCacheSize = options.memoryCacheSize || 1000;
    this.memoryCacheHits = 0;
    this.memoryCacheMisses = 0;

    // L2 Cache (Redis or Memory fallback) - Shared across instances
    this.redisCacheHits = 0;
    this.redisCacheMisses = 0;
    
    // Fallback cache (when Redis unavailable)
    if (!this.useRedis) {
      this.fallbackCache = new Map();
      this.fallbackCacheSize = options.fallbackCacheSize || 10000;
    }

    // TTLs (seconds)
    this.defaultTTL = options.defaultTTL || 3600; // 1 hour
    this.scanResultTTL = 7 * 24 * 3600; // 7 days
    this.vulnerabilityTTL = 24 * 3600; // 24 hours
    this.domainInfoTTL = 30 * 24 * 3600; // 30 days

    // Compression threshold (bytes)
    this.compressionThreshold = 1024; // 1KB

    if (this.useRedis) {
      this.connect();
    } else {
      console.log('✅ Memory-only cache initialized');
    }
  }

  async connect() {
    if (this.useRedis && this.redisClient && !this.redisClient.isOpen) {
      try {
        await this.redisClient.connect();
      } catch (error) {
        console.warn('⚠️  Redis connection failed:', error.message);
        this.useRedis = false;
      }
    }
  }

  /**
   * Get cached value with multi-layer lookup
   */
  async get(key, options = {}) {
    const cacheKey = this.generateKey(key);

    // L1: Check memory cache first (fastest)
    if (this.memoryCache.has(cacheKey)) {
      this.memoryCacheHits++;
      const cached = this.memoryCache.get(cacheKey);
      
      // Check if expired
      if (Date.now() < cached.expiresAt) {
        return cached.value;
      } else {
        this.memoryCache.delete(cacheKey);
      }
    }

    this.memoryCacheMisses++;

    // L2: Check Redis cache (if available)
    if (this.useRedis && this.redisClient) {
      try {
        const cached = await this.redisClient.get(cacheKey);
        
        if (cached) {
          this.redisCacheHits++;
          let value = cached;

          // Decompress if needed
          if (cached.startsWith('COMPRESSED:')) {
            const compressed = Buffer.from(cached.substring(11), 'base64');
            value = await this.decompress(compressed);
          }

          const parsed = JSON.parse(value);

          // Promote to L1 cache (hot data)
          this.setMemoryCache(cacheKey, parsed, options.ttl || this.defaultTTL);

          return parsed;
        }

        this.redisCacheMisses++;
        return null;

      } catch (error) {
        console.error('Redis get error:', error.message);
        // Fall through to fallback cache
      }
    }
    
    // L2 Fallback: Check fallback cache (memory-based)
    if (this.fallbackCache && this.fallbackCache.has(cacheKey)) {
      const cached = this.fallbackCache.get(cacheKey);
      
      if (Date.now() < cached.expiresAt) {
        this.redisCacheHits++; // Count as L2 hit
        return cached.value;
      } else {
        this.fallbackCache.delete(cacheKey);
      }
    }

    this.redisCacheMisses++;
    return null;
  }

  /**
   * Set cached value in both layers
   */
  async set(key, value, ttl = null) {
    const cacheKey = this.generateKey(key);
    const cacheTTL = ttl || this.defaultTTL;

    try {
      let serialized = JSON.stringify(value);
      
      // Compress large objects (only if size warrants it)
      let shouldCompress = serialized.length > this.compressionThreshold;
      if (shouldCompress) {
        try {
          const compressed = await this.compress(serialized);
          serialized = 'COMPRESSED:' + compressed.toString('base64');
        } catch (error) {
          // If compression fails, use uncompressed
          shouldCompress = false;
        }
      }

      // L2: Set in Redis (persistent, shared) if available
      if (this.useRedis && this.redisClient) {
        try {
          await this.redisClient.setEx(cacheKey, cacheTTL, serialized);
        } catch (error) {
          console.error('Redis set error:', error.message);
          // Fall through to fallback
        }
      }
      
      // L2 Fallback: Set in fallback cache
      if (this.fallbackCache) {
        // Enforce size limit
        if (this.fallbackCache.size >= this.fallbackCacheSize) {
          // Remove oldest entry
          const firstKey = this.fallbackCache.keys().next().value;
          this.fallbackCache.delete(firstKey);
        }
        
        this.fallbackCache.set(cacheKey, {
          value,
          expiresAt: Date.now() + (cacheTTL * 1000)
        });
      }

      // L1: Set in memory (fast access)
      this.setMemoryCache(cacheKey, value, cacheTTL);

      return true;
    } catch (error) {
      console.error('Cache set error:', error.message);
      return false;
    }
  }

  /**
   * Cache scan results (long TTL)
   */
  async cacheScanResult(scanId, scanData) {
    const key = `scan:${scanId}`;
    await this.set(key, scanData, this.scanResultTTL);
    
    // Also cache by domain for quick lookup
    const domainKey = `scan:domain:${scanData.domain_id}:latest`;
    await this.set(domainKey, scanData, this.scanResultTTL);
  }

  /**
   * Get cached scan result
   */
  async getCachedScan(scanId) {
    return await this.get(`scan:${scanId}`);
  }

  /**
   * Cache vulnerability data
   */
  async cacheVulnerability(vulnHash, vulnData) {
    const key = `vuln:${vulnHash}`;
    await this.set(key, vulnData, this.vulnerabilityTTL);
  }

  /**
   * Check if vulnerability already known (deduplication)
   */
  async isKnownVulnerability(url, payload, type) {
    const hash = this.hashVulnerability(url, payload, type);
    const cached = await this.get(`vuln:${hash}`);
    return cached !== null;
  }

  /**
   * Cache domain metadata (whois, SSL, DNS)
   */
  async cacheDomainInfo(domain, info) {
    const key = `domain:info:${domain}`;
    await this.set(key, info, this.domainInfoTTL);
  }

  /**
   * Intelligent cache warming for frequently accessed data
   */
  async warmCache(userId) {
    console.log(`🔥 Warming cache for user ${userId}...`);

    try {
      // Warm recent scans
      const recentScans = await this.getRecentScans(userId, 10);
      for (const scan of recentScans) {
        await this.cacheScanResult(scan.id, scan);
      }

      // Warm domain list
      const domains = await this.getUserDomains(userId);
      await this.set(`user:${userId}:domains`, domains, 3600);

      console.log(`✅ Cache warmed: ${recentScans.length} scans, ${domains.length} domains`);
    } catch (error) {
      console.error('Cache warming error:', error);
    }
  }

  /**
   * Invalidate cache for specific patterns
   */
  async invalidate(pattern) {
    try {
      const keys = await this.redisClient.keys(this.generateKey(pattern));
      
      if (keys.length > 0) {
        await this.redisClient.del(keys);
        
        // Also clear from memory cache
        for (const key of keys) {
          this.memoryCache.delete(key);
        }

        console.log(`🗑️  Invalidated ${keys.length} cache entries`);
      }
    } catch (error) {
      console.error('Cache invalidation error:', error);
    }
  }

  /**
   * Smart invalidation on scan completion
   */
  async invalidateAfterScan(domainId) {
    await this.invalidate(`scan:domain:${domainId}:*`);
    await this.invalidate(`analytics:domain:${domainId}:*`);
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    const memoryHitRate = this.memoryCacheHits / (this.memoryCacheHits + this.memoryCacheMisses) || 0;
    const redisHitRate = this.redisCacheHits / (this.redisCacheHits + this.redisCacheMisses) || 0;

    return {
      memory: {
        size: this.memoryCache.size,
        maxSize: this.memoryCacheSize,
        hits: this.memoryCacheHits,
        misses: this.memoryCacheMisses,
        hitRate: (memoryHitRate * 100).toFixed(2) + '%'
      },
      redis: {
        hits: this.redisCacheHits,
        misses: this.redisCacheMisses,
        hitRate: (redisHitRate * 100).toFixed(2) + '%'
      },
      overall: {
        hitRate: (((this.memoryCacheHits + this.redisCacheHits) / 
                   (this.memoryCacheHits + this.memoryCacheMisses + 
                    this.redisCacheHits + this.redisCacheMisses)) * 100).toFixed(2) + '%'
      }
    };
  }

  /**
   * Memory cache management
   */
  setMemoryCache(key, value, ttl) {
    // Evict oldest if at capacity
    if (this.memoryCache.size >= this.memoryCacheSize) {
      const firstKey = this.memoryCache.keys().next().value;
      this.memoryCache.delete(firstKey);
    }

    this.memoryCache.set(key, {
      value,
      expiresAt: Date.now() + (ttl * 1000)
    });
  }

  /**
   * Generate cache key with namespace
   */
  generateKey(key) {
    return `nexus:${key}`;
  }

  /**
   * Hash vulnerability for deduplication
   */
  hashVulnerability(url, payload, type) {
    const data = `${url}:${payload}:${type}`;
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Compress data
   */
  async compress(data) {
    return new Promise((resolve, reject) => {
      zlib.gzip(data, (err, compressed) => {
        if (err) reject(err);
        else resolve(compressed);
      });
    });
  }

  /**
   * Decompress data
   */
  async decompress(data) {
    return new Promise((resolve, reject) => {
      zlib.gunzip(data, (err, decompressed) => {
        if (err) reject(err);
        else resolve(decompressed.toString());
      });
    });
  }

  /**
   * Helper methods (would connect to actual DB in production)
   */
  async getRecentScans(userId, limit) {
    // Placeholder - would query database
    return [];
  }

  async getUserDomains(userId) {
    // Placeholder - would query database
    return [];
  }

  /**
   * Cleanup and disconnect
   */
  async disconnect() {
    this.memoryCache.clear();
    await this.redisClient.quit();
    console.log('🔌 Cache disconnected');
  }
}

module.exports = IntelligentCache;
