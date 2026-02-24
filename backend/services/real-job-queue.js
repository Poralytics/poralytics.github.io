/**
 * REAL JOB QUEUE SYSTEM
 * Manages scan jobs with or without Redis
 */

const EventEmitter = require('events');

class RealJobQueue extends EventEmitter {
  constructor() {
    super();
    this.redis = null;
    this.useRedis = false;
    this.queue = []; // Fallback in-memory queue
    this.processing = false;
    this.workers = [];
    this.maxConcurrent = 3; // Max 3 scans at once
    
    this.initializeRedis();
    this.startWorker();
  }

  /**
   * Try to initialize Redis (graceful fallback)
   */
  async initializeRedis() {
    try {
      if (process.env.REDIS_URL) {
        const Redis = require('ioredis');
        this.redis = new Redis(process.env.REDIS_URL);
        
        await this.redis.ping();
        this.useRedis = true;
        console.log('✅ Redis queue initialized');
      } else {
        console.log('ℹ️  Using in-memory queue (REDIS_URL not set)');
      }
    } catch (error) {
      console.log('ℹ️  Redis not available, using in-memory queue');
      this.useRedis = false;
    }
  }

  /**
   * Add job to queue
   */
  async addJob(type, data, options = {}) {
    const job = {
      id: this.generateJobId(),
      type,
      data,
      status: 'pending',
      priority: options.priority || 0,
      attempts: 0,
      maxAttempts: options.maxAttempts || 3,
      createdAt: Date.now(),
      ...options
    };

    if (this.useRedis) {
      // Add to Redis
      await this.redis.lpush(`queue:${type}`, JSON.stringify(job));
      await this.redis.set(`job:${job.id}`, JSON.stringify(job));
    } else {
      // Add to in-memory queue
      this.queue.push(job);
      this.queue.sort((a, b) => b.priority - a.priority); // Sort by priority
    }

    this.emit('jobAdded', job);
    console.log(`[Queue] Added job ${job.id} (${type})`);

    return job.id;
  }

  /**
   * Get next job from queue
   */
  async getNextJob() {
    if (this.useRedis) {
      const types = ['scan', 'report', 'notification'];
      
      for (const type of types) {
        const jobStr = await this.redis.rpop(`queue:${type}`);
        if (jobStr) {
          return JSON.parse(jobStr);
        }
      }
      return null;
    } else {
      // Get from in-memory queue
      const pendingJobs = this.queue.filter(j => j.status === 'pending');
      if (pendingJobs.length > 0) {
        const job = pendingJobs[0];
        job.status = 'processing';
        return job;
      }
      return null;
    }
  }

  /**
   * Update job status
   */
  async updateJobStatus(jobId, status, result = null) {
    if (this.useRedis) {
      const jobStr = await this.redis.get(`job:${jobId}`);
      if (jobStr) {
        const job = JSON.parse(jobStr);
        job.status = status;
        job.result = result;
        job.completedAt = Date.now();
        await this.redis.set(`job:${jobId}`, JSON.stringify(job));
        
        // Set expiry (keep for 24 hours)
        await this.redis.expire(`job:${jobId}`, 86400);
      }
    } else {
      const job = this.queue.find(j => j.id === jobId);
      if (job) {
        job.status = status;
        job.result = result;
        job.completedAt = Date.now();
      }
    }

    this.emit('jobStatusChanged', { jobId, status, result });
  }

  /**
   * Worker to process jobs
   */
  async startWorker() {
    setInterval(async () => {
      if (this.workers.length >= this.maxConcurrent) {
        return; // Max concurrent jobs reached
      }

      const job = await this.getNextJob();
      
      if (job) {
        this.processJob(job);
      }
    }, 1000); // Check every second
  }

  /**
   * Process a job
   */
  async processJob(job) {
    try {
      this.workers.push(job.id);
      console.log(`[Queue] Processing job ${job.id} (${job.type})`);

      let result;

      switch (job.type) {
        case 'scan':
          result = await this.processScanJob(job);
          break;
        case 'report':
          result = await this.processReportJob(job);
          break;
        case 'notification':
          result = await this.processNotificationJob(job);
          break;
        default:
          throw new Error(`Unknown job type: ${job.type}`);
      }

      await this.updateJobStatus(job.id, 'completed', result);
      console.log(`[Queue] Completed job ${job.id}`);

    } catch (error) {
      console.error(`[Queue] Job ${job.id} failed:`, error);
      
      job.attempts++;
      
      if (job.attempts >= job.maxAttempts) {
        await this.updateJobStatus(job.id, 'failed', { error: error.message });
      } else {
        // Retry
        job.status = 'pending';
        await this.addJob(job.type, job.data, { 
          ...job, 
          id: undefined // Generate new ID
        });
      }
    } finally {
      // Remove from workers
      const index = this.workers.indexOf(job.id);
      if (index > -1) {
        this.workers.splice(index, 1);
      }
    }
  }

  /**
   * Process scan job
   */
  async processScanJob(job) {
    const { scanId, domainId, userId, url } = job.data;
    
    const RealScanOrchestrator = require('./real-scan-orchestrator');
    const result = await RealScanOrchestrator.startScan(scanId, domainId, userId, url);
    
    return result;
  }

  /**
   * Process report job
   */
  async processReportJob(job) {
    // Generate report
    console.log('[Queue] Generating report:', job.data);
    return { success: true };
  }

  /**
   * Process notification job
   */
  async processNotificationJob(job) {
    // Send notification
    console.log('[Queue] Sending notification:', job.data);
    return { success: true };
  }

  /**
   * Get job status
   */
  async getJobStatus(jobId) {
    if (this.useRedis) {
      const jobStr = await this.redis.get(`job:${jobId}`);
      return jobStr ? JSON.parse(jobStr) : null;
    } else {
      return this.queue.find(j => j.id === jobId) || null;
    }
  }

  /**
   * Get queue stats
   */
  async getStats() {
    if (this.useRedis) {
      const scanCount = await this.redis.llen('queue:scan');
      return {
        pending: scanCount,
        processing: this.workers.length,
        useRedis: true
      };
    } else {
      return {
        pending: this.queue.filter(j => j.status === 'pending').length,
        processing: this.workers.length,
        total: this.queue.length,
        useRedis: false
      };
    }
  }

  /**
   * Generate job ID
   */
  generateJobId() {
    return `job_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Clear completed jobs (cleanup)
   */
  async cleanup() {
    if (!this.useRedis) {
      const oneHourAgo = Date.now() - 3600000;
      this.queue = this.queue.filter(job => {
        return job.status === 'pending' || 
               job.status === 'processing' || 
               (job.completedAt && job.completedAt > oneHourAgo);
      });
    }
  }
}

module.exports = new RealJobQueue();
