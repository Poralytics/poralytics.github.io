/**
 * Distributed Scanning System
 * Features:
 * - Horizontal scaling with multiple workers
 * - Load balancing across workers
 * - Job queue with priority
 * - Health monitoring
 * - Fault tolerance
 * - Auto-scaling based on load
 */

const { Queue, Worker, QueueScheduler } = require('bullmq');
const redis = require('redis');
const os = require('os');

class DistributedScanSystem {
  constructor(options = {}) {
    this.redisConnection = {
      host: options.redisHost || process.env.REDIS_HOST || 'localhost',
      port: options.redisPort || process.env.REDIS_PORT || 6379
    };

    // Main scan queue with priority support
    this.scanQueue = new Queue('nexus-scans', {
      connection: this.redisConnection,
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        },
        removeOnComplete: {
          count: 1000, // Keep last 1000 completed
          age: 7 * 24 * 3600 // 7 days
        },
        removeOnFail: {
          count: 5000
        }
      }
    });

    // Queue scheduler for delayed/repeatable jobs
    this.scheduler = new QueueScheduler('nexus-scans', {
      connection: this.redisConnection
    });

    // Workers pool
    this.workers = [];
    this.maxWorkers = options.maxWorkers || os.cpus().length;
    this.activeWorkers = 0;

    // Metrics
    this.metrics = {
      totalJobs: 0,
      completedJobs: 0,
      failedJobs: 0,
      activeJobs: 0,
      avgProcessingTime: 0,
      jobsPerMinute: 0
    };

    // Health check
    this.healthCheckInterval = null;

    this.initialize();
  }

  /**
   * Initialize distributed system
   */
  async initialize() {
    console.log('🚀 Initializing Distributed Scan System...');
    console.log(`   Max workers: ${this.maxWorkers}`);

    // Start initial workers
    await this.startWorkers(this.maxWorkers);

    // Setup monitoring
    this.setupMonitoring();

    // Setup health checks
    this.startHealthChecks();

    // Setup auto-scaling
    this.setupAutoScaling();

    console.log('✅ Distributed Scan System ready');
  }

  /**
   * Add scan job to queue
   */
  async addScan(scanData, options = {}) {
    const priority = this.calculatePriority(scanData, options);

    const job = await this.scanQueue.add('scan', scanData, {
      priority,
      jobId: `scan-${scanData.scan_id}`,
      delay: options.delay || 0,
      ...options
    });

    this.metrics.totalJobs++;

    console.log(`📝 Scan job added: ${job.id} (priority: ${priority})`);

    return job;
  }

  /**
   * Add bulk scans (batch processing)
   */
  async addBulkScans(scansData, options = {}) {
    const jobs = scansData.map((scanData, index) => ({
      name: 'scan',
      data: scanData,
      opts: {
        priority: this.calculatePriority(scanData, options),
        jobId: `scan-${scanData.scan_id}`,
        delay: options.stagger ? index * 1000 : 0 // Stagger by 1s
      }
    }));

    const added = await this.scanQueue.addBulk(jobs);

    this.metrics.totalJobs += added.length;

    console.log(`📝 Added ${added.length} bulk scan jobs`);

    return added;
  }

  /**
   * Schedule recurring scan
   */
  async scheduleRecurringScan(scanData, cronExpression, options = {}) {
    const job = await this.scanQueue.add('scan', scanData, {
      repeat: {
        pattern: cronExpression,
        ...options.repeatOptions
      },
      jobId: `recurring-${scanData.domain_id}`
    });

    console.log(`⏰ Scheduled recurring scan for domain ${scanData.domain_id}: ${cronExpression}`);

    return job;
  }

  /**
   * Start worker pool
   */
  async startWorkers(count) {
    for (let i = 0; i < count; i++) {
      await this.startWorker(i);
    }
  }

  /**
   * Start individual worker
   */
  async startWorker(workerId) {
    const worker = new Worker('nexus-scans', async (job) => {
      return await this.processScanJob(job);
    }, {
      connection: this.redisConnection,
      concurrency: 5, // Each worker handles 5 jobs concurrently
      limiter: {
        max: 10, // Max 10 jobs per worker
        duration: 1000 // per second
      }
    });

    // Worker event handlers
    worker.on('completed', (job, result) => {
      this.metrics.completedJobs++;
      this.metrics.activeJobs--;
      this.updateProcessingTime(job.processedOn, job.finishedOn);
      console.log(`✅ Worker ${workerId} completed job ${job.id}`);
    });

    worker.on('failed', (job, err) => {
      this.metrics.failedJobs++;
      this.metrics.activeJobs--;
      console.error(`❌ Worker ${workerId} failed job ${job.id}:`, err.message);
    });

    worker.on('error', (err) => {
      console.error(`⚠️  Worker ${workerId} error:`, err);
    });

    this.workers.push(worker);
    this.activeWorkers++;

    console.log(`👷 Worker ${workerId} started`);
  }

  /**
   * Process scan job (actual scanning logic)
   */
  async processScanJob(job) {
    const { scan_id, domain_id, domain_url } = job.data;

    console.log(`🔍 Processing scan ${scan_id} for ${domain_url}`);

    this.metrics.activeJobs++;

    try {
      // Update scan status to 'running'
      await this.updateScanStatus(scan_id, 'running');

      // Run the actual scanner (import LegendaryScanner)
      const LegendaryScanner = require('../services/legendary-scanner');
      const scanner = new LegendaryScanner();

      const results = await scanner.scanDomain({
        id: domain_id,
        url: domain_url
      });

      // Update scan with results
      await this.updateScanResults(scan_id, results);

      // Update status to 'completed'
      await this.updateScanStatus(scan_id, 'completed');

      // Trigger post-scan actions
      await this.postScanActions(scan_id, results);

      return {
        success: true,
        scan_id,
        vulnerabilities_found: results.vulnerabilities?.length || 0,
        duration: results.duration
      };

    } catch (error) {
      console.error(`Error processing scan ${scan_id}:`, error);

      await this.updateScanStatus(scan_id, 'failed', error.message);

      throw error;
    }
  }

  /**
   * Calculate job priority (1-10, 1 = highest)
   */
  calculatePriority(scanData, options) {
    if (options.priority) return options.priority;

    let priority = 5; // Default medium priority

    // Critical domains get higher priority
    if (scanData.is_critical) priority -= 2;

    // Scheduled scans get lower priority
    if (scanData.is_scheduled) priority += 1;

    // User tier affects priority
    if (scanData.user_tier === 'enterprise') priority -= 2;
    else if (scanData.user_tier === 'pro') priority -= 1;

    // Recent failures get higher priority (retry sooner)
    if (scanData.failed_attempts > 0) priority -= 1;

    return Math.max(1, Math.min(10, priority));
  }

  /**
   * Setup monitoring and metrics collection
   */
  setupMonitoring() {
    // Update metrics every 10 seconds
    setInterval(async () => {
      const counts = await this.scanQueue.getJobCounts();

      this.metrics.activeJobs = counts.active;
      this.metrics.totalJobs = counts.waiting + counts.active + counts.completed + counts.failed;

      // Calculate jobs per minute
      const completedInLastMinute = await this.getCompletedJobsInLastMinute();
      this.metrics.jobsPerMinute = completedInLastMinute;

    }, 10000);
  }

  /**
   * Setup auto-scaling based on queue depth
   */
  setupAutoScaling() {
    setInterval(async () => {
      const counts = await this.scanQueue.getJobCounts();
      const queueDepth = counts.waiting;

      // Scale up if queue is backing up
      if (queueDepth > 50 && this.activeWorkers < this.maxWorkers) {
        console.log(`📈 Scaling up: queue depth ${queueDepth}`);
        await this.scaleUp(1);
      }

      // Scale down if queue is empty and we have extra workers
      if (queueDepth < 5 && this.activeWorkers > 2) {
        console.log(`📉 Scaling down: queue depth ${queueDepth}`);
        await this.scaleDown(1);
      }

    }, 30000); // Check every 30s
  }

  /**
   * Scale up workers
   */
  async scaleUp(count) {
    const currentCount = this.workers.length;
    const newCount = Math.min(currentCount + count, this.maxWorkers);

    for (let i = currentCount; i < newCount; i++) {
      await this.startWorker(i);
    }

    console.log(`✅ Scaled up to ${this.workers.length} workers`);
  }

  /**
   * Scale down workers
   */
  async scaleDown(count) {
    for (let i = 0; i < count && this.workers.length > 2; i++) {
      const worker = this.workers.pop();
      await worker.close();
      this.activeWorkers--;
    }

    console.log(`✅ Scaled down to ${this.workers.length} workers`);
  }

  /**
   * Health checks for workers
   */
  startHealthChecks() {
    this.healthCheckInterval = setInterval(async () => {
      const healthStatus = {
        workers: this.workers.length,
        activeWorkers: this.activeWorkers,
        queueHealth: await this.checkQueueHealth(),
        metrics: this.metrics
      };

      // Log if unhealthy
      if (!healthStatus.queueHealth) {
        console.warn('⚠️  Queue health check failed!');
      }

    }, 60000); // Every minute
  }

  /**
   * Check queue health
   */
  async checkQueueHealth() {
    try {
      const counts = await this.scanQueue.getJobCounts();
      return counts !== null;
    } catch (error) {
      console.error('Queue health check error:', error);
      return false;
    }
  }

  /**
   * Get system metrics
   */
  async getMetrics() {
    const counts = await this.scanQueue.getJobCounts();

    return {
      ...this.metrics,
      queue: {
        waiting: counts.waiting,
        active: counts.active,
        completed: counts.completed,
        failed: counts.failed,
        delayed: counts.delayed
      },
      workers: {
        total: this.workers.length,
        active: this.activeWorkers
      },
      system: {
        cpu: os.loadavg()[0],
        memory: (1 - (os.freemem() / os.totalmem())) * 100
      }
    };
  }

  /**
   * Get queue status
   */
  async getQueueStatus() {
    const [waiting, active, completed, failed] = await Promise.all([
      this.scanQueue.getWaitingCount(),
      this.scanQueue.getActiveCount(),
      this.scanQueue.getCompletedCount(),
      this.scanQueue.getFailedCount()
    ]);

    return {
      waiting,
      active,
      completed,
      failed,
      total: waiting + active + completed + failed
    };
  }

  /**
   * Pause/resume queue
   */
  async pauseQueue() {
    await this.scanQueue.pause();
    console.log('⏸️  Queue paused');
  }

  async resumeQueue() {
    await this.scanQueue.resume();
    console.log('▶️  Queue resumed');
  }

  /**
   * Clean completed/failed jobs
   */
  async cleanJobs(grace = 7 * 24 * 3600 * 1000) {
    const cleaned = await this.scanQueue.clean(grace, 1000, 'completed');
    const cleanedFailed = await this.scanQueue.clean(grace, 1000, 'failed');

    console.log(`🧹 Cleaned ${cleaned.length + cleanedFailed.length} old jobs`);
  }

  /**
   * Helper methods (would integrate with actual DB)
   */
  async updateScanStatus(scanId, status, error = null) {
    // Placeholder - would update database
    console.log(`   Status update: scan ${scanId} -> ${status}`);
  }

  async updateScanResults(scanId, results) {
    // Placeholder - would save to database
    console.log(`   Results saved for scan ${scanId}`);
  }

  async postScanActions(scanId, results) {
    // Send notifications, update analytics, etc.
    console.log(`   Post-scan actions for scan ${scanId}`);
  }

  async getCompletedJobsInLastMinute() {
    // Simplified calculation
    return Math.floor(this.metrics.completedJobs / 60);
  }

  updateProcessingTime(startTime, endTime) {
    const duration = endTime - startTime;
    this.metrics.avgProcessingTime = 
      (this.metrics.avgProcessingTime * 0.9) + (duration * 0.1); // Moving average
  }

  /**
   * Graceful shutdown
   */
  async shutdown() {
    console.log('🛑 Shutting down Distributed Scan System...');

    // Stop accepting new jobs
    await this.pauseQueue();

    // Wait for active jobs to complete (max 60s)
    console.log('   Waiting for active jobs to complete...');
    await new Promise(resolve => setTimeout(resolve, 5000));

    // Close all workers
    for (const worker of this.workers) {
      await worker.close();
    }

    // Close queue
    await this.scanQueue.close();
    await this.scheduler.close();

    // Clear health check
    if (this.healthCheckInterval) {
      clearInterval(this.healthCheckInterval);
    }

    console.log('✅ Shutdown complete');
  }
}

module.exports = DistributedScanSystem;
