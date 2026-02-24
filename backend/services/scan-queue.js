/**
 * Distributed Queue System with Bull
 * Enables parallel scanning at scale
 * Features:
 * - Job prioritization
 * - Retry logic
 * - Progress tracking
 * - Worker pooling
 * - Rate limiting per domain
 */

const Queue = require('bull');
const db = require('../config/database');
const LegendaryScanner = require('../services/legendary-scanner');

class ScanQueue {
  constructor() {
    this.scanQueue = new Queue('nexus-scans', {
      redis: {
        host: process.env.REDIS_HOST || 'localhost',
        port: process.env.REDIS_PORT || 6379,
        password: process.env.REDIS_PASSWORD
      },
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000
        },
        removeOnComplete: 100, // Keep last 100 completed
        removeOnFail: 500      // Keep last 500 failed
      }
    });

    this.setupProcessors();
    this.setupEventHandlers();
  }

  setupProcessors() {
    // Process scans with configurable concurrency
    this.scanQueue.process('scan', 
      parseInt(process.env.CONCURRENT_SCANS) || 10, 
      async (job) => {
        return await this.processScan(job);
      }
    );

    // High priority scans
    this.scanQueue.process('urgent-scan', 
      5, 
      async (job) => {
        return await this.processScan(job);
      }
    );
  }

  setupEventHandlers() {
    this.scanQueue.on('completed', (job, result) => {
      console.log(`✅ Scan ${job.data.scanId} completed: ${result.vulnerabilities} vulns`);
      this.updateScanStatus(job.data.scanId, 'completed', result);
    });

    this.scanQueue.on('failed', (job, err) => {
      console.error(`❌ Scan ${job.data.scanId} failed: ${err.message}`);
      this.updateScanStatus(job.data.scanId, 'failed', { error: err.message });
    });

    this.scanQueue.on('progress', (job, progress) => {
      console.log(`📊 Scan ${job.data.scanId}: ${progress}%`);
      this.updateScanProgress(job.data.scanId, progress);
    });

    this.scanQueue.on('stalled', (job) => {
      console.warn(`⚠️  Scan ${job.data.scanId} stalled`);
    });
  }

  async addScan(scanId, domainId, options = {}) {
    const priority = options.priority || 'normal';
    const jobOptions = {
      priority: priority === 'urgent' ? 1 : priority === 'high' ? 5 : 10,
      timeout: options.timeout || 300000, // 5 minutes default
      jobId: `scan-${scanId}`,
      ...options
    };

    const job = await this.scanQueue.add(
      priority === 'urgent' ? 'urgent-scan' : 'scan',
      {
        scanId,
        domainId,
        options
      },
      jobOptions
    );

    console.log(`📥 Scan queued: ${scanId} (priority: ${priority})`);
    return job;
  }

  async processScan(job) {
    const { scanId, domainId } = job.data;
    
    try {
      // Update status
      db.prepare('UPDATE scans SET status = ? WHERE id = ?').run('running', scanId);
      
      // Progress callback
      const progressCallback = (progress) => {
        job.progress(progress);
      };

      // Create scanner
      const scanner = new LegendaryScanner(domainId, scanId, progressCallback);
      
      // Run scan
      const results = await scanner.performLegendaryScan();
      
      return {
        success: true,
        vulnerabilities: results.vulnerabilities.length,
        score: results.score
      };
      
    } catch (error) {
      console.error(`Scan ${scanId} error:`, error);
      throw error;
    }
  }

  updateScanStatus(scanId, status, data = {}) {
    try {
      db.prepare(`
        UPDATE scans 
        SET status = ?, 
            completed_at = ?,
            vulnerabilities_found = ?
        WHERE id = ?
      `).run(
        status,
        status === 'completed' ? new Date().toISOString() : null,
        data.vulnerabilities || 0,
        scanId
      );
    } catch (error) {
      console.error('Failed to update scan status:', error);
    }
  }

  updateScanProgress(scanId, progress) {
    try {
      db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(progress, scanId);
    } catch (error) {
      // Silent fail
    }
  }

  async getQueueStats() {
    const [waiting, active, completed, failed, delayed] = await Promise.all([
      this.scanQueue.getWaitingCount(),
      this.scanQueue.getActiveCount(),
      this.scanQueue.getCompletedCount(),
      this.scanQueue.getFailedCount(),
      this.scanQueue.getDelayedCount()
    ]);

    return {
      waiting,
      active,
      completed,
      failed,
      delayed,
      total: waiting + active + completed + failed + delayed
    };
  }

  async pauseQueue() {
    await this.scanQueue.pause();
    console.log('⏸️  Queue paused');
  }

  async resumeQueue() {
    await this.scanQueue.resume();
    console.log('▶️  Queue resumed');
  }

  async clearQueue() {
    await this.scanQueue.empty();
    console.log('🗑️  Queue cleared');
  }

  async getJob(jobId) {
    return await this.scanQueue.getJob(jobId);
  }

  async retryFailed() {
    const failed = await this.scanQueue.getFailed();
    for (const job of failed) {
      await job.retry();
    }
    console.log(`🔄 Retrying ${failed.length} failed jobs`);
  }

  async close() {
    await this.scanQueue.close();
  }
}

// Singleton instance
let queueInstance = null;

function getQueue() {
  if (!queueInstance) {
    queueInstance = new ScanQueue();
  }
  return queueInstance;
}

module.exports = { ScanQueue, getQueue };
