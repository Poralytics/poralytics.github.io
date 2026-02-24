/**
 * Prometheus Metrics Exporter
 * Monitors application performance and health
 * Metrics exposed on /metrics endpoint
 */

const client = require('prom-client');

class MetricsCollector {
  constructor() {
    // Enable default metrics (CPU, memory, etc.)
    client.collectDefaultMetrics({ 
      timeout: 5000,
      prefix: 'nexus_'
    });

    // Custom metrics
    this.initializeMetrics();
  }

  initializeMetrics() {
    // Scan metrics
    this.scansTotal = new client.Counter({
      name: 'nexus_scans_total',
      help: 'Total number of scans initiated',
      labelNames: ['status', 'domain']
    });

    this.scanDuration = new client.Histogram({
      name: 'nexus_scan_duration_seconds',
      help: 'Scan duration in seconds',
      labelNames: ['scanner_type'],
      buckets: [1, 5, 15, 30, 60, 120, 300, 600]
    });

    this.vulnerabilitiesFound = new client.Counter({
      name: 'nexus_vulnerabilities_found_total',
      help: 'Total vulnerabilities found',
      labelNames: ['severity', 'category']
    });

    this.activeScans = new client.Gauge({
      name: 'nexus_active_scans',
      help: 'Number of currently running scans'
    });

    // API metrics
    this.httpRequestsTotal = new client.Counter({
      name: 'nexus_http_requests_total',
      help: 'Total HTTP requests',
      labelNames: ['method', 'route', 'status_code']
    });

    this.httpRequestDuration = new client.Histogram({
      name: 'nexus_http_request_duration_seconds',
      help: 'HTTP request duration',
      labelNames: ['method', 'route'],
      buckets: [0.01, 0.05, 0.1, 0.5, 1, 2, 5]
    });

    // Database metrics
    this.dbQueryDuration = new client.Histogram({
      name: 'nexus_db_query_duration_seconds',
      help: 'Database query duration',
      labelNames: ['operation'],
      buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1]
    });

    this.dbConnections = new client.Gauge({
      name: 'nexus_db_connections',
      help: 'Number of database connections'
    });

    // Queue metrics
    this.queueSize = new client.Gauge({
      name: 'nexus_queue_size',
      help: 'Number of jobs in queue',
      labelNames: ['state']
    });

    this.queueJobDuration = new client.Histogram({
      name: 'nexus_queue_job_duration_seconds',
      help: 'Queue job processing duration',
      labelNames: ['job_type'],
      buckets: [1, 10, 30, 60, 120, 300]
    });

    // Business metrics
    this.riskExposure = new client.Gauge({
      name: 'nexus_risk_exposure_eur',
      help: 'Total risk exposure in EUR',
      labelNames: ['domain']
    });

    this.securityScore = new client.Gauge({
      name: 'nexus_security_score',
      help: 'Security score (0-100)',
      labelNames: ['domain']
    });

    // Error metrics
    this.errorsTotal = new client.Counter({
      name: 'nexus_errors_total',
      help: 'Total errors',
      labelNames: ['type', 'severity']
    });
  }

  // Scan metrics
  recordScanStart(domain) {
    this.scansTotal.inc({ status: 'started', domain });
    this.activeScans.inc();
  }

  recordScanComplete(domain, duration, vulnerabilities) {
    this.scansTotal.inc({ status: 'completed', domain });
    this.activeScans.dec();
    this.scanDuration.observe({ scanner_type: 'full' }, duration);
    
    // Record vulnerabilities by severity
    Object.entries(vulnerabilities).forEach(([severity, count]) => {
      this.vulnerabilitiesFound.inc({ severity, category: 'all' }, count);
    });
  }

  recordScanFailed(domain, error) {
    this.scansTotal.inc({ status: 'failed', domain });
    this.activeScans.dec();
    this.errorsTotal.inc({ type: 'scan_failure', severity: 'high' });
  }

  recordVulnerability(severity, category) {
    this.vulnerabilitiesFound.inc({ severity, category });
  }

  // HTTP metrics
  recordHTTPRequest(method, route, statusCode, duration) {
    this.httpRequestsTotal.inc({ method, route, status_code: statusCode });
    this.httpRequestDuration.observe({ method, route }, duration);
  }

  // Database metrics
  recordDBQuery(operation, duration) {
    this.dbQueryDuration.observe({ operation }, duration);
  }

  setDBConnections(count) {
    this.dbConnections.set(count);
  }

  // Queue metrics
  updateQueueStats(stats) {
    this.queueSize.set({ state: 'waiting' }, stats.waiting || 0);
    this.queueSize.set({ state: 'active' }, stats.active || 0);
    this.queueSize.set({ state: 'completed' }, stats.completed || 0);
    this.queueSize.set({ state: 'failed' }, stats.failed || 0);
  }

  recordQueueJob(jobType, duration) {
    this.queueJobDuration.observe({ job_type: jobType }, duration);
  }

  // Business metrics
  updateRiskExposure(domain, amount) {
    this.riskExposure.set({ domain }, amount);
  }

  updateSecurityScore(domain, score) {
    this.securityScore.set({ domain }, score);
  }

  // Error metrics
  recordError(type, severity) {
    this.errorsTotal.inc({ type, severity });
  }

  // Get metrics for Prometheus
  getMetrics() {
    return client.register.metrics();
  }

  // Reset all metrics (useful for testing)
  reset() {
    client.register.clear();
    this.initializeMetrics();
  }
}

// Middleware for automatic HTTP metrics
function metricsMiddleware(metrics) {
  return (req, res, next) => {
    const start = Date.now();
    
    res.on('finish', () => {
      const duration = (Date.now() - start) / 1000;
      const route = req.route ? req.route.path : req.path;
      metrics.recordHTTPRequest(req.method, route, res.statusCode, duration);
    });
    
    next();
  };
}

// Singleton
let metricsInstance = null;

function getMetrics() {
  if (!metricsInstance) {
    metricsInstance = new MetricsCollector();
  }
  return metricsInstance;
}

module.exports = { MetricsCollector, getMetrics, metricsMiddleware };
