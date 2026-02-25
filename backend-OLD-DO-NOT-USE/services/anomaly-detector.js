/**
 * Anomaly Detector - Basic ML for 0-day Detection
 * Uses statistical analysis and pattern recognition
 * to detect unusual behaviors that may indicate unknown vulnerabilities
 */

class AnomalyDetector {
  constructor() {
    this.baseline = null;
    this.anomalies = [];
    this.threshold = 3; // Standard deviations for anomaly
  }

  /**
   * Analyze responses to detect anomalous behaviors
   */
  async analyze(responses) {
    console.log('    🤖 ML Anomaly Detector analyzing responses...');
    
    if (responses.length < 10) {
      console.log('    ⚠️  Need at least 10 responses for statistical analysis');
      return [];
    }

    // Establish baseline
    this.establishBaseline(responses);
    
    // Detect anomalies
    this.detectResponseTimeAnomalies(responses);
    this.detectLengthAnomalies(responses);
    this.detectStatusCodeAnomalies(responses);
    this.detectContentAnomalies(responses);
    this.detectHeaderAnomalies(responses);
    
    console.log(`    ✅ Found ${this.anomalies.length} anomalies`);
    
    return this.anomalies;
  }

  establishBaseline(responses) {
    const responseTimes = responses.map(r => r.responseTime || 0);
    const lengths = responses.map(r => r.length || 0);
    const statusCodes = responses.map(r => r.status || 200);
    
    this.baseline = {
      responseTime: {
        mean: this.mean(responseTimes),
        stdDev: this.standardDeviation(responseTimes),
        median: this.median(responseTimes)
      },
      length: {
        mean: this.mean(lengths),
        stdDev: this.standardDeviation(lengths),
        median: this.median(lengths)
      },
      statusCodes: {
        distribution: this.distribution(statusCodes),
        mostCommon: this.mode(statusCodes)
      }
    };
  }

  detectResponseTimeAnomalies(responses) {
    const { mean, stdDev } = this.baseline.responseTime;
    
    responses.forEach((response, index) => {
      const time = response.responseTime || 0;
      const zScore = Math.abs((time - mean) / stdDev);
      
      if (zScore > this.threshold) {
        this.anomalies.push({
          type: 'response_time_anomaly',
          severity: this.calculateAnomalySeverity(zScore),
          description: `Unusual response time: ${time}ms (expected ~${Math.round(mean)}ms)`,
          zScore: zScore.toFixed(2),
          payload: response.payload,
          details: {
            actual: time,
            expected: mean,
            deviation: stdDev
          },
          potentialCause: time > mean * 3 ? 'Time-based injection or DoS' : 'Performance anomaly',
          confidence: Math.min(zScore / 5 * 100, 95)
        });
      }
    });
  }

  detectLengthAnomalies(responses) {
    const { mean, stdDev } = this.baseline.length;
    
    responses.forEach(response => {
      const length = response.length || 0;
      const zScore = Math.abs((length - mean) / stdDev);
      
      if (zScore > this.threshold) {
        this.anomalies.push({
          type: 'length_anomaly',
          severity: this.calculateAnomalySeverity(zScore),
          description: `Unusual response length: ${length} bytes (expected ~${Math.round(mean)} bytes)`,
          zScore: zScore.toFixed(2),
          payload: response.payload,
          details: {
            actual: length,
            expected: mean,
            deviation: stdDev
          },
          potentialCause: length > mean ? 'Error message leak or verbose response' : 'Boolean-based SQLi or filtered response',
          confidence: Math.min(zScore / 5 * 100, 90)
        });
      }
    });
  }

  detectStatusCodeAnomalies(responses) {
    const mostCommon = this.baseline.statusCodes.mostCommon;
    
    responses.forEach(response => {
      if (response.status && response.status !== mostCommon) {
        const severity = response.status >= 500 ? 'high' : 
                        response.status >= 400 ? 'medium' : 'low';
        
        this.anomalies.push({
          type: 'status_code_anomaly',
          severity,
          description: `Unexpected status code: ${response.status} (normal: ${mostCommon})`,
          payload: response.payload,
          details: {
            actual: response.status,
            expected: mostCommon
          },
          potentialCause: response.status >= 500 ? 'Server error triggered by payload' : 
                         response.status === 403 ? 'WAF or input filter triggered' :
                         'Request handling changed',
          confidence: 70
        });
      }
    });
  }

  detectContentAnomalies(responses) {
    // Look for error patterns that might indicate 0-days
    const suspiciousPatterns = [
      // Memory errors
      { pattern: /segmentation fault/i, cause: 'Memory corruption (potential RCE)' },
      { pattern: /core dumped/i, cause: 'Process crash (potential DoS/RCE)' },
      { pattern: /access violation/i, cause: 'Memory access error' },
      
      // Unexpected errors
      { pattern: /fatal error/i, cause: 'Fatal application error' },
      { pattern: /uncaught exception/i, cause: 'Unhandled exception' },
      { pattern: /null pointer/i, cause: 'Null pointer dereference' },
      
      // Framework errors
      { pattern: /stack trace/i, cause: 'Debug information leak' },
      { pattern: /in .+\.php on line \d+/i, cause: 'PHP error disclosure' },
      { pattern: /at .+\.java:\d+/i, cause: 'Java stack trace' },
      
      // Security bypass indicators
      { pattern: /authentication bypass/i, cause: 'Auth bypass attempt detected' },
      { pattern: /unauthorized access/i, cause: 'Access control issue' },
      
      // Injection success indicators
      { pattern: /command not found/i, cause: 'OS command injection' },
      { pattern: /root:x:/i, cause: '/etc/passwd disclosure' },
      { pattern: /\[boot loader\]/i, cause: '/boot.ini disclosure' }
    ];
    
    responses.forEach(response => {
      if (!response.data) return;
      
      const data = response.data.toString().toLowerCase();
      
      suspiciousPatterns.forEach(({ pattern, cause }) => {
        if (pattern.test(data)) {
          this.anomalies.push({
            type: 'content_anomaly',
            severity: 'high',
            description: `Suspicious pattern detected: ${pattern.source}`,
            payload: response.payload,
            potentialCause: cause,
            confidence: 85,
            details: {
              pattern: pattern.source,
              matched: true
            }
          });
        }
      });
    });
  }

  detectHeaderAnomalies(responses) {
    // Collect all unique headers across responses
    const headerFrequency = {};
    
    responses.forEach(response => {
      if (response.headers) {
        Object.keys(response.headers).forEach(header => {
          headerFrequency[header] = (headerFrequency[header] || 0) + 1;
        });
      }
    });
    
    // Detect missing or extra headers
    responses.forEach(response => {
      if (!response.headers) return;
      
      const headers = Object.keys(response.headers);
      
      // Check for security-critical headers that disappeared
      const criticalHeaders = ['x-frame-options', 'content-security-policy', 'x-content-type-options'];
      criticalHeaders.forEach(header => {
        if (headerFrequency[header] > responses.length * 0.5 && !headers.includes(header)) {
          this.anomalies.push({
            type: 'header_anomaly',
            severity: 'medium',
            description: `Security header disappeared: ${header}`,
            payload: response.payload,
            potentialCause: 'Payload bypassed security middleware or triggered different code path',
            confidence: 75
          });
        }
      });
      
      // Check for unusual new headers
      headers.forEach(header => {
        if ((headerFrequency[header] || 0) < responses.length * 0.1) {
          this.anomalies.push({
            type: 'header_anomaly',
            severity: 'low',
            description: `Unusual header appeared: ${header}`,
            payload: response.payload,
            potentialCause: 'Different processing logic triggered',
            confidence: 60
          });
        }
      });
    });
  }

  calculateAnomalySeverity(zScore) {
    if (zScore > 5) return 'critical';
    if (zScore > 4) return 'high';
    if (zScore > 3) return 'medium';
    return 'low';
  }

  // Statistical helper functions
  mean(arr) {
    return arr.reduce((sum, val) => sum + val, 0) / arr.length;
  }

  standardDeviation(arr) {
    const avg = this.mean(arr);
    const squaredDiffs = arr.map(val => Math.pow(val - avg, 2));
    const variance = this.mean(squaredDiffs);
    return Math.sqrt(variance);
  }

  median(arr) {
    const sorted = [...arr].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0 
      ? (sorted[mid - 1] + sorted[mid]) / 2 
      : sorted[mid];
  }

  mode(arr) {
    const frequency = {};
    let maxFreq = 0;
    let mode = arr[0];
    
    arr.forEach(val => {
      frequency[val] = (frequency[val] || 0) + 1;
      if (frequency[val] > maxFreq) {
        maxFreq = frequency[val];
        mode = val;
      }
    });
    
    return mode;
  }

  distribution(arr) {
    const dist = {};
    arr.forEach(val => {
      dist[val] = (dist[val] || 0) + 1;
    });
    return dist;
  }

  /**
   * Predict if anomalies indicate potential 0-day
   */
  predict0day() {
    const criticalAnomalies = this.anomalies.filter(a => 
      a.severity === 'critical' || a.severity === 'high'
    );
    
    if (criticalAnomalies.length === 0) return null;
    
    // Cluster anomalies by type
    const clusters = {};
    criticalAnomalies.forEach(anomaly => {
      const key = anomaly.type;
      clusters[key] = clusters[key] || [];
      clusters[key].push(anomaly);
    });
    
    // If multiple anomaly types for same payload, high likelihood of 0-day
    const payloadAnomalyCounts = {};
    criticalAnomalies.forEach(anomaly => {
      const payload = anomaly.payload || 'unknown';
      payloadAnomalyCounts[payload] = (payloadAnomalyCounts[payload] || 0) + 1;
    });
    
    const suspiciousPayloads = Object.entries(payloadAnomalyCounts)
      .filter(([_, count]) => count >= 2)
      .map(([payload, count]) => ({ payload, anomalyCount: count }));
    
    if (suspiciousPayloads.length > 0) {
      return {
        likelihood: 'high',
        confidence: 75,
        suspiciousPayloads,
        reasoning: `Multiple anomaly types detected for same payloads. This behavior is unusual and may indicate an unknown vulnerability.`,
        recommendation: 'Manual verification recommended. Payload triggers multiple anomalous behaviors.',
        anomalies: criticalAnomalies
      };
    }
    
    return null;
  }
}

module.exports = AnomalyDetector;
