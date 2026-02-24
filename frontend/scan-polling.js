/**
 * SCAN POLLING SERVICE
 * Polling intelligent avec arrêt automatique
 */

class ScanPollingService {
  constructor() {
    this.activePoll = null;
    this.pollAttempts = 0;
    this.maxAttempts = 60; // 60 * 5s = 5 minutes max
  }

  /**
   * Start polling a scan until it completes
   */
  async startPolling(scanId, onUpdate, onComplete, onError) {
    this.stopPolling(); // Stop any existing poll
    this.pollAttempts = 0;

    const pollInterval = 5000; // 5 seconds

    const poll = async () => {
      try {
        this.pollAttempts++;

        // Max attempts reached
        if (this.pollAttempts > this.maxAttempts) {
          console.log('Max poll attempts reached, stopping');
          this.stopPolling();
          onError(new Error('Scan timeout - please check the scans page'));
          return;
        }

        const token = localStorage.getItem('token');
        const res = await fetch(`/api/scans/${scanId}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) {
          throw new Error('Failed to fetch scan status');
        }

        const data = await res.json();
        const scan = data.scan;

        // Update progress
        onUpdate(scan);

        // Check if completed
        if (scan.status === 'completed') {
          console.log('Scan completed!');
          this.stopPolling();
          onComplete(scan);
          return;
        }

        // Check if failed
        if (scan.status === 'failed') {
          console.log('Scan failed');
          this.stopPolling();
          onError(new Error('Scan failed'));
          return;
        }

        // Continue polling if still running
        if (scan.status === 'running' || scan.status === 'pending') {
          this.activePoll = setTimeout(poll, pollInterval);
        }

      } catch (error) {
        console.error('Poll error:', error);
        this.stopPolling();
        onError(error);
      }
    };

    // Start first poll
    poll();
  }

  /**
   * Stop active polling
   */
  stopPolling() {
    if (this.activePoll) {
      clearTimeout(this.activePoll);
      this.activePoll = null;
    }
    this.pollAttempts = 0;
  }
}

// Export singleton
window.scanPollingService = new ScanPollingService();
