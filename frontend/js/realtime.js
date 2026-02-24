/**
 * REAL-TIME WEBSOCKET CLIENT
 * Manages WebSocket connection with automatic reconnection
 */

class RealTimeClient {
  constructor() {
    this.ws = null;
    this.authenticated = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 2000;
    this.listeners = new Map();
    this.messageQueue = [];
    
    this.connect();
  }

  /**
   * Connect to WebSocket server
   */
  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws`;

    console.log('[WebSocket] Connecting to', wsUrl);

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('[WebSocket] Connected');
        this.reconnectAttempts = 0;
        this.authenticate();
      };

      this.ws.onmessage = (event) => {
        this.handleMessage(event.data);
      };

      this.ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error);
      };

      this.ws.onclose = () => {
        console.log('[WebSocket] Disconnected');
        this.authenticated = false;
        this.attemptReconnect();
      };
    } catch (error) {
      console.error('[WebSocket] Connection error:', error);
      this.attemptReconnect();
    }
  }

  /**
   * Authenticate with JWT token
   */
  authenticate() {
    const token = localStorage.getItem('token');
    
    if (!token) {
      console.error('[WebSocket] No auth token found');
      return;
    }

    this.send({
      type: 'auth',
      token: token
    });
  }

  /**
   * Handle incoming message
   */
  handleMessage(data) {
    try {
      const message = JSON.parse(data);
      
      if (message.type === 'authenticated') {
        this.authenticated = true;
        console.log('[WebSocket] Authenticated');
        this.emit('authenticated', message);
        this.flushQueue();
      } else if (message.type === 'auth_failed') {
        console.error('[WebSocket] Authentication failed');
        this.emit('auth_failed', message);
      } else if (message.type === 'ping') {
        // Respond to ping to keep connection alive
        this.send({ type: 'pong' });
      } else {
        // Emit specific event
        this.emit(message.type, message);
      }
    } catch (error) {
      console.error('[WebSocket] Message parse error:', error);
    }
  }

  /**
   * Send message to server
   */
  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      if (!this.authenticated && message.type !== 'auth') {
        this.messageQueue.push(message);
        return;
      }
      
      this.ws.send(JSON.stringify(message));
    } else {
      this.messageQueue.push(message);
    }
  }

  /**
   * Flush queued messages
   */
  flushQueue() {
    while (this.messageQueue.length > 0) {
      const message = this.messageQueue.shift();
      this.send(message);
    }
  }

  /**
   * Attempt to reconnect
   */
  attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[WebSocket] Max reconnect attempts reached');
      this.emit('max_reconnect_attempts');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * this.reconnectAttempts;

    console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

    setTimeout(() => {
      this.connect();
    }, delay);
  }

  /**
   * Register event listener
   */
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);
  }

  /**
   * Unregister event listener
   */
  off(event, callback) {
    if (this.listeners.has(event)) {
      const callbacks = this.listeners.get(event);
      const index = callbacks.indexOf(callback);
      if (index > -1) {
        callbacks.splice(index, 1);
      }
    }
  }

  /**
   * Emit event to listeners
   */
  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`[WebSocket] Listener error for ${event}:`, error);
        }
      });
    }
  }

  /**
   * Close connection
   */
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Get connection status
   */
  isConnected() {
    return this.ws && this.ws.readyState === WebSocket.OPEN && this.authenticated;
  }
}

// Create global instance
const realTimeClient = new RealTimeClient();

// Listen for scan events
realTimeClient.on('scan_progress', (data) => {
  console.log('[Real-time] Scan progress:', data);
  
  // Update UI
  const progressBar = document.querySelector(`[data-scan-id="${data.scanId}"] .progress-bar`);
  if (progressBar) {
    progressBar.style.width = `${data.progress}%`;
    progressBar.textContent = `${data.progress}%`;
  }

  const phaseText = document.querySelector(`[data-scan-id="${data.scanId}"] .scan-phase`);
  if (phaseText) {
    phaseText.textContent = data.phase || 'Scanning...';
  }
});

realTimeClient.on('scan_completed', (data) => {
  console.log('[Real-time] Scan completed:', data);
  
  // Show notification
  if (typeof showNotification === 'function') {
    showNotification('success', `Scan completed with score: ${data.securityScore}`);
  }

  // Reload scan results
  if (typeof loadScans === 'function') {
    loadScans();
  }
});

realTimeClient.on('scan_failed', (data) => {
  console.log('[Real-time] Scan failed:', data);
  
  // Show error notification
  if (typeof showNotification === 'function') {
    showNotification('error', `Scan failed: ${data.error}`);
  }
});

// Export for use in other scripts
window.realTimeClient = realTimeClient;
