/**
 * REAL WEBSOCKET SERVER v2.1
 * Real-time scan progress, alerts, and notifications
 */
const jwt = require('jsonwebtoken');
const { logger } = require('../utils/error-handler');

class RealWebSocketServer {
  constructor() {
    this.wss = null;
    this.connections = new Map(); // userId -> Set<ws>
    this.initialized = false;
  }

  initialize(httpServer) {
    try {
      const WebSocket = require('ws');
      this.wss = new WebSocket.Server({ server: httpServer, path: '/ws' });
      this.wss.on('connection', (ws, req) => this.handleConnection(ws, req));
      this.initialized = true;
      logger.logInfo('WebSocket server initialized on /ws');
    } catch (err) {
      logger.logError(err, { context: 'WebSocket init' });
    }
  }

  handleConnection(ws, req) {
    ws.isAlive = true;
    ws.userId = null;

    ws.on('pong', () => { ws.isAlive = true; });

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'auth' && msg.token) {
          const secret = process.env.JWT_SECRET || 'CHANGE_ME_SET_JWT_SECRET_IN_ENV_FILE';
          const decoded = jwt.verify(msg.token, secret, { algorithms: ['HS256'] });
          ws.userId = decoded.userId;
          if (!this.connections.has(ws.userId)) {
            this.connections.set(ws.userId, new Set());
          }
          this.connections.get(ws.userId).add(ws);
          ws.send(JSON.stringify({ type: 'auth_ok', userId: ws.userId }));
          logger.logInfo('WS client authenticated', { userId: ws.userId });
        }
      } catch (e) {
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid message or auth failed' }));
      }
    });

    ws.on('close', () => {
      if (ws.userId && this.connections.has(ws.userId)) {
        this.connections.get(ws.userId).delete(ws);
        if (this.connections.get(ws.userId).size === 0) {
          this.connections.delete(ws.userId);
        }
      }
    });

    ws.on('error', (err) => {
      logger.logError(err, { context: 'WebSocket connection error' });
    });

    // Send welcome
    ws.send(JSON.stringify({ type: 'connected', message: 'NEXUS WebSocket v2.1', timestamp: new Date() }));
  }

  sendToUser(userId, data) {
    if (!this.initialized || !this.connections.has(userId)) return;
    const msg = JSON.stringify(data);
    this.connections.get(userId).forEach(ws => {
      try {
        if (ws.readyState === 1) ws.send(msg); // OPEN
      } catch (e) {}
    });
  }

  broadcast(data) {
    if (!this.initialized || !this.wss) return;
    const msg = JSON.stringify(data);
    this.wss.clients.forEach(ws => {
      try {
        if (ws.readyState === 1) ws.send(msg);
      } catch (e) {}
    });
  }

  sendScanProgress(userId, scanId, progress, phase, stats = {}) {
    this.sendToUser(userId, { type: 'scan_progress', scanId, progress, phase, stats, timestamp: new Date() });
  }

  sendScanComplete(userId, scanId, stats, securityScore) {
    this.sendToUser(userId, { type: 'scan_complete', scanId, stats, securityScore, timestamp: new Date() });
  }

  sendAlert(userId, severity, message, data = {}) {
    this.sendToUser(userId, { type: 'alert', severity, message, data, timestamp: new Date() });
  }

  getStats() {
    return {
      initialized: this.initialized,
      totalConnections: this.wss ? this.wss.clients.size : 0,
      authenticatedUsers: this.connections.size
    };
  }

  cleanup() {
    if (!this.initialized) return;
    // Ping all connections for heartbeat
    this.wss.clients.forEach(ws => {
      if (!ws.isAlive) return ws.terminate();
      ws.isAlive = false;
      ws.ping();
    });
  }
}

const wsServer = new RealWebSocketServer();
module.exports = wsServer;
