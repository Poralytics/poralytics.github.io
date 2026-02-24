/**
 * REAL-TIME DASHBOARD SERVICE
 * 
 * UPGRADE MAJEUR: WebSocket pour mises à jour en temps réel
 * 
 * Features:
 * - Live scan progress
 * - Real-time vulnerability alerts
 * - Team activity feed
 * - Security score updates
 * - Attack simulation events
 * - Compliance status changes
 * 
 * DIFFÉRENCIATION: Competitors n'ont pas de real-time dashboard
 */

let WebSocket;
try {
  WebSocket = require('ws');
} catch {
  console.warn('⚠️  WebSocket (ws) not installed, real-time features disabled');
  WebSocket = null;
}

class RealTimeDashboard {
  constructor(server) {
    this.connections = new Map(); // userId -> Set of WebSocket connections
    this.wss = null;

    if (WebSocket && server) {
      this.initialize(server);
    } else {
      console.log('📊 Dashboard running in polling mode (no WebSocket)');
    }
  }

  initialize(server) {
    try {
      this.wss = new WebSocket.Server({ 
        server,
        path: '/ws',
        clientTracking: true
      });

      this.wss.on('connection', (ws, req) => {
        this.handleConnection(ws, req);
      });

      console.log('✅ Real-time dashboard WebSocket server initialized');
    } catch (error) {
      console.error('Failed to initialize WebSocket:', error.message);
    }
  }

  handleConnection(ws, req) {
    let userId = null;

    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);

        if (data.type === 'auth') {
          userId = data.userId;
          this.registerConnection(userId, ws);
          
          ws.send(JSON.stringify({
            type: 'connected',
            message: 'Real-time updates active',
            timestamp: Date.now()
          }));
        }
      } catch (error) {
        console.error('WebSocket message error:', error.message);
      }
    });

    ws.on('close', () => {
      if (userId) {
        this.unregisterConnection(userId, ws);
      }
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error.message);
    });
  }

  registerConnection(userId, ws) {
    if (!this.connections.has(userId)) {
      this.connections.set(userId, new Set());
    }
    this.connections.get(userId).add(ws);
    console.log(`📡 User ${userId} connected (${this.connections.get(userId).size} connections)`);
  }

  unregisterConnection(userId, ws) {
    if (this.connections.has(userId)) {
      this.connections.get(userId).delete(ws);
      if (this.connections.get(userId).size === 0) {
        this.connections.delete(userId);
      }
      console.log(`📡 User ${userId} disconnected`);
    }
  }

  /**
   * Send update to specific user
   */
  sendToUser(userId, event) {
    if (!this.wss) {
      return; // WebSocket not available
    }

    const connections = this.connections.get(userId);
    if (!connections || connections.size === 0) {
      return; // User not connected
    }

    const message = JSON.stringify({
      ...event,
      timestamp: Date.now()
    });

    connections.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(message);
        } catch (error) {
          console.error('Failed to send message:', error.message);
        }
      }
    });
  }

  /**
   * Broadcast to all connected users
   */
  broadcast(event) {
    if (!this.wss) {
      return;
    }

    const message = JSON.stringify({
      ...event,
      timestamp: Date.now()
    });

    this.wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(message);
        } catch (error) {
          console.error('Broadcast error:', error.message);
        }
      }
    });
  }

  // ========== EVENT METHODS ==========

  /**
   * Scan progress update
   */
  scanProgress(userId, scanId, progress) {
    this.sendToUser(userId, {
      type: 'scan_progress',
      scanId,
      progress,
      phase: progress.phase,
      percentage: progress.percentage
    });
  }

  /**
   * New vulnerability found
   */
  vulnerabilityFound(userId, vulnerability) {
    this.sendToUser(userId, {
      type: 'vulnerability_found',
      vulnerability: {
        id: vulnerability.id,
        severity: vulnerability.severity,
        title: vulnerability.title,
        category: vulnerability.category
      }
    });
  }

  /**
   * Security score updated
   */
  scoreUpdated(userId, domainId, newScore, oldScore) {
    this.sendToUser(userId, {
      type: 'score_updated',
      domainId,
      newScore,
      oldScore,
      change: newScore - oldScore
    });
  }

  /**
   * Attack simulation event
   */
  simulationEvent(userId, simulationId, event) {
    this.sendToUser(userId, {
      type: 'simulation_event',
      simulationId,
      event: event.type,
      data: event.data
    });
  }

  /**
   * Compliance status change
   */
  complianceUpdate(userId, framework, status) {
    this.sendToUser(userId, {
      type: 'compliance_update',
      framework,
      status,
      score: status.score
    });
  }

  /**
   * Team activity
   */
  teamActivity(teamId, activity) {
    // Send to all team members
    const db = require('../config/database');
    try {
      const members = db.prepare('SELECT id FROM users WHERE team_id = ?').all(teamId);
      
      members.forEach(member => {
        this.sendToUser(member.id, {
          type: 'team_activity',
          activity
        });
      });
    } catch (error) {
      console.error('Team activity broadcast error:', error.message);
    }
  }

  /**
   * Critical alert
   */
  criticalAlert(userId, alert) {
    this.sendToUser(userId, {
      type: 'critical_alert',
      alert: {
        title: alert.title,
        message: alert.message,
        severity: 'critical',
        actionRequired: alert.actionRequired
      }
    });
  }

  /**
   * Threat intelligence alert
   */
  threatAlert(userId, threat) {
    this.sendToUser(userId, {
      type: 'threat_alert',
      threat: {
        category: threat.category,
        severity: threat.severity,
        description: threat.description
      }
    });
  }

  /**
   * Get connection stats
   */
  getStats() {
    if (!this.wss) {
      return {
        enabled: false,
        message: 'WebSocket not available'
      };
    }

    return {
      enabled: true,
      totalConnections: this.wss.clients.size,
      uniqueUsers: this.connections.size,
      averageConnectionsPerUser: this.wss.clients.size / Math.max(1, this.connections.size)
    };
  }
}

// Export singleton
let instance = null;

module.exports = {
  initialize: (server) => {
    if (!instance) {
      instance = new RealTimeDashboard(server);
    }
    return instance;
  },
  getInstance: () => {
    if (!instance) {
      instance = new RealTimeDashboard(null);
    }
    return instance;
  }
};
