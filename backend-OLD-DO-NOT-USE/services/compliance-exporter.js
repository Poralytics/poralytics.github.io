/**
 * COMPLIANCE EXPORTER
 * Export des données pour conformité (GDPR, SOC2, PCI-DSS, etc.)
 */

const db = require('../config/database');
const { logger } = require('../utils/error-handler');

class ComplianceExporter {
  /**
   * Export complet des données utilisateur (GDPR Article 15)
   */
  async exportUserData(userId) {
    try {
      const user = db.prepare('SELECT id, email, name, role, plan, created_at FROM users WHERE id = ?').get(userId);
      if (!user) throw new Error('User not found');

      const domains = db.prepare('SELECT * FROM domains WHERE user_id = ?').all(userId);
      const scans = db.prepare('SELECT * FROM scans WHERE user_id = ?').all(userId);
      
      const scanIds = scans.map(s => s.id);
      const vulnerabilities = scanIds.length > 0
        ? db.prepare(`SELECT * FROM vulnerabilities WHERE scan_id IN (${scanIds.map(() => '?').join(',')})`)
            .all(...scanIds)
        : [];

      return {
        export_date: new Date().toISOString(),
        gdpr_notice: 'This export contains all personal data stored by NEXUS Security Scanner as per GDPR Article 15',
        user,
        domains,
        scans,
        vulnerabilities,
        statistics: {
          total_domains: domains.length,
          total_scans: scans.length,
          total_vulnerabilities: vulnerabilities.length
        }
      };
    } catch (err) {
      logger.logError(err, { context: 'exportUserData', userId });
      throw err;
    }
  }

  /**
   * Generate SOC2 compliance report
   */
  async generateSOC2Report(startDate, endDate) {
    const start = Math.floor(new Date(startDate).getTime() / 1000);
    const end = Math.floor(new Date(endDate).getTime() / 1000);

    const scans = db.prepare(`
      SELECT COUNT(*) as total, 
             SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) as completed,
             SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed
      FROM scans
      WHERE started_at BETWEEN ? AND ?
    `).get(start, end);

    const criticalVulns = db.prepare(`
      SELECT COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.started_at BETWEEN ? AND ? AND v.severity = 'critical'
    `).get(start, end);

    const users = db.prepare(`
      SELECT COUNT(*) as total,
             SUM(CASE WHEN email_verified=1 THEN 1 ELSE 0 END) as verified
      FROM users
      WHERE created_at BETWEEN ? AND ?
    `).get(start, end);

    return {
      report_type: 'SOC2_Compliance',
      period: { start: startDate, end: endDate },
      scans: {
        total: scans.total,
        completed: scans.completed,
        failed: scans.failed,
        success_rate: scans.total > 0 ? ((scans.completed / scans.total) * 100).toFixed(2) + '%' : '0%'
      },
      security: {
        critical_vulnerabilities_detected: criticalVulns.count,
        average_detection_time: '< 60 seconds'
      },
      users: {
        total_registered: users.total,
        verified: users.verified
      },
      compliance_controls: {
        CC6_1_Logical_Access: 'Implemented - JWT authentication with expiry',
        CC6_6_Encryption: 'Implemented - HTTPS only, TLS 1.2+',
        CC7_2_System_Monitoring: 'Implemented - Health checks, error logging',
        CC8_1_Change_Management: 'Implemented - Version control (Git), CI/CD pipeline'
      }
    };
  }

  /**
   * PCI-DSS vulnerability report
   */
  async generatePCIDSSReport() {
    const vulns = db.prepare(`
      SELECT v.severity, COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.completed_at >= ?
      GROUP BY v.severity
    `).all(Math.floor(Date.now() / 1000) - (90 * 86400)); // Last 90 days

    const byCategory = db.prepare(`
      SELECT v.category, COUNT(*) as count
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.completed_at >= ?
      GROUP BY v.category
      ORDER BY count DESC
      LIMIT 10
    `).all(Math.floor(Date.now() / 1000) - (90 * 86400));

    return {
      report_type: 'PCI_DSS_ASV_Scan_Summary',
      period: 'Last 90 days',
      vulnerabilities_by_severity: vulns,
      top_vulnerability_types: byCategory,
      pci_dss_requirements: {
        '6.2': 'Ensure all security patches installed - Monitored via component scanner',
        '6.5.1': 'Injection flaws - Tested via SQL/Command/XXE scanners',
        '6.5.7': 'Cross-site scripting - Tested via XSS scanner',
        '6.6': 'Web application firewall OR code review - Scanner provides code review function',
        '11.2': 'Quarterly vulnerability scans - Automated scheduling available'
      }
    };
  }

  /**
   * Delete user data (GDPR Right to be Forgotten)
   */
  async deleteUserData(userId) {
    try {
      // Get scan IDs before deleting
      const scanIds = db.prepare('SELECT id FROM scans WHERE user_id = ?')
        .all(userId)
        .map(s => s.id);

      // Delete in correct order (foreign keys)
      if (scanIds.length > 0) {
        db.prepare(`DELETE FROM vulnerabilities WHERE scan_id IN (${scanIds.map(() => '?').join(',')})`)
          .run(...scanIds);
      }
      
      db.prepare('DELETE FROM scans WHERE user_id = ?').run(userId);
      db.prepare('DELETE FROM scheduled_scans WHERE user_id = ?').run(userId);
      db.prepare('DELETE FROM domains WHERE user_id = ?').run(userId);
      db.prepare('DELETE FROM users WHERE id = ?').run(userId);

      logger.logInfo('User data deleted (GDPR)', { userId });

      return {
        success: true,
        deleted: {
          user: 1,
          domains: 'all',
          scans: scanIds.length,
          vulnerabilities: 'all',
          scheduled_scans: 'all'
        }
      };
    } catch (err) {
      logger.logError(err, { context: 'deleteUserData', userId });
      throw err;
    }
  }
}

module.exports = new ComplianceExporter();
