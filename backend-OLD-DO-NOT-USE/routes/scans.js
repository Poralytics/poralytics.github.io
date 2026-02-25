/**
 * SCANS ROUTES - AVEC VRAIS SCANNERS
 */

const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { auth } = require('../middleware/auth');
const ScannerOrchestrator = require('../scanners/orchestrator');

const scannerOrchestrator = new ScannerOrchestrator();

// Liste des scans
router.get('/', auth, async (req, res) => {
  try {
    const scans = db.prepare(`
      SELECT s.*, d.url, d.name as domain_name
      FROM scans s
      JOIN domains d ON s.domain_id = d.id
      WHERE s.user_id = ?
      ORDER BY s.created_at DESC
      LIMIT 50
    `).all(req.user.userId);

    res.json({ scans });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Démarrer un scan
router.post('/start', auth, async (req, res) => {
  try {
    const { domain_id } = req.body;
    if (!domain_id) {
      return res.status(400).json({ error: 'domain_id required' });
    }

    // Vérifier que le domaine appartient à l'utilisateur
    const domain = db.prepare(
      'SELECT * FROM domains WHERE id = ? AND user_id = ?'
    ).get(domain_id, req.user.userId);

    if (!domain) {
      return res.status(404).json({ error: 'Domain not found' });
    }

    // Créer l'entrée scan
    const result = db.prepare(`
      INSERT INTO scans (domain_id, user_id, status, progress, created_at, started_at)
      VALUES (?, ?, 'running', 0, ?, ?)
    `).run(
      domain_id,
      req.user.userId,
      Math.floor(Date.now() / 1000),
      Math.floor(Date.now() / 1000)
    );

    const scanId = result.lastInsertRowid;

    // Lancer le scan en arrière-plan
    setImmediate(async () => {
      try {
        console.log(`[Scan ${scanId}] Starting scan for ${domain.url}`);

        const scanResults = await scannerOrchestrator.scanUrl(
          domain.url,
          (progress) => {
            // Mettre à jour la progression dans la DB
            db.prepare(
              'UPDATE scans SET progress = ? WHERE id = ?'
            ).run(progress.progress, scanId);
          }
        );

        // Enregistrer les vulnérabilités
        for (const vuln of scanResults.vulnerabilities) {
          db.prepare(`
            INSERT INTO vulnerabilities (
              scan_id, type, severity, title, description,
              url, evidence, recommendation, created_at, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
          `).run(
            scanId,
            vuln.type,
            vuln.severity,
            vuln.title,
            vuln.description,
            vuln.url || domain.url,
            vuln.evidence || '',
            vuln.recommendation || '',
            Math.floor(Date.now() / 1000)
          );
        }

        // Mettre à jour le scan comme complété
        db.prepare(`
          UPDATE scans 
          SET status = 'completed',
              progress = 100,
              vulnerabilities_found = ?,
              completed_at = ?
          WHERE id = ?
        `).run(
          scanResults.vulnerabilities.length,
          Math.floor(Date.now() / 1000),
          scanId
        );

        console.log(`[Scan ${scanId}] Completed - Found ${scanResults.vulnerabilities.length} vulnerabilities`);

      } catch (error) {
        console.error(`[Scan ${scanId}] Error:`, error);
        db.prepare(
          "UPDATE scans SET status = 'failed', progress = 0 WHERE id = ?"
        ).run(scanId);
      }
    });

    res.json({
      success: true,
      scan_id: scanId,
      status: 'running',
      message: 'Scan started'
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtenir le statut d'un scan
router.get('/:scanId', auth, async (req, res) => {
  try {
    const scan = db.prepare(`
      SELECT s.*, d.url, d.name as domain_name
      FROM scans s
      JOIN domains d ON s.domain_id = d.id
      WHERE s.id = ? AND s.user_id = ?
    `).get(req.params.scanId, req.user.userId);

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    // Si le scan est terminé, récupérer les vulnérabilités
    let vulnerabilities = [];
    if (scan.status === 'completed') {
      vulnerabilities = db.prepare(
        'SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity'
      ).all(scan.id);
    }

    res.json({
      scan,
      vulnerabilities
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtenir les résultats d'un scan
router.get('/:scanId/results', auth, async (req, res) => {
  try {
    const scan = db.prepare(`
      SELECT s.*, d.url
      FROM scans s
      JOIN domains d ON s.domain_id = d.id
      WHERE s.id = ? AND s.user_id = ?
    `).get(req.params.scanId, req.user.userId);

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    const vulnerabilities = db.prepare(
      'SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity'
    ).all(scan.id);

    const stats = {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length
    };

    res.json({
      scan,
      vulnerabilities,
      statistics: stats
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
