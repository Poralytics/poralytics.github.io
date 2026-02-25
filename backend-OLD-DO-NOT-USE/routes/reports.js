/**
 * REPORTS ROUTES - PDF + JSON + CSV export
 */
const express = require('express');
const router = express.Router();
const db = require('../config/database');
const { auth } = require('../middleware/auth');
const { asyncHandler, logger } = require('../utils/error-handler');

// Generate PDF report
router.get('/:scanId/pdf', auth, asyncHandler(async (req, res) => {
  const scan = db.prepare(`
    SELECT s.*, d.url, d.name as domain_name, d.user_id
    FROM scans s JOIN domains d ON s.domain_id = d.id
    WHERE s.id = ? AND d.user_id = ?
  `).get(req.params.scanId, req.user.userId);

  if (!scan) return res.status(404).json({ error: 'Scan not found' });
  if (scan.status !== 'completed') return res.status(400).json({ error: 'Scan not completed yet' });

  const domain = db.prepare('SELECT * FROM domains WHERE id = ?').get(scan.domain_id);
  const vulns = db.prepare(`
    SELECT * FROM vulnerabilities WHERE scan_id = ?
    ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END
  `).all(scan.id);
  const user = db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(req.user.userId);

  const PDFGenerator = require('../services/pdf-report-generator');
  const pdfBuffer = await PDFGenerator.generateScanReport(scan, domain, vulns, user);

  const filename = `nexus-report-${domain.name || 'scan'}-${new Date().toISOString().split('T')[0]}.pdf`;
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Length', pdfBuffer.length);
  res.send(pdfBuffer);
}));

// JSON report
router.get('/:scanId/json', auth, asyncHandler(async (req, res) => {
  const scan = db.prepare(`
    SELECT s.*, d.url, d.name as domain_name FROM scans s
    JOIN domains d ON s.domain_id = d.id WHERE s.id = ? AND d.user_id = ?
  `).get(req.params.scanId, req.user.userId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY cvss_score DESC').all(scan.id);
  res.json({
    report: { generated_at: new Date(), scan_id: scan.id, tool: 'NEXUS v2.1', url: scan.url },
    summary: { total: scan.total_vulns, critical: scan.critical_count, high: scan.high_count, medium: scan.medium_count, low: scan.low_count, score: scan.security_score },
    vulnerabilities: vulns
  });
}));

// CSV report
router.get('/:scanId/csv', auth, asyncHandler(async (req, res) => {
  const scan = db.prepare(`
    SELECT s.*, d.url FROM scans s JOIN domains d ON s.domain_id = d.id WHERE s.id = ? AND d.user_id = ?
  `).get(req.params.scanId, req.user.userId);
  if (!scan) return res.status(404).json({ error: 'Scan not found' });

  const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scan.id);
  const escape = v => `"${String(v || '').replace(/"/g, '""')}"`;
  const header = ['ID', 'Severity', 'Category', 'Title', 'CVSS', 'Confidence', 'Parameter', 'OWASP', 'CWE', 'Remediation'].join(',');
  const rows = vulns.map(v => [v.id, v.severity, v.category, v.title, v.cvss_score, v.confidence, v.parameter, v.owasp_category, v.cwe_id, v.remediation_text].map(escape).join(','));
  const csv = [header, ...rows].join('\n');

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="nexus-report-${scan.id}.csv"`);
  res.send(csv);
}));

module.exports = router;
