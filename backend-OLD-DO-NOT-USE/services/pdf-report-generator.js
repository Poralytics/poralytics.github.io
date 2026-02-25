/**
 * PDF REPORT GENERATOR
 * Generates professional security audit reports
 */
const { logger } = require('../utils/error-handler');

class PDFReportGenerator {
  constructor() {
    this.colors = {
      critical: '#DC2626', high: '#EA580C',
      medium: '#D97706', low: '#65A30D', info: '#3B82F6'
    };
  }

  async generateScanReport(scan, domain, vulnerabilities, user) {
    try {
      const PDFDocument = require('pdfkit');
      const chunks = [];
      const doc = new PDFDocument({ margin: 50, size: 'A4' });

      doc.on('data', chunk => chunks.push(chunk));

      await new Promise((resolve, reject) => {
        doc.on('end', resolve);
        doc.on('error', reject);

        // ── COVER PAGE ──
        doc.rect(0, 0, doc.page.width, 200).fill('#0F172A');
        doc.fillColor('white').fontSize(28).font('Helvetica-Bold')
          .text('NEXUS SECURITY REPORT', 50, 60);
        doc.fontSize(16).font('Helvetica')
          .text(domain.url || 'Security Audit', 50, 100);
        doc.fontSize(12)
          .text(`Generated: ${new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`, 50, 130)
          .text(`Scan ID: #${scan.id}`, 50, 150);

        // Security Score Badge
        const score = scan.security_score || 0;
        const scoreColor = score >= 800 ? '#10B981' : score >= 600 ? '#F59E0B' : '#EF4444';
        doc.fillColor(scoreColor).fontSize(48).font('Helvetica-Bold')
          .text(score.toString(), 400, 70, { width: 100, align: 'center' });
        doc.fillColor('white').fontSize(12).font('Helvetica')
          .text('Security Score', 380, 130, { width: 140, align: 'center' });

        doc.fillColor('#0F172A').rect(0, 200, doc.page.width, doc.page.height).fill();

        // ── EXECUTIVE SUMMARY ──
        doc.addPage();
        doc.fillColor('#0F172A').fontSize(20).font('Helvetica-Bold').text('Executive Summary', 50, 50);
        doc.moveTo(50, 75).lineTo(545, 75).stroke('#E2E8F0');

        const riskLevel = scan.risk_level || 'unknown';
        const riskColors = { low: '#10B981', medium: '#F59E0B', high: '#EF4444', critical: '#7C3AED' };

        doc.fillColor('#1E293B').fontSize(12).font('Helvetica').text(
          `This security assessment was conducted on ${domain.url} using NEXUS automated scanner v2.1. ` +
          `The scan identified ${scan.total_vulns || 0} vulnerabilities across ${vulnerabilities.length} unique findings.`,
          50, 90, { width: 495, lineGap: 4 }
        );

        // Stats boxes
        const severities = [
          { label: 'Critical', key: 'critical_count', color: this.colors.critical },
          { label: 'High', key: 'high_count', color: this.colors.high },
          { label: 'Medium', key: 'medium_count', color: this.colors.medium },
          { label: 'Low', key: 'low_count', color: this.colors.low }
        ];
        let boxX = 50;
        severities.forEach(sev => {
          doc.roundedRect(boxX, 140, 110, 70, 8).fill(sev.color);
          doc.fillColor('white').fontSize(32).font('Helvetica-Bold')
            .text((scan[sev.key] || 0).toString(), boxX, 150, { width: 110, align: 'center' });
          doc.fontSize(11).font('Helvetica')
            .text(sev.label, boxX, 185, { width: 110, align: 'center' });
          boxX += 125;
        });

        // Risk Level
        doc.fillColor('#1E293B').fontSize(14).font('Helvetica-Bold').text('Overall Risk Level:', 50, 235);
        doc.fillColor(riskColors[riskLevel] || '#94A3B8').fontSize(14)
          .text(riskLevel.toUpperCase(), 190, 235);

        // ── VULNERABILITIES TABLE ──
        doc.addPage();
        doc.fillColor('#0F172A').fontSize(20).font('Helvetica-Bold').text('Vulnerability Findings', 50, 50);
        doc.moveTo(50, 75).lineTo(545, 75).stroke('#E2E8F0');

        // Table header
        doc.fillColor('#1E293B').rect(50, 85, 495, 28).fill();
        doc.fillColor('white').fontSize(10).font('Helvetica-Bold');
        doc.text('#', 55, 93).text('Severity', 75, 93).text('Category', 145, 93)
          .text('Title', 235, 93).text('CVSS', 480, 93);

        let y = 120;
        const sortedVulns = [...vulnerabilities].sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          return (order[a.severity] || 5) - (order[b.severity] || 5);
        });

        sortedVulns.slice(0, 40).forEach((vuln, idx) => {
          if (y > 750) { doc.addPage(); y = 50; }
          if (idx % 2 === 0) doc.fillColor('#F8FAFC').rect(50, y - 3, 495, 22).fill();
          const sevColor = this.colors[vuln.severity] || '#64748B';
          doc.fillColor(sevColor).rect(145, y - 1, 80, 16).fill();
          doc.fillColor(sevColor).fontSize(9).font('Helvetica-Bold')
            .text(idx + 1, 55, y, { width: 15 });
          doc.fillColor(sevColor).fontSize(8).font('Helvetica-Bold')
            .text((vuln.severity || '').toUpperCase(), 75, y, { width: 65 });
          doc.fillColor('white').fontSize(8)
            .text((vuln.category || '').substring(0, 10), 148, y, { width: 78 });
          doc.fillColor('#1E293B').fontSize(8).font('Helvetica')
            .text((vuln.title || '').substring(0, 50), 235, y, { width: 235 });
          doc.fillColor('#64748B').text((vuln.cvss_score || 0).toFixed(1), 480, y, { width: 45 });
          y += 22;
        });

        // ── DETAILED FINDINGS ──
        doc.addPage();
        doc.fillColor('#0F172A').fontSize(20).font('Helvetica-Bold').text('Detailed Findings', 50, 50);
        doc.moveTo(50, 75).lineTo(545, 75).stroke('#E2E8F0');

        y = 90;
        sortedVulns.filter(v => ['critical', 'high'].includes(v.severity)).slice(0, 15).forEach((vuln, idx) => {
          if (y > 700) { doc.addPage(); y = 50; }
          const sevColor = this.colors[vuln.severity] || '#64748B';
          doc.fillColor(sevColor).rect(50, y, 495, 24).fill();
          doc.fillColor('white').fontSize(11).font('Helvetica-Bold')
            .text(`${idx + 1}. ${(vuln.title || '').substring(0, 70)}`, 58, y + 6);
          y += 30;

          const details = [
            ['Severity', (vuln.severity || '').toUpperCase()],
            ['CVSS Score', (vuln.cvss_score || 0).toFixed(1)],
            ['Category', vuln.category || ''],
            ['CWE', vuln.cwe_id || 'N/A'],
            ['OWASP', (vuln.owasp_category || '').substring(0, 40)]
          ];

          details.forEach(([label, value]) => {
            doc.fillColor('#64748B').fontSize(9).font('Helvetica-Bold').text(label + ':', 58, y, { width: 80 });
            doc.fillColor('#1E293B').fontSize(9).font('Helvetica').text(value, 145, y, { width: 400 });
            y += 14;
          });

          if (vuln.description) {
            doc.fillColor('#64748B').fontSize(9).font('Helvetica-Bold').text('Description:', 58, y);
            y += 12;
            doc.fillColor('#334155').fontSize(9).font('Helvetica')
              .text(vuln.description.substring(0, 300), 58, y, { width: 487, lineGap: 2 });
            y += Math.ceil(vuln.description.substring(0, 300).length / 85) * 14;
          }

          if (vuln.remediation_text) {
            doc.fillColor('#64748B').fontSize(9).font('Helvetica-Bold').text('Remediation:', 58, y);
            y += 12;
            doc.fillColor('#166534').fontSize(9).font('Helvetica')
              .text(vuln.remediation_text.substring(0, 250), 58, y, { width: 487, lineGap: 2 });
            y += Math.ceil(vuln.remediation_text.substring(0, 250).length / 85) * 14;
          }

          y += 15;
          doc.moveTo(50, y - 5).lineTo(545, y - 5).stroke('#E2E8F0');
        });

        // ── RECOMMENDATIONS ──
        doc.addPage();
        doc.fillColor('#0F172A').fontSize(20).font('Helvetica-Bold').text('Recommendations', 50, 50);
        doc.moveTo(50, 75).lineTo(545, 75).stroke('#E2E8F0');

        const recs = [
          { title: 'Immediate (0-24h)', items: ['Patch all critical vulnerabilities', 'Disable exposed admin interfaces', 'Rotate compromised secrets/tokens'] },
          { title: 'Short Term (1 week)', items: ['Fix high severity findings', 'Implement rate limiting', 'Enable security headers'] },
          { title: 'Medium Term (1 month)', items: ['Address medium severity issues', 'Implement WAF', 'Security training for developers'] },
          { title: 'Long Term', items: ['Regular automated scanning', 'Bug bounty program', 'Penetration testing annually'] }
        ];

        let recY = 90;
        recs.forEach(rec => {
          doc.fillColor('#1E3A5F').fontSize(13).font('Helvetica-Bold').text(rec.title, 50, recY);
          recY += 18;
          rec.items.forEach(item => {
            doc.fillColor('#10B981').text('▸', 55, recY, { width: 15 });
            doc.fillColor('#334155').fontSize(10).font('Helvetica').text(item, 75, recY, { width: 470 });
            recY += 16;
          });
          recY += 8;
        });

        // Footer on last page
        doc.fillColor('#94A3B8').fontSize(9)
          .text(`NEXUS Security Scanner v2.1 | Confidential | ${new Date().toISOString().split('T')[0]}`,
            50, doc.page.height - 40, { width: 495, align: 'center' });

        doc.end();
      });

      return Buffer.concat(chunks);

    } catch (err) {
      logger.logError(err, { context: 'PDF generation', scanId: scan.id });
      throw err;
    }
  }
}

module.exports = new PDFReportGenerator();
