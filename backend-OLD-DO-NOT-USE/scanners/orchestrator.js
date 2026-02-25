/**
 * SCANNER ORCHESTRATOR
 * Orchestre l'exécution de tous les scanners
 */

const SQLInjectionScanner = require('./sql-injection');
const XSSScanner = require('./xss');
const SecurityHeadersScanner = require('./security-headers');
const SSLScanner = require('./ssl-tls');

class ScannerOrchestrator {
  constructor() {
    this.scanners = [
      new SQLInjectionScanner(),
      new XSSScanner(),
      new SecurityHeadersScanner(),
      new SSLScanner()
    ];
  }

  /**
   * Lance tous les scanners sur une URL
   * @param {string} url - URL à scanner
   * @param {function} progressCallback - Callback pour rapporter la progression
   * @returns {Promise<Object>} Résultats du scan
   */
  async scanUrl(url, progressCallback = null) {
    const startTime = Date.now();
    const allVulnerabilities = [];
    const scannerResults = [];

    console.log(`🔍 Starting scan for: ${url}`);

    let completedScanners = 0;
    const totalScanners = this.scanners.length;

    for (const scanner of this.scanners) {
      try {
        console.log(`  Running ${scanner.name}...`);
        
        const result = await scanner.scan(url);
        
        scannerResults.push({
          scanner: scanner.name,
          status: result.status,
          duration_ms: result.duration_ms,
          vulnerabilities_found: result.vulnerabilities.length
        });

        allVulnerabilities.push(...result.vulnerabilities);

        completedScanners++;
        const progress = Math.floor((completedScanners / totalScanners) * 100);

        if (progressCallback) {
          progressCallback({
            progress,
            current_scanner: scanner.name,
            vulnerabilities_found: allVulnerabilities.length
          });
        }

        console.log(`  ✓ ${scanner.name} completed - Found ${result.vulnerabilities.length} issues`);

      } catch (error) {
        console.error(`  ✗ ${scanner.name} failed:`, error.message);
        scannerResults.push({
          scanner: scanner.name,
          status: 'error',
          error: error.message
        });
      }
    }

    const totalDuration = Date.now() - startTime;

    // Calculer statistiques
    const stats = {
      total: allVulnerabilities.length,
      critical: allVulnerabilities.filter(v => v.severity === 'critical').length,
      high: allVulnerabilities.filter(v => v.severity === 'high').length,
      medium: allVulnerabilities.filter(v => v.severity === 'medium').length,
      low: allVulnerabilities.filter(v => v.severity === 'low').length
    };

    console.log(`✅ Scan completed in ${totalDuration}ms`);
    console.log(`   Found ${stats.total} vulnerabilities (${stats.critical} critical, ${stats.high} high, ${stats.medium} medium, ${stats.low} low)`);

    return {
      url,
      scan_start: new Date(startTime).toISOString(),
      scan_end: new Date().toISOString(),
      duration_ms: totalDuration,
      scanners_executed: scannerResults,
      vulnerabilities: allVulnerabilities,
      statistics: stats,
      status: 'completed'
    };
  }

  /**
   * Obtient la liste des scanners disponibles
   */
  getAvailableScanners() {
    return this.scanners.map(scanner => ({
      name: scanner.name,
      severity: scanner.severity
    }));
  }
}

module.exports = ScannerOrchestrator;
