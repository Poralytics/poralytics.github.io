/**
 * Scanner Marketplace - Ecosystem Platform
 * Permet aux développeurs de créer et monétiser leurs propres scanners
 * 
 * INNOVATION MAJEURE: Transforme NEXUS en plateforme
 * - Développeurs créent custom scanners
 * - Vendent sur marketplace (70/30 revenue split)
 * - API pour intégration facile
 * - Review & rating system
 * - Automatic updates
 * - Revenue tracking
 * 
 * IMPACT: Network effect - Plus de scanners = Plus de valeur = Plus d'utilisateurs
 */

const db = require('../config/database');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const vm = require('vm');
const crypto = require('crypto');

class ScannerMarketplace {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    this.revenueShare = {
      developer: 0.70, // 70% to developer
      platform: 0.30   // 30% to NEXUS
    };

    this.categories = [
      'Web Applications',
      'APIs',
      'Mobile Apps',
      'Cloud Infrastructure',
      'Blockchain',
      'IoT Devices',
      'Compliance',
      'Custom Industry'
    ];

    this.pricingTiers = {
      free: 0,
      basic: 9.99,
      pro: 29.99,
      enterprise: 99.99
    };
  }

  /**
   * Submit new scanner to marketplace
   */
  async submitScanner(developerId, scannerData) {
    try {
      // Validate scanner code
      const validation = await this.validateScannerCode(scannerData.code);
      
      if (!validation.isValid) {
        throw new Error(`Scanner validation failed: ${validation.errors.join(', ')}`);
      }

      const scannerId = this.generateScannerId();

      // Create scanner entry
      const scanner = {
        id: scannerId,
        developer_id: developerId,
        name: scannerData.name,
        description: scannerData.description,
        category: scannerData.category,
        version: scannerData.version || '1.0.0',
        
        // Code & execution
        code: scannerData.code,
        entrypoint: scannerData.entrypoint || 'scan',
        dependencies: JSON.stringify(scannerData.dependencies || []),
        
        // Pricing
        pricing_tier: scannerData.pricingTier || 'free',
        price: this.pricingTiers[scannerData.pricingTier] || 0,
        
        // Metadata
        tags: JSON.stringify(scannerData.tags || []),
        icon_url: scannerData.iconUrl || '/assets/default-scanner-icon.png',
        screenshots: JSON.stringify(scannerData.screenshots || []),
        
        // Stats
        downloads: 0,
        rating: 0,
        reviews_count: 0,
        
        // Status
        status: 'pending_review',
        created_at: Date.now() / 1000,
        updated_at: Date.now() / 1000
      };

      // Save to database
      db.prepare(`
        INSERT INTO marketplace_scanners (
          id, developer_id, name, description, category, version,
          code, entrypoint, dependencies, pricing_tier, price,
          tags, icon_url, screenshots, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        scanner.id, scanner.developer_id, scanner.name, scanner.description,
        scanner.category, scanner.version, scanner.code, scanner.entrypoint,
        scanner.dependencies, scanner.pricing_tier, scanner.price,
        scanner.tags, scanner.icon_url, scanner.screenshots,
        scanner.status, scanner.created_at
      );

      // Notify review team
      await this.notifyReviewTeam(scannerId);

      console.log(`✅ Scanner submitted for review: ${scanner.name}`);

      return {
        success: true,
        scannerId,
        status: 'pending_review',
        estimatedReviewTime: '2-3 business days'
      };

    } catch (error) {
      console.error('Scanner submission error:', error);
      throw error;
    }
  }

  /**
   * Validate scanner code (security & quality checks)
   */
  async validateScannerCode(code) {
    const errors = [];
    const warnings = [];

    // 1. Basic syntax check
    try {
      new vm.Script(code);
    } catch (error) {
      errors.push(`Syntax error: ${error.message}`);
      return { isValid: false, errors, warnings };
    }

    // 2. Security checks - Dangerous patterns
    const dangerousPatterns = [
      { pattern: /require\s*\(\s*['"]child_process['"]\s*\)/g, risk: 'Code execution' },
      { pattern: /require\s*\(\s*['"]fs['"]\s*\)/g, risk: 'File system access' },
      { pattern: /eval\s*\(/g, risk: 'Eval usage' },
      { pattern: /Function\s*\(/g, risk: 'Dynamic function creation' },
      { pattern: /process\.env/g, risk: 'Environment variable access' },
      { pattern: /require\s*\(\s*['"]net['"]\s*\)/g, risk: 'Raw socket access' }
    ];

    for (const { pattern, risk } of dangerousPatterns) {
      if (pattern.test(code)) {
        errors.push(`Security risk detected: ${risk}`);
      }
    }

    // 3. Required structure check
    if (!code.includes('async scan(') && !code.includes('async function scan')) {
      errors.push('Missing required scan() function');
    }

    if (!code.includes('return') || !code.includes('findings')) {
      warnings.push('Scanner should return findings array');
    }

    // 4. Code quality checks
    const codeLines = code.split('\n').length;
    if (codeLines > 1000) {
      warnings.push('Scanner code is quite long (>1000 lines). Consider optimization.');
    }

    // 5. Best practices
    if (!code.includes('try') || !code.includes('catch')) {
      warnings.push('No error handling detected. Add try-catch blocks.');
    }

    if (!code.includes('console.log')) {
      warnings.push('No logging detected. Consider adding debug logs.');
    }

    return {
      isValid: errors.length === 0,
      errors,
      warnings,
      score: this.calculateCodeQualityScore(code)
    };
  }

  /**
   * Review and approve scanner
   */
  async reviewScanner(scannerId, reviewerId, decision, feedback) {
    const scanner = db.prepare('SELECT * FROM marketplace_scanners WHERE id = ?')
      .get(scannerId);

    if (!scanner) {
      throw new Error('Scanner not found');
    }

    const newStatus = decision === 'approve' ? 'approved' : 'rejected';

    db.prepare(`
      UPDATE marketplace_scanners 
      SET status = ?, reviewed_by = ?, reviewed_at = ?, review_feedback = ?
      WHERE id = ?
    `).run(newStatus, reviewerId, Date.now() / 1000, feedback, scannerId);

    // Notify developer
    await this.notifyDeveloper(scanner.developer_id, {
      type: decision,
      scannerId,
      scannerName: scanner.name,
      feedback
    });

    if (decision === 'approve') {
      // Publish to marketplace
      await this.publishToMarketplace(scannerId);
    }

    return { success: true, status: newStatus };
  }

  /**
   * Install scanner for user
   */
  async installScanner(userId, scannerId) {
    const scanner = db.prepare('SELECT * FROM marketplace_scanners WHERE id = ? AND status = ?')
      .get(scannerId, 'approved');

    if (!scanner) {
      throw new Error('Scanner not found or not approved');
    }

    // Check if already installed
    const existing = db.prepare(
      'SELECT * FROM user_installed_scanners WHERE user_id = ? AND scanner_id = ?'
    ).get(userId, scannerId);

    if (existing) {
      throw new Error('Scanner already installed');
    }

    // Check pricing
    if (scanner.price > 0) {
      await this.processScannerPurchase(userId, scannerId, scanner.price);
    }

    // Install scanner
    db.prepare(`
      INSERT INTO user_installed_scanners (user_id, scanner_id, installed_at, auto_update)
      VALUES (?, ?, ?, 1)
    `).run(userId, scannerId, Date.now() / 1000);

    // Update download count
    db.prepare('UPDATE marketplace_scanners SET downloads = downloads + 1 WHERE id = ?')
      .run(scannerId);

    // Track revenue for developer
    await this.trackDeveloperRevenue(scanner.developer_id, scannerId, scanner.price);

    console.log(`✅ Scanner installed: ${scanner.name} for user ${userId}`);

    return {
      success: true,
      scanner: {
        id: scanner.id,
        name: scanner.name,
        version: scanner.version
      }
    };
  }

  /**
   * Execute custom scanner
   */
  async executeScanner(userId, scannerId, target) {
    const installation = db.prepare(`
      SELECT s.* FROM marketplace_scanners s
      JOIN user_installed_scanners u ON s.id = u.scanner_id
      WHERE u.user_id = ? AND s.id = ? AND s.status = 'approved'
    `).get(userId, scannerId);

    if (!installation) {
      throw new Error('Scanner not installed or not available');
    }

    // Create safe sandbox environment
    const sandbox = {
      console: {
        log: (...args) => console.log(`[Scanner ${scannerId}]`, ...args),
        error: (...args) => console.error(`[Scanner ${scannerId}]`, ...args)
      },
      require: (module) => {
        // Only allow safe modules
        const allowedModules = ['axios', 'cheerio', 'url', 'crypto'];
        if (allowedModules.includes(module)) {
          return require(module);
        }
        throw new Error(`Module ${module} not allowed`);
      },
      target: target,
      findings: []
    };

    try {
      // Execute scanner in VM
      const context = vm.createContext(sandbox);
      const script = new vm.Script(`
        (async function() {
          ${installation.code}
          return await ${installation.entrypoint}(target);
        })()
      `);

      const result = await script.runInContext(context, {
        timeout: 60000, // 60 second timeout
        displayErrors: true
      });

      // Track usage
      await this.trackScannerUsage(userId, scannerId);

      return {
        success: true,
        findings: result || [],
        scanner: {
          id: scannerId,
          name: installation.name,
          version: installation.version
        }
      };

    } catch (error) {
      console.error(`Scanner execution error: ${scannerId}`, error);
      throw new Error(`Scanner execution failed: ${error.message}`);
    }
  }

  /**
   * Rate and review scanner
   */
  async rateScanner(userId, scannerId, rating, review) {
    if (rating < 1 || rating > 5) {
      throw new Error('Rating must be between 1 and 5');
    }

    // Check if user has scanner installed
    const installation = db.prepare(
      'SELECT * FROM user_installed_scanners WHERE user_id = ? AND scanner_id = ?'
    ).get(userId, scannerId);

    if (!installation) {
      throw new Error('You must install the scanner before reviewing');
    }

    // Save review
    db.prepare(`
      INSERT INTO scanner_reviews (scanner_id, user_id, rating, review, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(scannerId, userId, rating, review, Date.now() / 1000);

    // Update scanner average rating
    const avgRating = db.prepare(`
      SELECT AVG(rating) as avg, COUNT(*) as count 
      FROM scanner_reviews 
      WHERE scanner_id = ?
    `).get(scannerId);

    db.prepare(`
      UPDATE marketplace_scanners 
      SET rating = ?, reviews_count = ? 
      WHERE id = ?
    `).run(avgRating.avg, avgRating.count, scannerId);

    return { success: true };
  }

  /**
   * Get marketplace listings
   */
  async getMarketplaceListings(filters = {}) {
    let query = `
      SELECT 
        s.*,
        u.username as developer_name,
        (SELECT COUNT(*) FROM scanner_reviews WHERE scanner_id = s.id) as review_count
      FROM marketplace_scanners s
      JOIN users u ON s.developer_id = u.id
      WHERE s.status = 'approved'
    `;

    const params = [];

    if (filters.category) {
      query += ' AND s.category = ?';
      params.push(filters.category);
    }

    if (filters.pricingTier) {
      query += ' AND s.pricing_tier = ?';
      params.push(filters.pricingTier);
    }

    if (filters.search) {
      query += ' AND (s.name LIKE ? OR s.description LIKE ?)';
      params.push(`%${filters.search}%`, `%${filters.search}%`);
    }

    // Sorting
    const sortBy = filters.sortBy || 'downloads';
    const sortOrder = filters.sortOrder || 'DESC';
    query += ` ORDER BY s.${sortBy} ${sortOrder}`;

    // Pagination
    const limit = filters.limit || 50;
    const offset = filters.offset || 0;
    query += ` LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    const scanners = db.prepare(query).all(...params);

    return scanners.map(s => ({
      id: s.id,
      name: s.name,
      description: s.description,
      category: s.category,
      version: s.version,
      developer: s.developer_name,
      rating: s.rating,
      reviewCount: s.review_count,
      downloads: s.downloads,
      price: s.price,
      pricingTier: s.pricing_tier,
      iconUrl: s.icon_url,
      tags: JSON.parse(s.tags || '[]')
    }));
  }

  /**
   * Developer dashboard
   */
  async getDeveloperDashboard(developerId) {
    // Get developer's scanners
    const scanners = db.prepare(
      'SELECT * FROM marketplace_scanners WHERE developer_id = ?'
    ).all(developerId);

    // Get revenue stats
    const revenue = db.prepare(`
      SELECT 
        SUM(amount) as total_revenue,
        COUNT(*) as total_sales
      FROM developer_revenue
      WHERE developer_id = ?
    `).get(developerId);

    // Get recent reviews
    const recentReviews = db.prepare(`
      SELECT r.*, s.name as scanner_name, u.username
      FROM scanner_reviews r
      JOIN marketplace_scanners s ON r.scanner_id = s.id
      JOIN users u ON r.user_id = u.id
      WHERE s.developer_id = ?
      ORDER BY r.created_at DESC
      LIMIT 10
    `).all(developerId);

    return {
      scanners: scanners.map(s => ({
        id: s.id,
        name: s.name,
        status: s.status,
        downloads: s.downloads,
        rating: s.rating,
        revenue: this.calculateScannerRevenue(s.id, developerId)
      })),
      stats: {
        totalScanners: scanners.length,
        approvedScanners: scanners.filter(s => s.status === 'approved').length,
        totalDownloads: scanners.reduce((sum, s) => sum + s.downloads, 0),
        totalRevenue: revenue.total_revenue || 0,
        totalSales: revenue.total_sales || 0
      },
      recentReviews: recentReviews
    };
  }

  /**
   * Process scanner purchase
   */
  async processScannerPurchase(userId, scannerId, price) {
    // Charge user via Stripe (simplified)
    const BillingSystem = require('./billing-system');
    
    // Create one-time charge
    await BillingSystem.chargeOverage(userId, 'scanner_purchase', 1);

    console.log(`💰 Scanner purchased: ${scannerId} for $${price}`);
  }

  /**
   * Track developer revenue
   */
  async trackDeveloperRevenue(developerId, scannerId, price) {
    const developerShare = price * this.revenueShare.developer;

    db.prepare(`
      INSERT INTO developer_revenue (
        developer_id, scanner_id, amount, created_at
      ) VALUES (?, ?, ?, ?)
    `).run(developerId, scannerId, developerShare, Date.now() / 1000);
  }

  /**
   * Track scanner usage
   */
  async trackScannerUsage(userId, scannerId) {
    db.prepare(`
      INSERT INTO scanner_usage_log (user_id, scanner_id, executed_at)
      VALUES (?, ?, ?)
    `).run(userId, scannerId, Date.now() / 1000);
  }

  /**
   * Helper methods
   */
  calculateCodeQualityScore(code) {
    let score = 100;

    // Deduct for code smells
    if (code.length > 10000) score -= 10;
    if (!code.includes('try')) score -= 10;
    if (!code.includes('async')) score -= 5;
    if (code.split('\n').length < 50) score -= 5;

    return Math.max(0, score);
  }

  generateScannerId() {
    return 'scan_' + crypto.randomBytes(8).toString('hex');
  }

  async notifyReviewTeam(scannerId) {
    console.log(`📧 Review team notified for scanner: ${scannerId}`);
  }

  async notifyDeveloper(developerId, notification) {
    console.log(`📧 Developer ${developerId} notified:`, notification.type);
  }

  async publishToMarketplace(scannerId) {
    console.log(`🚀 Scanner published to marketplace: ${scannerId}`);
  }

  calculateScannerRevenue(scannerId, developerId) {
    const result = db.prepare(`
      SELECT SUM(amount) as revenue
      FROM developer_revenue
      WHERE scanner_id = ? AND developer_id = ?
    `).get(scannerId, developerId);

    return result?.revenue || 0;
  }
}

module.exports = new ScannerMarketplace();
