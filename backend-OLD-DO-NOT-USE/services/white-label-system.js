/**
 * White-Label System for Resellers
 * Permet aux agences/MSPs de revendre NEXUS sous leur propre marque
 * 
 * Features:
 * - Custom branding (logo, colors, domain)
 * - Multi-tenant isolation
 * - Reseller billing & commissions
 * - Client management
 * - Branded reports
 * - Custom email templates
 * - Revenue sharing (30-40%)
 */

const db = require('../config/database');
const fs = require('fs');
const path = require('path');

class WhiteLabelSystem {
  constructor() {
    this.defaultBranding = {
      companyName: 'NEXUS Security',
      logo: '/assets/nexus-logo.png',
      primaryColor: '#667eea',
      secondaryColor: '#764ba2',
      domain: 'nexussecurity.com',
      supportEmail: 'support@nexussecurity.com',
      footerText: 'Powered by NEXUS'
    };
  }

  /**
   * Create white-label account for reseller
   */
  async createWhiteLabelAccount(resellerId, branding, config = {}) {
    try {
      const whiteLabelId = this.generateWhiteLabelId();

      // Validate branding
      const validatedBranding = this.validateBranding(branding);

      // Create white-label configuration
      const whiteLabelConfig = {
        id: whiteLabelId,
        reseller_id: resellerId,
        status: 'active',
        
        // Branding
        company_name: validatedBranding.companyName,
        logo_url: validatedBranding.logo,
        primary_color: validatedBranding.primaryColor,
        secondary_color: validatedBranding.secondaryColor,
        custom_domain: validatedBranding.domain,
        support_email: validatedBranding.supportEmail,
        
        // Features
        features: {
          customDomain: config.customDomain !== false,
          brandedReports: config.brandedReports !== false,
          customEmails: config.customEmails !== false,
          hidePoweredBy: config.hidePoweredBy || false,
          apiAccess: config.apiAccess || true,
          whitelistIPs: config.whitelistIPs || []
        },
        
        // Billing
        commission_rate: config.commissionRate || 0.30, // 30% default
        pricing_markup: config.pricingMarkup || 0, // Can add markup
        
        // Limits
        max_clients: config.maxClients || 100,
        max_scans_per_client: config.maxScansPerClient || 1000,
        
        created_at: Date.now() / 1000
      };

      // Save to database
      db.prepare(`
        INSERT INTO white_label_accounts (
          id, reseller_id, company_name, logo_url, primary_color, 
          secondary_color, custom_domain, support_email, 
          commission_rate, max_clients, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        whiteLabelId,
        resellerId,
        whiteLabelConfig.company_name,
        whiteLabelConfig.logo_url,
        whiteLabelConfig.primary_color,
        whiteLabelConfig.secondary_color,
        whiteLabelConfig.custom_domain,
        whiteLabelConfig.support_email,
        whiteLabelConfig.commission_rate,
        whiteLabelConfig.max_clients,
        whiteLabelConfig.created_at
      );

      // Generate custom CSS
      await this.generateCustomCSS(whiteLabelId, validatedBranding);

      // Setup custom domain (if provided)
      if (validatedBranding.domain) {
        await this.setupCustomDomain(whiteLabelId, validatedBranding.domain);
      }

      // Create onboarding materials
      await this.createOnboardingMaterials(whiteLabelId, validatedBranding);

      console.log(`✅ White-label account created: ${whiteLabelId}`);

      return {
        success: true,
        whiteLabelId,
        config: whiteLabelConfig,
        setupInstructions: this.getSetupInstructions(whiteLabelId)
      };

    } catch (error) {
      console.error('White-label creation error:', error);
      throw error;
    }
  }

  /**
   * Get branding for a white-label account
   */
  async getBranding(whiteLabelId) {
    const config = db.prepare('SELECT * FROM white_label_accounts WHERE id = ?')
      .get(whiteLabelId);

    if (!config) {
      return this.defaultBranding;
    }

    return {
      companyName: config.company_name,
      logo: config.logo_url,
      primaryColor: config.primary_color,
      secondaryColor: config.secondary_color,
      domain: config.custom_domain,
      supportEmail: config.support_email,
      customCSS: `/white-label/${whiteLabelId}/custom.css`,
      hidePoweredBy: config.hide_powered_by
    };
  }

  /**
   * Generate branded report for client
   */
  async generateBrandedReport(scanId, whiteLabelId) {
    const branding = await this.getBranding(whiteLabelId);
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?')
      .all(scanId);

    // Generate PDF with custom branding
    const PDFReportGenerator = require('./pdf-report-generator');
    
    const brandedReport = await PDFReportGenerator.generateExecutivePDF(
      scanId,
      scan.user_id,
      {
        // Custom branding
        companyName: branding.companyName,
        logo: branding.logo,
        primaryColor: branding.primaryColor,
        secondaryColor: branding.secondaryColor,
        footerText: branding.hidePoweredBy ? '' : 'Powered by NEXUS',
        
        // Custom styling
        customCSS: branding.customCSS
      }
    );

    return brandedReport;
  }

  /**
   * Manage reseller clients
   */
  async addClient(whiteLabelId, clientData) {
    const config = db.prepare('SELECT * FROM white_label_accounts WHERE id = ?')
      .get(whiteLabelId);

    // Check limits
    const clientCount = db.prepare(
      'SELECT COUNT(*) as count FROM white_label_clients WHERE white_label_id = ?'
    ).get(whiteLabelId);

    if (clientCount.count >= config.max_clients) {
      throw new Error('Maximum clients limit reached');
    }

    // Create client account
    const clientId = this.generateClientId();

    db.prepare(`
      INSERT INTO white_label_clients (
        id, white_label_id, company_name, contact_email, 
        contact_name, plan_tier, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      clientId,
      whiteLabelId,
      clientData.companyName,
      clientData.email,
      clientData.contactName,
      clientData.planTier || 'pro',
      Date.now() / 1000
    );

    // Send branded welcome email
    await this.sendBrandedWelcomeEmail(clientId, whiteLabelId);

    return {
      success: true,
      clientId,
      loginUrl: this.getClientLoginUrl(whiteLabelId, clientId)
    };
  }

  /**
   * Calculate reseller commissions
   */
  async calculateCommissions(whiteLabelId, period = 'month') {
    const config = db.prepare('SELECT * FROM white_label_accounts WHERE id = ?')
      .get(whiteLabelId);

    const startDate = this.getPeriodStart(period);

    // Get all client subscriptions
    const revenue = db.prepare(`
      SELECT 
        SUM(amount) as total_revenue,
        COUNT(*) as client_count
      FROM subscriptions s
      JOIN white_label_clients c ON s.user_id = c.id
      WHERE c.white_label_id = ? 
      AND s.created_at >= ?
    `).get(whiteLabelId, startDate);

    const commissionAmount = (revenue.total_revenue || 0) * config.commission_rate;

    return {
      period,
      revenue: revenue.total_revenue || 0,
      clientCount: revenue.client_count || 0,
      commissionRate: config.commission_rate,
      commissionAmount,
      status: 'pending',
      payoutDate: this.getNextPayoutDate()
    };
  }

  /**
   * Generate custom CSS for white-label
   */
  async generateCustomCSS(whiteLabelId, branding) {
    const css = `
      /* Custom White-Label Styles for ${branding.companyName} */
      
      :root {
        --primary-color: ${branding.primaryColor};
        --secondary-color: ${branding.secondaryColor};
      }

      .logo {
        content: url('${branding.logo}');
      }

      .header {
        background: linear-gradient(135deg, ${branding.primaryColor}, ${branding.secondaryColor});
      }

      .btn-primary {
        background: ${branding.primaryColor};
      }

      .btn-primary:hover {
        background: ${this.darkenColor(branding.primaryColor, 10)};
      }

      .card-header {
        border-left: 4px solid ${branding.primaryColor};
      }

      .scan-progress {
        background: ${branding.primaryColor};
      }

      ${branding.hidePoweredBy ? '.powered-by { display: none !important; }' : ''}
    `;

    const cssPath = path.join(__dirname, '..', 'public', 'white-label', whiteLabelId);
    
    if (!fs.existsSync(cssPath)) {
      fs.mkdirSync(cssPath, { recursive: true });
    }

    fs.writeFileSync(path.join(cssPath, 'custom.css'), css);

    return css;
  }

  /**
   * Setup custom domain (DNS instructions)
   */
  async setupCustomDomain(whiteLabelId, domain) {
    // Generate SSL certificate (would use Let's Encrypt in production)
    
    const dnsInstructions = {
      domain,
      records: [
        {
          type: 'CNAME',
          name: domain,
          value: `${whiteLabelId}.nexussecurity.com`,
          ttl: 3600
        },
        {
          type: 'TXT',
          name: `_nexus-verify.${domain}`,
          value: this.generateVerificationToken(whiteLabelId),
          ttl: 3600
        }
      ],
      ssl: {
        status: 'pending',
        provider: 'letsencrypt',
        autoRenew: true
      }
    };

    // Save DNS config
    db.prepare(`
      UPDATE white_label_accounts 
      SET custom_domain = ?, dns_config = ? 
      WHERE id = ?
    `).run(domain, JSON.stringify(dnsInstructions), whiteLabelId);

    return dnsInstructions;
  }

  /**
   * Create onboarding materials
   */
  async createOnboardingMaterials(whiteLabelId, branding) {
    const materials = {
      welcomeGuide: this.generateWelcomeGuide(branding),
      salesPitch: this.generateSalesPitch(branding),
      clientOnboarding: this.generateClientOnboarding(branding),
      brandingAssets: {
        logo: branding.logo,
        colors: {
          primary: branding.primaryColor,
          secondary: branding.secondaryColor
        },
        emailTemplates: await this.generateEmailTemplates(whiteLabelId, branding)
      }
    };

    return materials;
  }

  /**
   * Send branded email to client
   */
  async sendBrandedWelcomeEmail(clientId, whiteLabelId) {
    const branding = await this.getBranding(whiteLabelId);
    const client = db.prepare('SELECT * FROM white_label_clients WHERE id = ?')
      .get(clientId);

    const emailTemplate = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: Arial, sans-serif; }
          .header { 
            background: linear-gradient(135deg, ${branding.primaryColor}, ${branding.secondaryColor});
            color: white;
            padding: 40px;
            text-align: center;
          }
          .content { padding: 40px; }
          .button {
            background: ${branding.primaryColor};
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 5px;
            display: inline-block;
          }
        </style>
      </head>
      <body>
        <div class="header">
          <img src="${branding.logo}" alt="${branding.companyName}" style="max-width: 200px;">
          <h1>Welcome to ${branding.companyName}</h1>
        </div>
        <div class="content">
          <h2>Hi ${client.contact_name},</h2>
          <p>Welcome to ${branding.companyName}'s security platform!</p>
          <p>Your account is ready. Here's what you can do:</p>
          <ul>
            <li>🔍 Scan your websites for vulnerabilities</li>
            <li>📊 Get detailed security reports</li>
            <li>🛡️ Auto-fix 40% of issues</li>
            <li>📈 Track your security score</li>
          </ul>
          <p>
            <a href="${this.getClientLoginUrl(whiteLabelId, clientId)}" class="button">
              Get Started →
            </a>
          </p>
          <p>Questions? Contact us at ${branding.supportEmail}</p>
          ${!branding.hidePoweredBy ? '<p style="color: #999; font-size: 12px;">Powered by NEXUS</p>' : ''}
        </div>
      </body>
      </html>
    `;

    // Send email (would use SendGrid/Mailgun in production)
    console.log(`📧 Branded welcome email sent to ${client.contact_email}`);

    return emailTemplate;
  }

  /**
   * Reseller portal dashboard
   */
  async getResellerDashboard(whiteLabelId) {
    const config = db.prepare('SELECT * FROM white_label_accounts WHERE id = ?')
      .get(whiteLabelId);

    const clients = db.prepare('SELECT * FROM white_label_clients WHERE white_label_id = ?')
      .all(whiteLabelId);

    const revenue = await this.calculateCommissions(whiteLabelId, 'month');

    return {
      branding: await this.getBranding(whiteLabelId),
      stats: {
        totalClients: clients.length,
        maxClients: config.max_clients,
        activeClients: clients.filter(c => c.status === 'active').length,
        monthlyRevenue: revenue.revenue,
        commission: revenue.commissionAmount
      },
      clients: clients.map(c => ({
        id: c.id,
        companyName: c.company_name,
        planTier: c.plan_tier,
        status: c.status,
        signupDate: new Date(c.created_at * 1000).toLocaleDateString(),
        lastScan: c.last_scan_at ? new Date(c.last_scan_at * 1000).toLocaleDateString() : 'Never'
      })),
      revenueChart: await this.getRevenueChart(whiteLabelId),
      setupProgress: this.getSetupProgress(whiteLabelId)
    };
  }

  /**
   * Helper methods
   */
  validateBranding(branding) {
    return {
      companyName: branding.companyName || 'Security Platform',
      logo: branding.logo || this.defaultBranding.logo,
      primaryColor: this.isValidColor(branding.primaryColor) ? branding.primaryColor : '#667eea',
      secondaryColor: this.isValidColor(branding.secondaryColor) ? branding.secondaryColor : '#764ba2',
      domain: branding.domain || '',
      supportEmail: branding.supportEmail || 'support@example.com',
      hidePoweredBy: branding.hidePoweredBy || false
    };
  }

  isValidColor(color) {
    return /^#[0-9A-F]{6}$/i.test(color);
  }

  darkenColor(color, percent) {
    const num = parseInt(color.replace('#', ''), 16);
    const amt = Math.round(2.55 * percent);
    const R = (num >> 16) - amt;
    const G = (num >> 8 & 0x00FF) - amt;
    const B = (num & 0x0000FF) - amt;
    return '#' + (0x1000000 + (R < 255 ? R < 1 ? 0 : R : 255) * 0x10000 +
      (G < 255 ? G < 1 ? 0 : G : 255) * 0x100 +
      (B < 255 ? B < 1 ? 0 : B : 255))
      .toString(16).slice(1);
  }

  generateWhiteLabelId() {
    return 'wl_' + Math.random().toString(36).substr(2, 9);
  }

  generateClientId() {
    return 'cli_' + Math.random().toString(36).substr(2, 9);
  }

  generateVerificationToken(whiteLabelId) {
    return `nexus-verify-${whiteLabelId}-${Date.now()}`;
  }

  getClientLoginUrl(whiteLabelId, clientId) {
    return `https://${whiteLabelId}.nexussecurity.com/login?client=${clientId}`;
  }

  getPeriodStart(period) {
    const now = new Date();
    if (period === 'month') {
      return new Date(now.getFullYear(), now.getMonth(), 1).getTime() / 1000;
    }
    return now.getTime() / 1000 - (30 * 24 * 3600);
  }

  getNextPayoutDate() {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth() + 1, 15).toISOString();
  }

  getSetupInstructions(whiteLabelId) {
    return {
      step1: 'Configure your branding in the dashboard',
      step2: 'Add custom domain DNS records',
      step3: 'Customize email templates',
      step4: 'Add your first client',
      step5: 'Start selling!'
    };
  }

  generateWelcomeGuide(branding) {
    return `Welcome to ${branding.companyName} Partner Program...`;
  }

  generateSalesPitch(branding) {
    return `${branding.companyName} - Enterprise Security Made Simple...`;
  }

  generateClientOnboarding(branding) {
    return `Onboarding guide for ${branding.companyName} clients...`;
  }

  async generateEmailTemplates(whiteLabelId, branding) {
    return {
      welcome: 'Welcome email template',
      scanComplete: 'Scan complete template',
      criticalAlert: 'Critical alert template'
    };
  }

  async getRevenueChart(whiteLabelId) {
    // Simplified
    return [];
  }

  getSetupProgress(whiteLabelId) {
    return {
      branding: true,
      domain: false,
      clients: false,
      billing: false
    };
  }
}

module.exports = new WhiteLabelSystem();
