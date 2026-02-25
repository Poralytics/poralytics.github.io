/**
 * AI-POWERED ANALYSIS SERVICE
 * Utilise OpenAI GPT-4 pour l'analyse intelligente de sécurité
 */

const db = require('../config/database');
const { logger } = require('../utils/error-handler');

// Note: En production, utiliser OpenAI SDK
// const OpenAI = require('openai');
// const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

class AISecurityService {
  constructor() {
    this.model = 'gpt-4-turbo-preview';
    this.maxTokens = 2000;
  }

  /**
   * Expliquer une vulnérabilité en langage simple
   */
  async explainVulnerability(vulnerability) {
    const prompt = `
You are a security expert explaining vulnerabilities to non-technical executives.

Vulnerability Details:
- Type: ${vulnerability.type}
- Severity: ${vulnerability.severity}
- Title: ${vulnerability.title}
- Technical Description: ${vulnerability.description}
- Location: ${vulnerability.url}

Please provide:
1. A simple one-sentence explanation that a CEO would understand
2. The business impact (what could happen if exploited)
3. A real-world analogy to make it relatable
4. The recommended action in simple terms

Format as JSON:
{
  "simple_explanation": "...",
  "business_impact": "...",
  "analogy": "...",
  "recommended_action": "..."
}
`;

    try {
      // En production, utiliser l'API OpenAI réelle
      // const completion = await openai.chat.completions.create({
      //   model: this.model,
      //   messages: [{ role: 'user', content: prompt }],
      //   max_tokens: this.maxTokens,
      //   temperature: 0.7
      // });
      // const aiResponse = JSON.parse(completion.choices[0].message.content);

      // Pour la démo, simulation de la réponse AI
      const aiResponse = this.simulateAIExplanation(vulnerability);

      logger.logInfo('AI explanation generated', { vulnId: vulnerability.id });
      return aiResponse;
    } catch (error) {
      logger.logError(error, { context: 'explainVulnerability' });
      throw new Error('AI explanation failed');
    }
  }

  /**
   * Générer automatiquement un fix pour une vulnérabilité
   */
  async generateRemediationCode(vulnerability) {
    const prompt = `
You are a senior security engineer. Generate a code fix for this vulnerability.

Vulnerability:
- Type: ${vulnerability.type}
- Language: ${this.detectLanguage(vulnerability.url)}
- Vulnerable Code: ${vulnerability.evidence || 'N/A'}
- Description: ${vulnerability.description}

Provide:
1. The secure code replacement
2. Explanation of what was changed and why
3. Testing recommendations
4. Any additional security considerations

Format as JSON:
{
  "fixed_code": "...",
  "explanation": "...",
  "testing_steps": ["..."],
  "additional_notes": "..."
}
`;

    try {
      // En production: appel OpenAI réel
      // const completion = await openai.chat.completions.create({
      //   model: this.model,
      //   messages: [{ role: 'user', content: prompt }],
      //   max_tokens: this.maxTokens,
      //   temperature: 0.5
      // });

      // Simulation pour la démo
      const aiResponse = this.simulateRemediationCode(vulnerability);

      logger.logInfo('AI remediation generated', { vulnId: vulnerability.id });
      return aiResponse;
    } catch (error) {
      logger.logError(error, { context: 'generateRemediationCode' });
      throw new Error('AI remediation generation failed');
    }
  }

  /**
   * Générer un résumé exécutif avec AI
   */
  async generateExecutiveSummary(userId) {
    // Récupérer les données nécessaires
    const vulns = db.prepare(`
      SELECT v.*, s.domain_id
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      AND v.status != 'fixed'
      ORDER BY 
        CASE v.severity
          WHEN 'critical' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
          ELSE 5
        END
      LIMIT 10
    `).all(userId);

    const vulnSummary = this.summarizeVulnerabilities(vulns);

    const prompt = `
You are a CISO preparing a brief for the CEO and board of directors.

Security Status:
- Total vulnerabilities: ${vulns.length}
- Critical: ${vulnSummary.critical}
- High: ${vulnSummary.high}
- Medium: ${vulnSummary.medium}

Top Issues:
${vulns.slice(0, 3).map(v => `- ${v.type}: ${v.title}`).join('\n')}

Create a concise executive summary with:
1. A one-sentence headline about the security posture
2. Three key bullet points (max 15 words each)
3. The single most important action to take
4. A positive note or improvement to mention

Format as JSON:
{
  "headline": "...",
  "key_points": ["...", "...", "..."],
  "top_priority": "...",
  "positive_note": "..."
}
`;

    try {
      // En production: OpenAI call
      // Simulation:
      const aiResponse = this.simulateExecutiveSummary(vulnSummary);

      logger.logInfo('AI executive summary generated', { userId });
      return aiResponse;
    } catch (error) {
      logger.logError(error, { context: 'generateExecutiveSummary' });
      throw new Error('AI executive summary generation failed');
    }
  }

  /**
   * Prédire les vulnérabilités futures avec ML
   */
  async predictFutureVulnerabilities(userId) {
    // Analyser les patterns historiques
    const historicalVulns = db.prepare(`
      SELECT 
        v.type,
        v.severity,
        s.created_at,
        s.domain_id
      FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      ORDER BY s.created_at DESC
      LIMIT 100
    `).all(userId);

    // Analyser les patterns
    const patterns = this.analyzeVulnerabilityPatterns(historicalVulns);

    const prompt = `
You are a predictive security analyst using ML patterns to forecast vulnerabilities.

Historical Data:
- Most common vulnerability types: ${patterns.topTypes.join(', ')}
- Frequency trend: ${patterns.trend}
- Average time between similar issues: ${patterns.averageRecurrence} days

Based on these patterns, predict:
1. The most likely vulnerability types to appear in the next 30 days
2. Estimated probability (%) for each
3. Recommended preventive actions
4. Areas of the application most at risk

Format as JSON:
{
  "predictions": [
    {
      "vulnerability_type": "...",
      "probability": 85,
      "timeframe": "Next 30 days",
      "risk_area": "..."
    }
  ],
  "preventive_actions": ["...", "..."],
  "confidence_level": "High|Medium|Low"
}
`;

    try {
      // Simulation (en production: vrai ML model ou OpenAI)
      const aiResponse = this.simulatePredictions(patterns);

      logger.logInfo('AI predictions generated', { userId });
      return aiResponse;
    } catch (error) {
      logger.logError(error, { context: 'predictFutureVulnerabilities' });
      throw new Error('AI prediction failed');
    }
  }

  /**
   * Prioriser automatiquement les vulnérabilités par impact business
   */
  async prioritizeByBusinessImpact(vulnerabilities, businessContext) {
    const prompt = `
You are prioritizing security vulnerabilities based on business context.

Business Context:
- Industry: ${businessContext.industry || 'Technology'}
- Primary Revenue: ${businessContext.revenue_model || 'E-commerce'}
- User Data Sensitivity: ${businessContext.data_sensitivity || 'High'}
- Compliance Requirements: ${businessContext.compliance || 'GDPR, PCI-DSS'}

Vulnerabilities to prioritize:
${vulnerabilities.map((v, i) => `${i + 1}. ${v.type} (${v.severity}) in ${v.url}`).join('\n')}

Rank these by actual business impact, considering:
- Potential for data breach
- Revenue impact if exploited
- Compliance violations
- Reputation damage
- Customer trust impact

Provide ranked list with business justification.

Format as JSON:
{
  "prioritized_list": [
    {
      "rank": 1,
      "vulnerability_id": "...",
      "business_impact_score": 95,
      "justification": "...",
      "estimated_cost_if_exploited": "..."
    }
  ]
}
`;

    try {
      // Simulation
      const aiResponse = this.simulatePrioritization(vulnerabilities, businessContext);

      logger.logInfo('AI prioritization generated', { count: vulnerabilities.length });
      return aiResponse;
    } catch (error) {
      logger.logError(error, { context: 'prioritizeByBusinessImpact' });
      throw new Error('AI prioritization failed');
    }
  }

  // ========== SIMULATION METHODS (Remplacer par vrais appels OpenAI en production) ==========

  simulateAIExplanation(vulnerability) {
    const explanations = {
      sql_injection: {
        simple_explanation: "Attackers can manipulate your database through vulnerable input fields, potentially accessing or deleting all your data.",
        business_impact: "Complete database compromise could expose customer data, leading to $2-5M in breach costs, GDPR fines, and severe reputation damage.",
        analogy: "It's like leaving your bank vault door controlled by a keypad that accepts any combination - anyone can walk in and take everything.",
        recommended_action: "Implement input validation immediately. Estimated fix time: 8 hours. Cost of not fixing: $500K+ risk."
      },
      xss: {
        simple_explanation: "Malicious scripts can be injected into your website, potentially stealing user sessions and sensitive information.",
        business_impact: "Attackers could hijack user accounts, steal payment information, or deface your website, affecting customer trust and sales.",
        analogy: "It's like allowing anyone to post sticky notes on your storefront that contain hidden messages stealing customer wallet contents.",
        recommended_action: "Sanitize all user inputs and outputs. Estimated fix time: 4 hours. Prevents account takeovers worth $100K+ in fraud."
      },
      csrf: {
        simple_explanation: "Users can be tricked into performing actions they didn't intend, like transferring money or changing passwords.",
        business_impact: "Unauthorized transactions, account modifications, and potential financial losses for both company and users.",
        analogy: "Like a forged signature on a check - someone else can make transactions appear to come from legitimate users.",
        recommended_action: "Implement CSRF tokens on all forms. Estimated fix time: 6 hours. Prevents unauthorized transactions."
      }
    };

    return explanations[vulnerability.type] || {
      simple_explanation: `Security issue in ${vulnerability.type} that could be exploited by attackers.`,
      business_impact: "Potential for unauthorized access, data theft, or service disruption.",
      analogy: "Like leaving a window unlocked in your office - creates an unnecessary entry point for intruders.",
      recommended_action: "Review and fix this vulnerability. Consult security documentation for specific remediation steps."
    };
  }

  simulateRemediationCode(vulnerability) {
    const fixes = {
      sql_injection: {
        fixed_code: `// Before (VULNERABLE):
const query = "SELECT * FROM users WHERE id = " + userId;

// After (SECURE):
const query = "SELECT * FROM users WHERE id = ?";
const result = await db.execute(query, [userId]);

// Or using an ORM:
const user = await User.findById(userId);`,
        explanation: "Replaced string concatenation with parameterized queries. The database now treats user input as data, not executable code, preventing SQL injection.",
        testing_steps: [
          "Test with normal user IDs (1, 2, 3)",
          "Test with SQL injection payloads (1' OR '1'='1)",
          "Verify that injection attempts are treated as data",
          "Run automated SQL injection scanner"
        ],
        additional_notes: "Consider using an ORM like Sequelize or TypeORM for automatic query sanitization. Ensure all database queries throughout the application use parameterized queries."
      },
      xss: {
        fixed_code: `// Before (VULNERABLE):
element.innerHTML = userInput;

// After (SECURE):
element.textContent = userInput;
// Or if HTML is needed:
const sanitized = DOMPurify.sanitize(userInput);
element.innerHTML = sanitized;`,
        explanation: "Use textContent instead of innerHTML, or sanitize HTML with DOMPurify library. This prevents malicious scripts from executing.",
        testing_steps: [
          "Test with normal text input",
          "Test with HTML tags (<b>test</b>)",
          "Test with script tags (<script>alert(1)</script>)",
          "Verify scripts don't execute"
        ],
        additional_notes: "Install DOMPurify: npm install dompurify. Apply this fix to all user-generated content display points."
      }
    };

    return fixes[vulnerability.type] || {
      fixed_code: "// Consult security documentation for specific fix",
      explanation: "General security best practices should be applied",
      testing_steps: ["Review code", "Test thoroughly", "Run security scan"],
      additional_notes: "Consider consulting with a security expert for this vulnerability type."
    };
  }

  simulateExecutiveSummary(vulnSummary) {
    if (vulnSummary.critical > 0) {
      return {
        headline: "🔴 Immediate security attention required - critical vulnerabilities detected",
        key_points: [
          `${vulnSummary.critical} critical issues pose immediate risk to data and operations`,
          `Estimated financial exposure: $${(vulnSummary.critical * 500 + vulnSummary.high * 100)}K`,
          "Recommended action within 48 hours to prevent potential breach"
        ],
        top_priority: `Fix ${vulnSummary.critical} critical vulnerabilities immediately - estimated 24 hours of development time`,
        positive_note: vulnSummary.fixed > 0 
          ? `Security team has already resolved ${vulnSummary.fixed} issues this month` 
          : "Early detection allows proactive remediation before exploitation"
      };
    } else if (vulnSummary.high > 0) {
      return {
        headline: "⚠️ Security improvements needed - addressing high-priority issues",
        key_points: [
          `${vulnSummary.high} high-severity issues identified and prioritized`,
          "No critical vulnerabilities - good baseline security posture",
          "Recommended remediation within 2 weeks"
        ],
        top_priority: "Address high-severity vulnerabilities in authentication and data handling",
        positive_note: "Security score improving with consistent scanning and remediation"
      };
    } else {
      return {
        headline: "✅ Strong security posture - maintaining vigilance",
        key_points: [
          "No critical or high-severity vulnerabilities detected",
          `${vulnSummary.medium} medium-priority items for continuous improvement`,
          "Security practices align with industry best standards"
        ],
        top_priority: "Continue regular security scans and address remaining medium-priority items",
        positive_note: "Excellent security discipline - company is well-protected against common threats"
      };
    }
  }

  simulatePredictions(patterns) {
    return {
      predictions: [
        {
          vulnerability_type: patterns.topTypes[0] || "SQL Injection",
          probability: 75,
          timeframe: "Next 30 days",
          risk_area: "User authentication and data input forms"
        },
        {
          vulnerability_type: "XSS",
          probability: 60,
          timeframe: "Next 30 days",
          risk_area: "User-generated content displays"
        },
        {
          vulnerability_type: "Authentication Issues",
          probability: 45,
          timeframe: "Next 60 days",
          risk_area: "Login and session management"
        }
      ],
      preventive_actions: [
        "Implement automated input validation across all forms",
        "Enable Content Security Policy (CSP) headers",
        "Schedule security training for development team",
        "Set up automated security testing in CI/CD pipeline"
      ],
      confidence_level: "Medium"
    };
  }

  simulatePrioritization(vulnerabilities, businessContext) {
    return {
      prioritized_list: vulnerabilities.map((v, index) => ({
        rank: index + 1,
        vulnerability_id: v.id,
        vulnerability_type: v.type,
        business_impact_score: 100 - (index * 10),
        justification: this.getBusinessJustification(v, businessContext),
        estimated_cost_if_exploited: this.estimateBreachCost(v, businessContext)
      }))
    };
  }

  // ========== HELPER METHODS ==========

  detectLanguage(url) {
    if (url.includes('.php')) return 'PHP';
    if (url.includes('.jsp')) return 'Java';
    if (url.includes('.aspx')) return 'C#/.NET';
    return 'JavaScript/Node.js';
  }

  summarizeVulnerabilities(vulns) {
    return {
      critical: vulns.filter(v => v.severity === 'critical').length,
      high: vulns.filter(v => v.severity === 'high').length,
      medium: vulns.filter(v => v.severity === 'medium').length,
      low: vulns.filter(v => v.severity === 'low').length,
      fixed: 0 // Placeholder
    };
  }

  analyzeVulnerabilityPatterns(historicalVulns) {
    const typeCount = {};
    historicalVulns.forEach(v => {
      typeCount[v.type] = (typeCount[v.type] || 0) + 1;
    });

    const topTypes = Object.entries(typeCount)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map(([type]) => type);

    return {
      topTypes,
      trend: 'stable',
      averageRecurrence: 45
    };
  }

  getBusinessJustification(vuln, context) {
    const justifications = {
      sql_injection: `Direct access to ${context.data_sensitivity || 'sensitive'} customer data. GDPR violation risk with potential €20M fine.`,
      xss: "Session hijacking could compromise customer accounts and payment information, leading to fraud and chargebacks.",
      csrf: "Unauthorized transactions could result in financial losses and regulatory scrutiny.",
      authentication: "Account takeover risk affecting customer trust and potential compliance violations."
    };

    return justifications[vuln.type] || "Security risk requiring attention to maintain compliance and customer trust.";
  }

  estimateBreachCost(vuln, context) {
    const costs = {
      critical: "$500K - $2M",
      high: "$100K - $500K",
      medium: "$20K - $100K",
      low: "$5K - $20K"
    };

    return costs[vuln.severity] || "$10K - $50K";
  }
}

module.exports = new AISecurityService();
