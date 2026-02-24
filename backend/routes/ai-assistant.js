const express = require('express');
const { asyncHandler } = require('../utils/error-handler');
const router = express.Router();
const { auth } = require('../middleware/auth');
const AIAssistant = require('../services/ai-security-assistant');

/**
 * POST /api/ai/chat
 * Conversation avec l'assistant IA
 */
router.post('/chat', auth, async (req, res) => {
  try {
    const { message, conversationId, context } = req.body;

    if (!message) {
      return res.status(400).json({
        success: false,
        error: 'Message required'
      });
    }

    const response = await AIAssistant.chat(req.user.id, message, {
      conversationId,
      ...context
    });

    res.json({
      success: true,
      ...response
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/ai/explain-vulnerability/:vulnerabilityId
 * Expliquer une vulnérabilité en termes simples
 */
router.post('/explain-vulnerability/:vulnerabilityId', auth, async (req, res) => {
  try {
    const response = await AIAssistant.explainVulnerability(
      req.user.id,
      req.params.vulnerabilityId
    );

    res.json({
      success: true,
      ...response
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/ai/generate-fix/:vulnerabilityId
 * Générer du code pour fixer une vulnérabilité
 */
router.post('/generate-fix/:vulnerabilityId', auth, async (req, res) => {
  try {
    const { language } = req.body;

    const response = await AIAssistant.generateFixCode(
      req.user.id,
      req.params.vulnerabilityId,
      language || 'javascript'
    );

    res.json({
      success: true,
      ...response
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/ai/analyze-trends
 * Analyser les tendances de sécurité
 */
router.get('/analyze-trends', auth, async (req, res) => {
  try {
    const response = await AIAssistant.analyzeTrends(req.user.id);

    res.json({
      success: true,
      ...response
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/ai/recommendations
 * Obtenir des recommandations personnalisées
 */
router.get('/recommendations', auth, async (req, res) => {
  try {
    const response = await AIAssistant.getPersonalizedRecommendations(req.user.id);

    res.json({
      success: true,
      ...response
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * POST /api/ai/ask
 * Poser une question de sécurité
 */
router.post('/ask', auth, async (req, res) => {
  try {
    const { question } = req.body;

    if (!question) {
      return res.status(400).json({
        success: false,
        error: 'Question required'
      });
    }

    const response = await AIAssistant.answerSecurityQuestion(
      req.user.id,
      question
    );

    res.json({
      success: true,
      ...response
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/ai/conversations
 * Liste des conversations
 */
router.get('/conversations', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const conversations = db.prepare(`
      SELECT id, created_at, updated_at
      FROM ai_conversations 
      WHERE user_id = ? 
      ORDER BY updated_at DESC 
      LIMIT 50
    `).all(req.user.id);

    res.json({
      success: true,
      conversations
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/ai/conversations/:conversationId
 * Obtenir une conversation
 */
router.get('/conversations/:conversationId', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const conversation = db.prepare(
      'SELECT * FROM ai_conversations WHERE id = ? AND user_id = ?'
    ).get(req.params.conversationId, req.user.id);

    if (!conversation) {
      return res.status(404).json({
        success: false,
        error: 'Conversation not found'
      });
    }

    res.json({
      success: true,
      conversation: {
        ...conversation,
        messages: JSON.parse(conversation.messages)
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * DELETE /api/ai/conversations/:conversationId
 * Supprimer une conversation
 */
router.delete('/conversations/:conversationId', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    db.prepare('DELETE FROM ai_conversations WHERE id = ? AND user_id = ?')
      .run(req.params.conversationId, req.user.id);

    res.json({
      success: true,
      message: 'Conversation deleted'
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /api/ai/usage
 * Statistiques d'utilisation de l'IA
 */
router.get('/usage', auth, async (req, res) => {
  try {
    const db = require('../config/database');
    
    const usage = db.prepare(`
      SELECT 
        COUNT(*) as total_requests,
        SUM(total_tokens) as total_tokens,
        SUM(cost) as total_cost
      FROM ai_usage_log 
      WHERE user_id = ?
    `).get(req.user.id);

    res.json({
      success: true,
      usage
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
