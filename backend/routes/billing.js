/**
 * BILLING ROUTES — Gestion des abonnements et paiements
 */

const express = require('express');
const router = express.Router();
const { auth } = require('../middleware/auth');
const { asyncHandler, logger } = require('../utils/error-handler');
const stripeBilling = require('../services/stripe-billing-service');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

/**
 * GET /api/billing/plans
 * Liste des plans disponibles
 */
router.get('/plans', asyncHandler(async (req, res) => {
  res.json({ plans: stripeBilling.plans });
}));

/**
 * POST /api/billing/checkout
 * Créer une session Stripe Checkout
 */
router.post('/checkout', auth, asyncHandler(async (req, res) => {
  const { planId } = req.body;
  
  if (!planId) {
    return res.status(400).json({ error: 'Plan ID required' });
  }

  const successUrl = `${req.headers.origin || 'http://localhost:3000'}/dashboard?payment=success`;
  const cancelUrl = `${req.headers.origin || 'http://localhost:3000'}/pricing?payment=canceled`;

  const session = await stripeBilling.createCheckoutSession(
    req.user.userId,
    planId,
    successUrl,
    cancelUrl
  );

  res.json({ sessionId: session.id, url: session.url });
}));

/**
 * POST /api/billing/webhook
 * Webhook Stripe (non authentifié)
 */
router.post('/webhook', express.raw({ type: 'application/json' }), asyncHandler(async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    logger.logError(err, { context: 'Stripe webhook signature verification failed' });
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Gérer l'événement
  await stripeBilling.handleWebhook(event);

  res.json({ received: true });
}));

module.exports = router;
