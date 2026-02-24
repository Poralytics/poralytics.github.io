/**
 * STRIPE BILLING SERVICE — Production Ready
 * Gestion complète des abonnements, paiements, et facturation
 */

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const db = require('../config/database');
const { logger } = require('../utils/error-handler');

class StripeBillingService {
  constructor() {
    this.plans = {
      free: {
        id: 'free',
        name: 'Free',
        price: 0,
        interval: 'month',
        features: {
          domains: 1,
          scans_per_month: 5,
          users: 1,
          support: 'community',
          ai_features: false,
          compliance: false,
          api_access: false
        }
      },
      starter: {
        id: 'price_starter_monthly',
        name: 'Starter',
        price: 99,
        interval: 'month',
        features: {
          domains: 10,
          scans_per_month: 100,
          users: 3,
          support: 'email',
          ai_features: false,
          compliance: false,
          api_access: false
        }
      },
      professional: {
        id: 'price_pro_monthly',
        name: 'Professional',
        price: 299,
        interval: 'month',
        features: {
          domains: 50,
          scans_per_month: 500,
          users: 10,
          support: 'priority',
          ai_features: true,
          compliance: false,
          api_access: true,
          integrations: true
        }
      },
      business: {
        id: 'price_business_monthly',
        name: 'Business',
        price: 799,
        interval: 'month',
        features: {
          domains: 200,
          scans_per_month: 2000,
          users: 50,
          support: 'priority',
          ai_features: true,
          compliance: true,
          api_access: true,
          integrations: true,
          white_label: true
        }
      },
      enterprise: {
        id: 'price_enterprise_monthly',
        name: 'Enterprise',
        price: 5000,
        interval: 'month',
        features: {
          domains: -1, // unlimited
          scans_per_month: -1, // unlimited
          users: -1, // unlimited
          support: 'dedicated',
          ai_features: true,
          compliance: true,
          api_access: true,
          integrations: true,
          white_label: true,
          sso: true,
          sla: true,
          custom_contract: true
        }
      }
    };
  }

  /**
   * Créer un client Stripe
   */
  async createCustomer(userId, email, name) {
    try {
      const customer = await stripe.customers.create({
        email,
        name,
        metadata: { userId: userId.toString() }
      });

      // Sauvegarder l'ID Stripe
      db.prepare(`
        UPDATE users 
        SET stripe_customer_id = ?, updated_at = ?
        WHERE id = ?
      `).run(customer.id, Math.floor(Date.now() / 1000), userId);

      logger.logInfo('Stripe customer created', { userId, customerId: customer.id });
      return customer;
    } catch (error) {
      logger.logError(error, { context: 'createCustomer', userId });
      throw error;
    }
  }

  /**
   * Créer une souscription
   */
  async createSubscription(userId, planId, paymentMethodId = null) {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      
      if (!user) {
        throw new Error('User not found');
      }

      // Créer customer si nécessaire
      let customerId = user.stripe_customer_id;
      if (!customerId) {
        const customer = await this.createCustomer(userId, user.email, user.name);
        customerId = customer.id;
      }

      // Attacher le moyen de paiement si fourni
      if (paymentMethodId) {
        await stripe.paymentMethods.attach(paymentMethodId, {
          customer: customerId
        });

        // Définir comme méthode par défaut
        await stripe.customers.update(customerId, {
          invoice_settings: {
            default_payment_method: paymentMethodId
          }
        });
      }

      // Créer la souscription
      const subscription = await stripe.subscriptions.create({
        customer: customerId,
        items: [{ price: planId }],
        trial_period_days: user.trial_used ? 0 : 14, // 14 jours de trial si premier abonnement
        metadata: {
          userId: userId.toString(),
          plan: this.getPlanNameById(planId)
        }
      });

      // Sauvegarder dans la DB
      db.prepare(`
        UPDATE users 
        SET 
          plan = ?,
          stripe_subscription_id = ?,
          subscription_status = ?,
          trial_ends_at = ?,
          subscription_starts_at = ?,
          trial_used = 1,
          updated_at = ?
        WHERE id = ?
      `).run(
        this.getPlanNameById(planId),
        subscription.id,
        subscription.status,
        subscription.trial_end,
        subscription.current_period_start,
        Math.floor(Date.now() / 1000),
        userId
      );

      logger.logInfo('Subscription created', { userId, subscriptionId: subscription.id });
      return subscription;
    } catch (error) {
      logger.logError(error, { context: 'createSubscription', userId, planId });
      throw error;
    }
  }

  /**
   * Mettre à jour une souscription (upgrade/downgrade)
   */
  async updateSubscription(userId, newPlanId) {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      
      if (!user || !user.stripe_subscription_id) {
        throw new Error('No active subscription found');
      }

      const subscription = await stripe.subscriptions.retrieve(user.stripe_subscription_id);
      
      // Mettre à jour la souscription
      const updated = await stripe.subscriptions.update(user.stripe_subscription_id, {
        items: [{
          id: subscription.items.data[0].id,
          price: newPlanId
        }],
        proration_behavior: 'always_invoice', // Facturer immédiatement la différence
        metadata: {
          userId: userId.toString(),
          plan: this.getPlanNameById(newPlanId)
        }
      });

      // Mettre à jour la DB
      db.prepare(`
        UPDATE users 
        SET plan = ?, updated_at = ?
        WHERE id = ?
      `).run(
        this.getPlanNameById(newPlanId),
        Math.floor(Date.now() / 1000),
        userId
      );

      logger.logInfo('Subscription updated', { userId, newPlan: newPlanId });
      return updated;
    } catch (error) {
      logger.logError(error, { context: 'updateSubscription', userId, newPlanId });
      throw error;
    }
  }

  /**
   * Annuler une souscription
   */
  async cancelSubscription(userId, immediately = false) {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      
      if (!user || !user.stripe_subscription_id) {
        throw new Error('No active subscription found');
      }

      if (immediately) {
        // Annulation immédiate
        await stripe.subscriptions.cancel(user.stripe_subscription_id);
        
        db.prepare(`
          UPDATE users 
          SET 
            subscription_status = 'canceled',
            plan = 'free',
            updated_at = ?
          WHERE id = ?
        `).run(Math.floor(Date.now() / 1000), userId);
      } else {
        // Annulation à la fin de la période
        const subscription = await stripe.subscriptions.update(user.stripe_subscription_id, {
          cancel_at_period_end: true
        });

        db.prepare(`
          UPDATE users 
          SET 
            subscription_status = 'canceling',
            subscription_ends_at = ?,
            updated_at = ?
          WHERE id = ?
        `).run(
          subscription.current_period_end,
          Math.floor(Date.now() / 1000),
          userId
        );
      }

      logger.logInfo('Subscription canceled', { userId, immediately });
    } catch (error) {
      logger.logError(error, { context: 'cancelSubscription', userId });
      throw error;
    }
  }

  /**
   * Réactiver une souscription annulée
   */
  async reactivateSubscription(userId) {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      
      if (!user || !user.stripe_subscription_id) {
        throw new Error('No subscription found');
      }

      const subscription = await stripe.subscriptions.update(user.stripe_subscription_id, {
        cancel_at_period_end: false
      });

      db.prepare(`
        UPDATE users 
        SET 
          subscription_status = ?,
          subscription_ends_at = NULL,
          updated_at = ?
        WHERE id = ?
      `).run(
        subscription.status,
        Math.floor(Date.now() / 1000),
        userId
      );

      logger.logInfo('Subscription reactivated', { userId });
      return subscription;
    } catch (error) {
      logger.logError(error, { context: 'reactivateSubscription', userId });
      throw error;
    }
  }

  /**
   * Gérer les webhooks Stripe
   */
  async handleWebhook(event) {
    try {
      logger.logInfo('Webhook received', { type: event.type, id: event.id });

      switch (event.type) {
        case 'customer.subscription.created':
          await this.handleSubscriptionCreated(event.data.object);
          break;

        case 'customer.subscription.updated':
          await this.handleSubscriptionUpdated(event.data.object);
          break;

        case 'customer.subscription.deleted':
          await this.handleSubscriptionDeleted(event.data.object);
          break;

        case 'invoice.payment_succeeded':
          await this.handlePaymentSucceeded(event.data.object);
          break;

        case 'invoice.payment_failed':
          await this.handlePaymentFailed(event.data.object);
          break;

        default:
          logger.logInfo('Unhandled webhook type', { type: event.type });
      }
    } catch (error) {
      logger.logError(error, { context: 'handleWebhook', eventType: event.type });
      throw error;
    }
  }

  async handleSubscriptionCreated(subscription) {
    const userId = parseInt(subscription.metadata.userId);
    
    db.prepare(`
      UPDATE users 
      SET 
        subscription_status = ?,
        subscription_starts_at = ?,
        updated_at = ?
      WHERE id = ?
    `).run(
      subscription.status,
      subscription.current_period_start,
      Math.floor(Date.now() / 1000),
      userId
    );
  }

  async handleSubscriptionUpdated(subscription) {
    const userId = parseInt(subscription.metadata.userId);
    
    db.prepare(`
      UPDATE users 
      SET 
        subscription_status = ?,
        updated_at = ?
      WHERE id = ?
    `).run(
      subscription.status,
      Math.floor(Date.now() / 1000),
      userId
    );
  }

  async handleSubscriptionDeleted(subscription) {
    const userId = parseInt(subscription.metadata.userId);
    
    db.prepare(`
      UPDATE users 
      SET 
        plan = 'free',
        subscription_status = 'canceled',
        stripe_subscription_id = NULL,
        updated_at = ?
      WHERE id = ?
    `).run(
      Math.floor(Date.now() / 1000),
      userId
    );
  }

  async handlePaymentSucceeded(invoice) {
    const userId = parseInt(invoice.subscription_metadata?.userId);
    
    if (userId) {
      // Enregistrer le paiement
      db.prepare(`
        INSERT INTO payments (
          user_id,
          stripe_invoice_id,
          amount,
          currency,
          status,
          paid_at,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        userId,
        invoice.id,
        invoice.amount_paid,
        invoice.currency,
        'succeeded',
        invoice.status_transitions.paid_at,
        Math.floor(Date.now() / 1000)
      );

      logger.logInfo('Payment succeeded', { userId, amount: invoice.amount_paid });
    }
  }

  async handlePaymentFailed(invoice) {
    const userId = parseInt(invoice.subscription_metadata?.userId);
    
    if (userId) {
      // Enregistrer l'échec
      db.prepare(`
        INSERT INTO payments (
          user_id,
          stripe_invoice_id,
          amount,
          currency,
          status,
          created_at
        ) VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        userId,
        invoice.id,
        invoice.amount_due,
        invoice.currency,
        'failed',
        Math.floor(Date.now() / 1000)
      );

      // Suspendre l'accès si nécessaire (après X échecs)
      const failedPayments = db.prepare(`
        SELECT COUNT(*) as count 
        FROM payments 
        WHERE user_id = ? AND status = 'failed' 
        AND created_at > ?
      `).get(userId, Math.floor(Date.now() / 1000) - 30 * 24 * 60 * 60); // 30 jours

      if (failedPayments.count >= 3) {
        db.prepare(`
          UPDATE users 
          SET subscription_status = 'suspended', updated_at = ?
          WHERE id = ?
        `).run(Math.floor(Date.now() / 1000), userId);

        logger.logWarning('Account suspended due to failed payments', { userId });
      }
    }
  }

  /**
   * Vérifier si un user peut utiliser une feature
   */
  canUseFeature(user, feature) {
    const plan = this.plans[user.plan] || this.plans.free;
    return plan.features[feature] === true || plan.features[feature] === -1;
  }

  /**
   * Vérifier les quotas
   */
  checkQuota(user, quotaType) {
    const plan = this.plans[user.plan] || this.plans.free;
    const limit = plan.features[quotaType];
    
    if (limit === -1) return { allowed: true, remaining: -1 }; // unlimited
    
    // Compter l'utilisation actuelle
    const now = Math.floor(Date.now() / 1000);
    const monthStart = now - (30 * 24 * 60 * 60);
    
    let usage = 0;
    if (quotaType === 'domains') {
      usage = db.prepare('SELECT COUNT(*) as count FROM domains WHERE user_id = ?').get(user.id).count;
    } else if (quotaType === 'scans_per_month') {
      usage = db.prepare('SELECT COUNT(*) as count FROM scans WHERE user_id = ? AND started_at > ?').get(user.id, monthStart).count;
    }
    
    return {
      allowed: usage < limit,
      remaining: Math.max(0, limit - usage),
      limit,
      usage
    };
  }

  /**
   * Helper: Get plan name by Stripe price ID
   */
  getPlanNameById(priceId) {
    for (const [key, plan] of Object.entries(this.plans)) {
      if (plan.id === priceId) return key;
    }
    return 'free';
  }

  /**
   * Créer un portail client Stripe
   */
  async createCustomerPortalSession(userId, returnUrl) {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      
      if (!user || !user.stripe_customer_id) {
        throw new Error('No Stripe customer found');
      }

      const session = await stripe.billingPortal.sessions.create({
        customer: user.stripe_customer_id,
        return_url: returnUrl
      });

      return session;
    } catch (error) {
      logger.logError(error, { context: 'createCustomerPortalSession', userId });
      throw error;
    }
  }

  /**
   * Créer une session de paiement Checkout
   */
  async createCheckoutSession(userId, planId, successUrl, cancelUrl) {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
      
      if (!user) {
        throw new Error('User not found');
      }

      let customerId = user.stripe_customer_id;
      if (!customerId) {
        const customer = await this.createCustomer(userId, user.email, user.name);
        customerId = customer.id;
      }

      const session = await stripe.checkout.sessions.create({
        customer: customerId,
        payment_method_types: ['card'],
        line_items: [{
          price: planId,
          quantity: 1
        }],
        mode: 'subscription',
        success_url: successUrl,
        cancel_url: cancelUrl,
        subscription_data: {
          trial_period_days: user.trial_used ? 0 : 14,
          metadata: {
            userId: userId.toString(),
            plan: this.getPlanNameById(planId)
          }
        }
      });

      return session;
    } catch (error) {
      logger.logError(error, { context: 'createCheckoutSession', userId, planId });
      throw error;
    }
  }
}

module.exports = new StripeBillingService();
