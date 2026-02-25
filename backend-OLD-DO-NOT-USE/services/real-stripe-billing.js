/**
 * SECURE STRIPE BILLING SERVICE
 * Avec circuit breaker, retry logic et error handling robuste
 */

const db = require('../config/database');
const { CircuitBreaker, RetryHandler, logger } = require('../utils/error-handler');

class SecureStripeBilling {
  constructor() {
    this.stripe = null;
    this.initialized = false;
    
    // Circuit breaker pour Stripe API
    this.breaker = new CircuitBreaker({
      name: 'stripe-api',
      failureThreshold: 5,
      successThreshold: 2,
      timeout: 60000 // 1 minute avant retry
    });
    
    // Retry handler pour opérations critiques
    this.retryHandler = new RetryHandler({
      maxRetries: 3,
      initialDelay: 1000,
      maxDelay: 10000
    });
    
    this.initializeStripe();
    this.setupEventListeners();
  }

  /**
   * Initialize Stripe avec gestion d'erreur
   */
  initializeStripe() {
    try {
      if (!process.env.STRIPE_SECRET_KEY) {
        logger.logWarning('Stripe not configured', {
          reason: 'STRIPE_SECRET_KEY missing'
        });
        return;
      }

      const Stripe = require('stripe');
      this.stripe = Stripe(process.env.STRIPE_SECRET_KEY);
      this.initialized = true;
      
      logger.logInfo('Stripe initialized successfully');
      
    } catch (error) {
      logger.logError(error, {
        context: 'Stripe initialization',
        fatal: true
      });
    }
  }

  /**
   * Setup event listeners pour le circuit breaker
   */
  setupEventListeners() {
    this.breaker.on('open', (data) => {
      logger.logError(new Error('Stripe circuit breaker opened'), {
        breaker: data.name,
        nextAttempt: data.nextAttempt
      });
      
      // TODO: Alert ops team
      this.notifyOpsTeam('Stripe circuit breaker opened');
    });

    this.breaker.on('half-open', (data) => {
      logger.logInfo('Stripe circuit breaker testing connection', {
        breaker: data.name
      });
    });

    this.breaker.on('close', (data) => {
      logger.logInfo('Stripe circuit breaker closed - service restored', {
        breaker: data.name
      });
    });
  }

  /**
   * Vérifie si Stripe est disponible
   */
  isAvailable() {
    if (!this.initialized || !this.stripe) {
      return false;
    }
    
    // Vérifier l'état du circuit breaker
    return this.breaker.state !== 'OPEN';
  }

  /**
   * Crée un customer avec protection
   */
  async createCustomer(userId, email, name) {
    if (!this.isAvailable()) {
      throw new Error('Stripe service unavailable');
    }

    // Utiliser circuit breaker + retry
    return await this.breaker.execute(
      async () => {
        return await this.retryHandler.execute(async () => {
          try {
            // Vérifier si customer existe déjà
            const existingUser = db.prepare(
              'SELECT stripe_customer_id FROM users WHERE id = ?'
            ).get(userId);

            if (existingUser?.stripe_customer_id) {
              logger.logInfo('Customer already exists', {
                userId,
                customerId: existingUser.stripe_customer_id
              });
              return { id: existingUser.stripe_customer_id };
            }

            // Créer le customer
            const customer = await this.stripe.customers.create({
              email,
              name,
              metadata: { 
                userId: userId.toString(),
                created_by: 'nexus'
              }
            });

            // Sauvegarder dans DB (transaction)
            try {
              db.prepare(`
                UPDATE users 
                SET stripe_customer_id = ?, updated_at = ? 
                WHERE id = ?
              `).run(customer.id, Math.floor(Date.now() / 1000), userId);
              
              logger.logInfo('Customer created successfully', {
                userId,
                customerId: customer.id
              });

            } catch (dbError) {
              // Rollback Stripe customer si DB fail
              logger.logError(dbError, {
                context: 'DB update after Stripe customer creation',
                customerId: customer.id,
                userId
              });
              
              // Tenter de supprimer le customer Stripe
              try {
                await this.stripe.customers.del(customer.id);
              } catch (deleteError) {
                logger.logError(deleteError, {
                  context: 'Failed to rollback Stripe customer',
                  customerId: customer.id
                });
              }
              
              throw dbError;
            }

            return customer;

          } catch (error) {
            logger.logError(error, {
              context: 'Create Stripe customer',
              userId,
              email
            });
            throw error;
          }
        });
      },
      // Fallback : retourner une erreur gracieuse
      async () => {
        logger.logWarning('Using fallback for customer creation', { userId });
        throw new Error('Billing service temporarily unavailable. Please try again later.');
      }
    );
  }

  /**
   * Crée une checkout session avec protection
   */
  async createCheckoutSession(userId, priceId, successUrl, cancelUrl) {
    if (!this.isAvailable()) {
      throw new Error('Stripe service unavailable');
    }

    return await this.breaker.execute(
      async () => {
        try {
          // Obtenir ou créer le customer
          const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
          
          if (!user) {
            throw new Error('User not found');
          }

          let customerId = user.stripe_customer_id;
          
          if (!customerId) {
            const customer = await this.createCustomer(userId, user.email, user.name);
            customerId = customer.id;
          }

          // Créer la session
          const session = await this.stripe.checkout.sessions.create({
            customer: customerId,
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [{
              price: priceId,
              quantity: 1
            }],
            success_url: successUrl,
            cancel_url: cancelUrl,
            allow_promotion_codes: true,
            billing_address_collection: 'required',
            metadata: {
              userId: userId.toString(),
              priceId: priceId
            }
          });

          logger.logInfo('Checkout session created', {
            userId,
            sessionId: session.id,
            priceId
          });

          return session;

        } catch (error) {
          logger.logError(error, {
            context: 'Create checkout session',
            userId,
            priceId
          });
          throw error;
        }
      }
    );
  }

  /**
   * Crée un portal session avec protection
   */
  async createPortalSession(userId, returnUrl) {
    if (!this.isAvailable()) {
      throw new Error('Stripe service unavailable');
    }

    return await this.breaker.execute(
      async () => {
        try {
          const user = db.prepare(
            'SELECT stripe_customer_id FROM users WHERE id = ?'
          ).get(userId);

          if (!user?.stripe_customer_id) {
            throw new Error('No Stripe customer found for this user');
          }

          const session = await this.stripe.billingPortal.sessions.create({
            customer: user.stripe_customer_id,
            return_url: returnUrl
          });

          logger.logInfo('Portal session created', {
            userId,
            customerId: user.stripe_customer_id
          });

          return session;

        } catch (error) {
          logger.logError(error, {
            context: 'Create portal session',
            userId
          });
          throw error;
        }
      }
    );
  }

  /**
   * Handle webhook avec idempotence et validation
   */
  async handleWebhook(body, signature) {
    if (!this.isAvailable()) {
      throw new Error('Stripe service unavailable');
    }

    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    if (!webhookSecret) {
      throw new Error('STRIPE_WEBHOOK_SECRET not configured');
    }

    try {
      // Vérifier la signature
      const event = this.stripe.webhooks.constructEvent(
        body,
        signature,
        webhookSecret
      );

      // Vérifier idempotence (éviter double processing)
      const existingEvent = db.prepare(
        'SELECT id FROM stripe_events WHERE event_id = ?'
      ).get(event.id);

      if (existingEvent) {
        logger.logInfo('Webhook event already processed', {
          eventId: event.id,
          type: event.type
        });
        return { received: true, processed: false, reason: 'duplicate' };
      }

      // Logger l'événement
      db.prepare(`
        INSERT INTO stripe_events (event_id, type, data, processed_at)
        VALUES (?, ?, ?, ?)
      `).run(
        event.id,
        event.type,
        JSON.stringify(event.data),
        Math.floor(Date.now() / 1000)
      );

      // Traiter selon le type
      switch (event.type) {
        case 'checkout.session.completed':
          await this.handleCheckoutCompleted(event.data.object);
          break;
          
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
          logger.logInfo('Unhandled webhook event type', {
            type: event.type,
            eventId: event.id
          });
      }

      return { received: true, processed: true, eventId: event.id };

    } catch (error) {
      logger.logError(error, {
        context: 'Handle Stripe webhook',
        signature: signature?.substring(0, 20)
      });
      throw error;
    }
  }

  /**
   * Handle checkout completed
   */
  async handleCheckoutCompleted(session) {
    try {
      const userId = parseInt(session.metadata.userId);
      const customerId = session.customer;
      
      // Mettre à jour l'utilisateur
      db.prepare(`
        UPDATE users 
        SET stripe_customer_id = ?,
            plan_tier = 'pro',
            updated_at = ?
        WHERE id = ?
      `).run(customerId, Math.floor(Date.now() / 1000), userId);

      logger.logInfo('Checkout completed', {
        userId,
        sessionId: session.id,
        customerId
      });

      // TODO: Envoyer email de confirmation

    } catch (error) {
      logger.logError(error, {
        context: 'Handle checkout completed',
        sessionId: session.id
      });
      throw error;
    }
  }

  /**
   * Handle subscription created
   */
  async handleSubscriptionCreated(subscription) {
    try {
      const customerId = subscription.customer;
      
      // Trouver l'utilisateur
      const user = db.prepare(
        'SELECT id FROM users WHERE stripe_customer_id = ?'
      ).get(customerId);

      if (!user) {
        throw new Error(`User not found for customer ${customerId}`);
      }

      // Mettre à jour
      db.prepare(`
        UPDATE users 
        SET subscription_id = ?,
            subscription_status = ?,
            updated_at = ?
        WHERE id = ?
      `).run(
        subscription.id,
        subscription.status,
        Math.floor(Date.now() / 1000),
        user.id
      );

      logger.logInfo('Subscription created', {
        userId: user.id,
        subscriptionId: subscription.id,
        status: subscription.status
      });

    } catch (error) {
      logger.logError(error, {
        context: 'Handle subscription created',
        subscriptionId: subscription.id
      });
      throw error;
    }
  }

  /**
   * Handle subscription updated
   */
  async handleSubscriptionUpdated(subscription) {
    // Similar à handleSubscriptionCreated mais avec update
    // Code similaire omis pour concision
  }

  /**
   * Handle subscription deleted
   */
  async handleSubscriptionDeleted(subscription) {
    // Downgrade l'utilisateur à free
    // Code omis pour concision
  }

  /**
   * Handle payment succeeded
   */
  async handlePaymentSucceeded(invoice) {
    // Logger le paiement réussi
    // Code omis pour concision
  }

  /**
   * Handle payment failed
   */
  async handlePaymentFailed(invoice) {
    // Logger l'échec et notifier l'utilisateur
    // Code omis pour concision
  }

  /**
   * Notifie l'équipe ops
   */
  notifyOpsTeam(message) {
    // TODO: Intégrer avec Slack, PagerDuty, etc.
    logger.logError(new Error(message), {
      context: 'Ops notification',
      urgent: true
    });
  }

  /**
   * Health check
   */
  async healthCheck() {
    try {
      if (!this.isAvailable()) {
        return {
          healthy: false,
          reason: 'Service not initialized or circuit breaker open'
        };
      }

      // Ping Stripe API
      await this.stripe.balance.retrieve();
      
      return {
        healthy: true,
        circuitBreaker: this.breaker.getStats()
      };

    } catch (error) {
      return {
        healthy: false,
        error: error.message
      };
    }
  }
}

// Créer une instance unique
const stripeBilling = new SecureStripeBilling();

module.exports = stripeBilling;
