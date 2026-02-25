/**
 * ERROR HANDLER & CIRCUIT BREAKER SYSTEM
 * Protection contre les cascades d'erreurs et gestion graceful degradation
 */

const EventEmitter = require('events');

/**
 * Circuit Breaker Pattern Implementation
 * Protège contre les services défaillants
 */
class CircuitBreaker extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.name = options.name || 'unnamed';
    this.failureThreshold = options.failureThreshold || 5; // Nombre d'échecs avant ouverture
    this.successThreshold = options.successThreshold || 2; // Succès nécessaires pour fermer
    this.timeout = options.timeout || 60000; // Temps avant retry (1 minute)
    this.resetTimeout = options.resetTimeout || 30000; // Temps en half-open
    
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failures = 0;
    this.successes = 0;
    this.nextAttempt = Date.now();
    this.stats = {
      totalCalls: 0,
      successCalls: 0,
      failureCalls: 0,
      openCount: 0,
      lastFailure: null,
      lastSuccess: null
    };
  }

  /**
   * Exécute une fonction avec protection circuit breaker
   */
  async execute(fn, fallback = null) {
    this.stats.totalCalls++;
    
    // Si circuit ouvert
    if (this.state === 'OPEN') {
      // Vérifier si on peut passer en half-open
      if (Date.now() < this.nextAttempt) {
        this.emit('reject', { reason: 'Circuit breaker is OPEN', name: this.name });
        
        if (fallback) {
          console.log(`[CircuitBreaker:${this.name}] Using fallback (circuit OPEN)`);
          return await fallback();
        }
        
        throw new Error(`Circuit breaker is OPEN for ${this.name}`);
      }
      
      // Passer en half-open pour tester
      this.state = 'HALF_OPEN';
      this.emit('half-open', { name: this.name });
      console.log(`[CircuitBreaker:${this.name}] Switching to HALF_OPEN`);
    }

    try {
      // Exécuter la fonction
      const result = await fn();
      
      // Succès
      this.onSuccess();
      return result;
      
    } catch (error) {
      // Échec
      this.onFailure(error);
      
      // Utiliser fallback si disponible
      if (fallback && this.state === 'OPEN') {
        console.log(`[CircuitBreaker:${this.name}] Using fallback after failure`);
        try {
          return await fallback();
        } catch (fallbackError) {
          console.error(`[CircuitBreaker:${this.name}] Fallback also failed:`, fallbackError.message);
          throw error; // Throw l'erreur originale
        }
      }
      
      throw error;
    }
  }

  /**
   * Appelé lors d'un succès
   */
  onSuccess() {
    this.failures = 0;
    this.stats.successCalls++;
    this.stats.lastSuccess = Date.now();
    
    if (this.state === 'HALF_OPEN') {
      this.successes++;
      
      if (this.successes >= this.successThreshold) {
        this.close();
      }
    }
  }

  /**
   * Appelé lors d'un échec
   */
  onFailure(error) {
    this.failures++;
    this.stats.failureCalls++;
    this.stats.lastFailure = Date.now();
    
    this.emit('failure', { error: error.message, name: this.name, failures: this.failures });
    
    if (this.failures >= this.failureThreshold) {
      this.open();
    }
  }

  /**
   * Ouvre le circuit (stop les appels)
   */
  open() {
    this.state = 'OPEN';
    this.nextAttempt = Date.now() + this.timeout;
    this.stats.openCount++;
    
    this.emit('open', { name: this.name, nextAttempt: new Date(this.nextAttempt) });
    console.warn(`[CircuitBreaker:${this.name}] Circuit OPENED (${this.failures} failures)`);
  }

  /**
   * Ferme le circuit (retour à la normale)
   */
  close() {
    const wasOpen = this.state === 'OPEN';
    this.state = 'CLOSED';
    this.failures = 0;
    this.successes = 0;
    
    this.emit('close', { name: this.name });
    console.log(`[CircuitBreaker:${this.name}] Circuit CLOSED`);
  }

  /**
   * Force le circuit à s'ouvrir
   */
  forceOpen() {
    this.open();
  }

  /**
   * Force le circuit à se fermer
   */
  forceClose() {
    this.close();
  }

  /**
   * Obtient les statistiques
   */
  getStats() {
    return {
      ...this.stats,
      state: this.state,
      failures: this.failures,
      successRate: this.stats.totalCalls > 0 
        ? (this.stats.successCalls / this.stats.totalCalls * 100).toFixed(2) + '%'
        : 'N/A'
    };
  }

  /**
   * Reset les statistiques
   */
  resetStats() {
    this.stats = {
      totalCalls: 0,
      successCalls: 0,
      failureCalls: 0,
      openCount: 0,
      lastFailure: null,
      lastSuccess: null
    };
  }
}

/**
 * Retry avec exponential backoff
 */
class RetryHandler {
  constructor(options = {}) {
    this.maxRetries = options.maxRetries || 3;
    this.initialDelay = options.initialDelay || 1000; // 1 seconde
    this.maxDelay = options.maxDelay || 30000; // 30 secondes
    this.factor = options.factor || 2; // Multiplicateur
    this.jitter = options.jitter !== false; // Ajouter du random
  }

  /**
   * Exécute avec retry
   */
  async execute(fn, context = {}) {
    let lastError;
    
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        // Attendre avant de retry (sauf premier essai)
        if (attempt > 0) {
          const delay = this.calculateDelay(attempt);
          console.log(`[Retry] Attempt ${attempt + 1}/${this.maxRetries + 1} after ${delay}ms delay`);
          await this.sleep(delay);
        }
        
        // Exécuter
        return await fn();
        
      } catch (error) {
        lastError = error;
        
        // Si c'est une erreur non-retriable, arrêter
        if (this.isNonRetriable(error)) {
          throw error;
        }
        
        // Dernier essai ?
        if (attempt === this.maxRetries) {
          console.error(`[Retry] All ${this.maxRetries + 1} attempts failed`);
          throw error;
        }
        
        console.warn(`[Retry] Attempt ${attempt + 1} failed:`, error.message);
      }
    }
    
    throw lastError;
  }

  /**
   * Calcule le délai avec exponential backoff
   */
  calculateDelay(attempt) {
    let delay = this.initialDelay * Math.pow(this.factor, attempt - 1);
    
    // Limiter au max
    delay = Math.min(delay, this.maxDelay);
    
    // Ajouter du jitter (randomness) pour éviter thundering herd
    if (this.jitter) {
      delay = delay * (0.5 + Math.random() * 0.5);
    }
    
    return Math.floor(delay);
  }

  /**
   * Vérifie si une erreur est non-retriable
   */
  isNonRetriable(error) {
    // Erreurs qui ne doivent jamais être retriées
    const nonRetriableErrors = [
      'Invalid URL',
      'Authentication required',
      'Forbidden',
      'Not found',
      'Circuit breaker is OPEN'
    ];
    
    return nonRetriableErrors.some(msg => 
      error.message && error.message.includes(msg)
    );
  }

  /**
   * Sleep helper
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Error Logger avec structured logging
 */
class ErrorLogger {
  constructor(options = {}) {
    this.serviceName = options.serviceName || 'nexus';
    this.environment = process.env.NODE_ENV || 'development';
    this.logToFile = options.logToFile !== false;
    this.logToConsole = options.logToConsole !== false;
  }

  /**
   * Log une erreur avec contexte
   */
  logError(error, context = {}) {
    const errorLog = {
      timestamp: new Date().toISOString(),
      service: this.serviceName,
      environment: this.environment,
      level: 'ERROR',
      message: error.message,
      stack: error.stack,
      code: error.code,
      ...context
    };

    // Log console
    if (this.logToConsole) {
      console.error('[ERROR]', JSON.stringify(errorLog, null, 2));
    }

    // TODO: Log to file ou service externe (Sentry, DataDog, etc.)
    
    return errorLog;
  }

  /**
   * Log un warning
   */
  logWarning(message, context = {}) {
    const warningLog = {
      timestamp: new Date().toISOString(),
      service: this.serviceName,
      environment: this.environment,
      level: 'WARNING',
      message,
      ...context
    };

    if (this.logToConsole) {
      console.warn('[WARNING]', JSON.stringify(warningLog, null, 2));
    }

    return warningLog;
  }

  /**
   * Log une info
   */
  logInfo(message, context = {}) {
    const infoLog = {
      timestamp: new Date().toISOString(),
      service: this.serviceName,
      environment: this.environment,
      level: 'INFO',
      message,
      ...context
    };

    if (this.logToConsole) {
      console.log('[INFO]', JSON.stringify(infoLog, null, 2));
    }

    return infoLog;
  }
}

/**
 * Global Error Handler pour Express
 */
class ExpressErrorHandler {
  constructor(options = {}) {
    this.logger = options.logger || new ErrorLogger();
    this.includeStackTrace = options.includeStackTrace !== false && 
                             process.env.NODE_ENV === 'development';
  }

  /**
   * Middleware de gestion d'erreurs
   */
  middleware() {
    return (err, req, res, next) => {
      // Log l'erreur
      this.logger.logError(err, {
        method: req.method,
        url: req.url,
        ip: req.ip,
        userId: req.user?.id,
        body: req.body
      });

      // Déterminer le status code
      const statusCode = err.statusCode || err.status || 500;

      // Préparer la réponse
      const response = {
        error: {
          message: err.message || 'Internal Server Error',
          code: err.code,
          timestamp: new Date().toISOString()
        }
      };

      // Ajouter stack trace en dev
      if (this.includeStackTrace) {
        response.error.stack = err.stack;
      }

      // Ajouter des détails selon le type d'erreur
      if (err.name === 'ValidationError') {
        response.error.details = err.details;
      }

      res.status(statusCode).json(response);
    };
  }

  /**
   * Wrap async route handlers pour catch errors
   */
  static asyncHandler(fn) {
    return (req, res, next) => {
      Promise.resolve(fn(req, res, next)).catch(next);
    };
  }

  /**
   * Not found handler
   */
  notFoundHandler() {
    return (req, res) => {
      res.status(404).json({
        error: {
          message: 'Not found',
          path: req.url,
          timestamp: new Date().toISOString()
        }
      });
    };
  }
}

/**
 * Manager global pour tous les circuit breakers
 */
class CircuitBreakerManager {
  constructor() {
    this.breakers = new Map();
  }

  /**
   * Obtient ou crée un circuit breaker
   */
  getBreaker(name, options = {}) {
    if (!this.breakers.has(name)) {
      const breaker = new CircuitBreaker({ name, ...options });
      this.breakers.set(name, breaker);
    }
    return this.breakers.get(name);
  }

  /**
   * Obtient les stats de tous les breakers
   */
  getAllStats() {
    const stats = {};
    this.breakers.forEach((breaker, name) => {
      stats[name] = breaker.getStats();
    });
    return stats;
  }

  /**
   * Reset tous les breakers
   */
  resetAll() {
    this.breakers.forEach(breaker => breaker.forceClose());
  }

  /**
   * Health check de tous les breakers
   */
  healthCheck() {
    const health = {
      healthy: true,
      breakers: {}
    };

    this.breakers.forEach((breaker, name) => {
      const stats = breaker.getStats();
      health.breakers[name] = {
        state: stats.state,
        healthy: stats.state !== 'OPEN'
      };

      if (stats.state === 'OPEN') {
        health.healthy = false;
      }
    });

    return health;
  }
}

// Instances globales
const globalLogger = new ErrorLogger({ serviceName: 'nexus' });
const globalBreakerManager = new CircuitBreakerManager();
const globalRetryHandler = new RetryHandler();

// Exports
module.exports = {
  // Classes
  CircuitBreaker,
  RetryHandler,
  ErrorLogger,
  ExpressErrorHandler,
  CircuitBreakerManager,
  
  // Instances globales
  logger: globalLogger,
  breakerManager: globalBreakerManager,
  retryHandler: globalRetryHandler,
  
  // Helpers
  asyncHandler: ExpressErrorHandler.asyncHandler
};
