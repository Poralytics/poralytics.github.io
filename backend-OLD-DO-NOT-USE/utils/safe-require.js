/**
 * Safe Module Loader
 * Provides graceful fallbacks for optional modules
 */

function safeRequire(moduleName, fallback = null) {
  try {
    return require(moduleName);
  } catch (error) {
    if (fallback) {
      console.warn(`⚠️  Module '${moduleName}' not available, using fallback`);
      return fallback;
    }
    console.warn(`⚠️  Module '${moduleName}' not available, some features may be limited`);
    return null;
  }
}

// Redis fallback (use in-memory cache)
function createRedisFallback() {
  const cache = new Map();
  
  return {
    get: async (key) => cache.get(key) || null,
    set: async (key, value, options) => {
      cache.set(key, value);
      if (options?.EX) {
        setTimeout(() => cache.delete(key), options.EX * 1000);
      }
      return 'OK';
    },
    del: async (key) => cache.delete(key),
    exists: async (key) => cache.has(key) ? 1 : 0,
    keys: async (pattern) => {
      const regex = new RegExp(pattern.replace('*', '.*'));
      return Array.from(cache.keys()).filter(k => regex.test(k));
    },
    flushall: async () => cache.clear(),
    on: () => {},
    connect: async () => {},
    disconnect: async () => {},
    isReady: true
  };
}

// BullMQ fallback (use simple queue)
function createQueueFallback(name) {
  const queue = [];
  const workers = [];
  
  return {
    add: async (jobName, data, options) => {
      const job = { id: Date.now(), name: jobName, data, options };
      queue.push(job);
      // Process immediately in fallback mode
      setImmediate(() => {
        workers.forEach(worker => {
          try {
            worker.processor(job);
          } catch (error) {
            console.error('Queue job error:', error);
          }
        });
      });
      return job;
    },
    Worker: class {
      constructor(queueName, processor) {
        workers.push({ queueName, processor });
      }
      on() {}
      close() {}
    }
  };
}

// Stripe fallback (mock for development)
function createStripeFallback() {
  return {
    customers: {
      create: async (data) => ({ id: 'cus_' + Date.now(), ...data }),
      retrieve: async (id) => ({ id, email: 'test@example.com' }),
      update: async (id, data) => ({ id, ...data })
    },
    subscriptions: {
      create: async (data) => ({ id: 'sub_' + Date.now(), ...data, status: 'active' }),
      retrieve: async (id) => ({ id, status: 'active' }),
      update: async (id, data) => ({ id, ...data }),
      cancel: async (id) => ({ id, status: 'canceled' })
    },
    invoices: {
      create: async (data) => ({ id: 'in_' + Date.now(), ...data }),
      retrieve: async (id) => ({ id, amount: 4900 })
    },
    webhooks: {
      constructEvent: (payload, sig, secret) => {
        return JSON.parse(payload);
      }
    },
    billingPortal: {
      sessions: {
        create: async (data) => ({ url: 'https://billing.stripe.com/session' })
      }
    },
    checkout: {
      sessions: {
        create: async (data) => ({ id: 'cs_' + Date.now(), url: 'https://checkout.stripe.com' })
      }
    }
  };
}

// WebSocket fallback (mock server)
function createWebSocketFallback() {
  return {
    Server: class {
      constructor(options) {
        this.clients = new Set();
      }
      on(event, handler) {
        if (event === 'connection') {
          // Simulate a connection for testing
          setTimeout(() => {
            const mockWs = {
              send: (data) => console.log('WS send:', data),
              on: () => {},
              close: () => {},
              readyState: 1
            };
            handler(mockWs, {});
          }, 100);
        }
      }
    }
  };
}

module.exports = {
  safeRequire,
  createRedisFallback,
  createQueueFallback,
  createStripeFallback,
  createWebSocketFallback
};
