/**
 * Intelligent Rate Limiter
 * Adaptive rate limiting based on user plan
 */
const rateLimit = require('express-rate-limit');

const createPlanLimiter = (options = {}) => {
  return (req, res, next) => {
    const user = req.user;
    const plan = user?.plan || 'free';
    const limits = { free: options.free || 20, pro: options.pro || 100, business: options.business || 500, enterprise: options.enterprise || 2000 };
    const limiter = rateLimit({
      windowMs: options.windowMs || 15 * 60 * 1000,
      max: limits[plan] || limits.free,
      message: { error: `Rate limit exceeded for ${plan} plan. Upgrade for higher limits.` },
      standardHeaders: true
    });
    limiter(req, res, next);
  };
};

module.exports = { createPlanLimiter };
