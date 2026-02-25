/**
 * AUTH MIDDLEWARE - Production-ready
 * No hardcoded secrets. Validates JWT properly.
 */

const jwt = require('jsonwebtoken');
const { logger } = require('../utils/error-handler');

// Fail hard if JWT_SECRET not set in production
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('FATAL: JWT_SECRET environment variable is required in production');
  process.exit(1);
}
// Development fallback (clearly marked)
const _secret = JWT_SECRET || (() => {
  console.warn('WARNING: JWT_SECRET not set. Using insecure default. Set JWT_SECRET in .env');
  return 'CHANGE_ME_SET_JWT_SECRET_IN_ENV_FILE';
})();

const auth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const decoded = jwt.verify(token, _secret, {
      algorithms: ['HS256'],
      clockTolerance: 30 // 30 seconds tolerance for clock skew
    });

    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    logger.logError(error, { context: 'auth middleware' });
    return res.status(401).json({ error: 'Authentication failed' });
  }
};

const optionalAuth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      req.user = null;
      return next();
    }
    const token = authHeader.replace('Bearer ', '').trim();
    req.user = jwt.verify(token, _secret, { algorithms: ['HS256'] });
  } catch (_) {
    req.user = null;
  }
  next();
};

const signToken = (payload, expiresIn = '7d') => {
  return jwt.sign(payload, _secret, { algorithm: 'HS256', expiresIn });
};

// Export JWT_SECRET for backward compat (routes that use it)
const JWT_SECRET_EXPORT = _secret;

module.exports = { auth, optionalAuth, signToken, JWT_SECRET: JWT_SECRET_EXPORT };
