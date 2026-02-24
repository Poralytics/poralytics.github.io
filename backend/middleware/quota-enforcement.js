/**
 * QUOTA ENFORCEMENT MIDDLEWARE
 * Bloque les actions quand les limites sont atteintes
 */

const licenseService = require('../services/license-service');
const { logger } = require('../utils/error-handler');

/**
 * Middleware pour vérifier les quotas avant une action
 */
function enforceQuota(actionType) {
  return async (req, res, next) => {
    try {
      const userId = req.user.userId;
      
      // Vérifier si l'action est permise
      const check = await licenseService.canPerformAction(userId, actionType);
      
      if (!check.allowed) {
        logger.logWarning('Quota exceeded', { 
          userId, 
          actionType, 
          reason: check.reason 
        });

        return res.status(403).json({
          error: 'Quota exceeded',
          message: check.reason,
          usage: {
            limit: check.limit,
            used: check.usage,
            remaining: check.remaining
          },
          upgrade_required: check.upgrade_required,
          upgrade_url: '/pricing'
        });
      }

      // Si on est en grace period, avertir
      if (check.in_grace_period) {
        res.set('X-Grace-Period', 'true');
        res.set('X-Grace-Ends-At', check.grace_ends_at.toString());
      }

      // Attacher les infos de quota à la requête
      req.quotaCheck = check;
      
      next();
    } catch (error) {
      logger.logError(error, { context: 'enforceQuota', actionType });
      next(error);
    }
  };
}

/**
 * Middleware pour vérifier l'accès à une feature
 */
function requireFeature(featureName) {
  return async (req, res, next) => {
    try {
      const userId = req.user.userId;
      
      const check = licenseService.canUseFeature(userId, featureName);
      
      if (!check.allowed) {
        logger.logWarning('Feature not available', { 
          userId, 
          feature: featureName 
        });

        return res.status(403).json({
          error: 'Feature not available',
          message: check.reason,
          feature: featureName,
          available_in: check.available_in,
          upgrade_required: true,
          upgrade_url: '/pricing'
        });
      }

      next();
    } catch (error) {
      logger.logError(error, { context: 'requireFeature', featureName });
      next(error);
    }
  };
}

/**
 * Middleware pour enregistrer les appels API
 */
function trackApiCall(req, res, next) {
  try {
    if (req.user && req.user.userId) {
      licenseService.recordApiCall(
        req.user.userId,
        req.path,
        req.method
      );
    }
  } catch (error) {
    // Non-bloquant
    logger.logWarning('Could not track API call', { error: error.message });
  }
  
  next();
}

/**
 * Middleware pour afficher les warnings de quota
 */
function quotaWarnings(req, res, next) {
  if (!req.user || !req.user.userId) {
    return next();
  }

  try {
    const usage = licenseService.getUsageStats(req.user.userId);
    
    // Ajouter headers pour le frontend
    if (usage.usage.scans.percentage >= 80) {
      res.set('X-Quota-Warning', 'scans');
      res.set('X-Quota-Percentage', usage.usage.scans.percentage.toString());
    }

    if (usage.usage.domains.percentage >= 80) {
      res.set('X-Quota-Warning', 'domains');
      res.set('X-Quota-Percentage', usage.usage.domains.percentage.toString());
    }

    if (usage.upgrade_recommended.recommended) {
      res.set('X-Upgrade-Recommended', 'true');
      res.set('X-Suggested-Plan', usage.upgrade_recommended.suggested_plan);
    }
  } catch (error) {
    logger.logWarning('Could not check quota warnings', { error: error.message });
  }

  next();
}

module.exports = {
  enforceQuota,
  requireFeature,
  trackApiCall,
  quotaWarnings
};
