/**
 * Input Validation Middleware
 */
const validateScanStart = (req, res, next) => {
  const { domain_id } = req.body;
  if (!domain_id || isNaN(parseInt(domain_id))) {
    return res.status(400).json({ error: 'domain_id must be a valid integer' });
  }
  req.body.domain_id = parseInt(domain_id);
  next();
};

const validatePagination = (req, res, next) => {
  const limit = parseInt(req.query.limit) || 50;
  const offset = parseInt(req.query.offset) || 0;
  req.query.limit = Math.min(Math.max(1, limit), 500);
  req.query.offset = Math.max(0, offset);
  next();
};

const sanitizeString = (str, maxLen = 255) => {
  if (typeof str !== 'string') return '';
  return str.trim().substring(0, maxLen).replace(/[<>]/g, '');
};

module.exports = { validateScanStart, validatePagination, sanitizeString };
