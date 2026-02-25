// NEXUS Production Server - PostgreSQL ONLY
// NO SQLITE - PostgreSQL or FAIL

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

console.log('╔════════════════════════════════════════╗');
console.log('║  NEXUS PRODUCTION SERVER - PostgreSQL  ║');
console.log('╚════════════════════════════════════════╝');
console.log('📍 Port:', PORT);
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');

// CRITICAL: Check DATABASE_URL exists
if (!process.env.DATABASE_URL) {
  console.error('❌ FATAL: DATABASE_URL environment variable is not set!');
  console.error('❌ This server REQUIRES PostgreSQL via DATABASE_URL');
  process.exit(1);
}

console.log('✅ DATABASE_URL is set');

// PostgreSQL Connection Pool - NO FALLBACK TO SQLITE
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('❌ PostgreSQL connection failed:', err.message);
    console.error('❌ Check your DATABASE_URL environment variable');
    process.exit(1);
  } else {
    console.log('✅ PostgreSQL connected:', res.rows[0].now);
    console.log('✅ Database type: PostgreSQL');
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"]
    }
  }
}));

// CORS
app.use(cors({ origin: '*', credentials: true }));

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.set('trust proxy', 1);

// CRITICAL: Serve static files from frontend/
const frontendPath = path.join(__dirname, 'frontend');
console.log('📂 Frontend path:', frontendPath);
app.use(express.static(frontendPath));

// Logging
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// JWT
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const JWT_EXPIRES_IN = '7d';

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ==================== ROUTES ====================

app.get('/health', (req, res) => {
  res.json({
    service: 'NEXUS Security Platform',
    status: 'operational',
    version: '2.0.0',
    database: 'PostgreSQL',
    uptime: process.uptime()
  });
});

app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    let { email, password, name } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    email = email.toLowerCase().trim();
    name = name ? name.trim() : email.split('@')[0];

    const userCheck = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (email, password, name, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, email, name',
      [email, hashedPassword, name]
    );

    const user = result.rows[0];
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    console.log('✅ User registered:', email);
    res.status(201).json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    let { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    email = email.toLowerCase().trim();
    const result = await pool.query('SELECT id, email, name, password FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

    console.log('✅ User logged in:', email);
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, name, created_at, last_login FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Dashboard
app.get('/api/dashboard/metrics', authenticateToken, async (req, res) => {
  try {
    const stats = { securityScore: 850, totalAssets: 12, criticalIssues: 8, scansCompleted: 156 };
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get metrics' });
  }
});

// Domains
app.get('/api/domains', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, url, name, created_at FROM domains WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.userId]
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch domains' });
  }
});

app.post('/api/domains', authenticateToken, async (req, res) => {
  try {
    let { url, name } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    url = url.trim();
    name = name ? name.trim() : url;
    const result = await pool.query(
      'INSERT INTO domains (user_id, url, name, created_at) VALUES ($1, $2, $3, NOW()) RETURNING *',
      [req.user.userId, url, name]
    );
    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: 'Failed to add domain' });
  }
});

app.delete('/api/domains/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM domains WHERE id = $1 AND user_id = $2 RETURNING url',
      [req.params.id, req.user.userId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Domain not found' });
    }
    res.json({ message: 'Domain deleted' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete domain' });
  }
});

// 404
app.use((req, res) => {
  if (req.url.startsWith('/api/')) {
    res.status(404).json({ error: 'API route not found' });
  } else {
    // Serve login.html for any non-API 404
    res.sendFile(path.join(frontendPath, 'login.html'));
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('❌ Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('╔════════════════════════════════════════╗');
  console.log('║  ✅ NEXUS SERVER RUNNING              ║');
  console.log('║  Database: PostgreSQL                  ║');
  console.log('║  Port:', PORT.toString().padEnd(32), '║');
  console.log('╚════════════════════════════════════════╝');
});

process.on('SIGTERM', () => {
  console.log('Shutting down...');
  server.close(() => {
    pool.end();
    process.exit(0);
  });
});
