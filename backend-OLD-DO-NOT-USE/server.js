require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://poralytics.github.io';

app.set('trust proxy', 1);

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: [FRONTEND_URL, /\.github\.io$/],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests' }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(compression());

app.get('/', (req, res) => {
  res.json({
    service: 'NEXUS Security Platform',
    status: 'operational',
    version: '1.0.0',
    uptime: process.uptime()
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: Date.now() });
});

const routes = [
  { path: '/api/auth', file: './routes/auth' },
  { path: '/api/domains', file: './routes/domains' },
  { path: '/api/scans', file: './routes/scans' },
  { path: '/api/billing', file: './routes/billing' },
  { path: '/api/usage', file: './routes/usage' },
  { path: '/api/score', file: './routes/score' },
  { path: '/api/visualizations', file: './routes/visualizations' },
  { path: '/api/executive', file: './routes/executive' },
  { path: '/api/ai', file: './routes/ai' },
  { path: '/api/compliance', file: './routes/compliance' },
  { path: '/api/cicd', file: './routes/cicd' }
];

routes.forEach(({ path: routePath, file }) => {
  try {
    app.use(routePath, require(file));
  } catch (error) {
    console.log(`Route ${routePath} not loaded`);
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found' });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.statusCode || 500).json({
    error: NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`NEXUS Backend running on port ${PORT}`);
});

process.on('SIGTERM', () => server.close(() => process.exit(0)));
process.on('SIGINT', () => server.close(() => process.exit(0)));

module.exports = app;
