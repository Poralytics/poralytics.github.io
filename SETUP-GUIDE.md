# 🏆 NEXUS ULTIMATE PRO v5.0 - COMPLETE SETUP GUIDE

## 🚀 Quick Start (5 Minutes)

```bash
# 1. Clone or extract the project
cd NEXUS-FINAL-PRO/backend

# 2. Run automated setup (RECOMMENDED)
node setup.js

# 3. Start the server
npm start

# 4. Open http://localhost:3000
```

**That's it!** The setup script handles everything automatically.

---

## 📋 Manual Setup (If you prefer)

### Step 1: Prerequisites

**Required:**
- Node.js 18+ ([Download](https://nodejs.org/))
- npm 9+ (comes with Node.js)

**Optional but Recommended:**
- Redis 7+ ([Install Guide](https://redis.io/docs/getting-started/))
- PostgreSQL 15+ (for production, SQLite works for development)

### Step 2: Install Dependencies

```bash
cd backend
npm install
```

This installs 40+ packages including:
- Express, Axios, Cheerio (core)
- Stripe, Redis, BullMQ (services)
- PDFKit, ExcelJS (reports)
- Jest, Playwright (testing)

### Step 3: Environment Configuration

```bash
# Copy the example environment file
cp .env.example .env

# Edit .env with your favorite editor
nano .env
# or
code .env
```

**Minimum Required Variables:**
```env
JWT_SECRET=your-secret-key-change-this
PORT=3000
NODE_ENV=development
```

**Optional but Recommended:**
```env
# Stripe (for billing)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_BUSINESS=price_...

# Redis (for caching & queues)
REDIS_URL=redis://localhost:6379

# OpenAI (for AI Assistant)
OPENAI_API_KEY=sk-...
```

### Step 4: Database Setup

```bash
# Run migrations
node migrations/run-migrations.js

# Or use the npm script
npm run migrate
```

This creates 50+ tables for all features.

### Step 5: Create Admin User

```bash
# Initialize with default admin
npm run init

# Or create custom admin via setup script
node setup.js
```

Default admin credentials:
- Email: `admin@nexus.com`
- Password: `admin123` (CHANGE THIS!)

### Step 6: Start Development Server

```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start

# With worker processes
npm start & npm run worker
```

Server runs on: `http://localhost:3000`

---

## 🔧 Configuration Deep Dive

### Database Options

**SQLite (Default - Development):**
```env
# Already configured, no setup needed
# Database file: backend/nexus-ultimate.db
```

**PostgreSQL (Production):**
```env
# Install: brew install postgresql
# Start: brew services start postgresql

# Update in .env:
DB_TYPE=postgresql
DB_HOST=localhost
DB_PORT=5432
DB_NAME=nexus
DB_USER=nexus_user
DB_PASSWORD=secure_password
```

### Redis Setup (Required for full features)

**Mac:**
```bash
brew install redis
brew services start redis
```

**Linux:**
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

**Docker:**
```bash
docker run -d -p 6379:6379 redis:7-alpine
```

**Verify:**
```bash
redis-cli ping
# Should return: PONG
```

### Stripe Configuration

1. Go to [Stripe Dashboard](https://dashboard.stripe.com/test/apikeys)
2. Copy your **Secret Key** (sk_test_...)
3. Add to `.env`:
```env
STRIPE_SECRET_KEY=sk_test_your_key
```

4. Create Products & Prices:
```
Product: NEXUS Pro
Price: $49/month → Copy Price ID
Add to .env: STRIPE_PRICE_PRO=price_...

Product: NEXUS Business
Price: $199/month → Copy Price ID
Add to .env: STRIPE_PRICE_BUSINESS=price_...
```

### OpenAI Configuration (AI Assistant)

1. Go to [OpenAI API Keys](https://platform.openai.com/api-keys)
2. Create new key
3. Add to `.env`:
```env
OPENAI_API_KEY=sk-...
```

---

## 🐳 Docker Deployment

### Quick Docker Start

```bash
cd docker
docker-compose up -d
```

This starts:
- NEXUS Backend (port 3000)
- PostgreSQL (port 5432)
- Redis (port 6379)

### Build Custom Image

```bash
cd docker
docker build -t nexus-backend .
docker run -p 3000:3000 nexus-backend
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Unit tests only
npm run test:unit

# Integration tests
npm run test:integration

# E2E tests
npm run test:e2e

# Watch mode (during development)
npm run test:watch

# Coverage report
npm test -- --coverage
```

**Coverage Targets:**
- Branches: 80%
- Functions: 80%
- Lines: 80%
- Statements: 80%

---

## 📊 Available Services

### Core Services (Always Available)
✅ **20 Security Scanners** - SQL, XSS, CSRF, etc.
✅ **Vulnerability Database** - SQLite/PostgreSQL
✅ **User Authentication** - JWT-based
✅ **API Endpoints** - RESTful API
✅ **Web Dashboard** - HTML/CSS/JS

### Premium Services (Need Configuration)
⚙️ **Billing System** - Requires Stripe
⚙️ **Real-time Notifications** - Requires WebSocket
⚙️ **Distributed Scanning** - Requires Redis + BullMQ
⚙️ **Intelligent Cache** - Requires Redis
⚙️ **AI Assistant** - Requires OpenAI API
⚙️ **Email Notifications** - Requires SMTP

### Advanced Features (Optional)
🎯 **Scanner Marketplace** - Ready to use
🎯 **White-Label System** - Ready to use
🎯 **Gamification** - Ready to use
🎯 **Compliance Automation** - Ready to use (6 frameworks)
🎯 **Threat Intelligence** - Ready to use

---

## 🚀 Production Deployment

### Option 1: Heroku

```bash
# Install Heroku CLI
brew install heroku

# Login
heroku login

# Create app
heroku create nexus-security

# Add PostgreSQL
heroku addons:create heroku-postgresql:hobby-dev

# Add Redis
heroku addons:create heroku-redis:hobby-dev

# Set environment variables
heroku config:set JWT_SECRET=your-secret
heroku config:set STRIPE_SECRET_KEY=sk_live_...

# Deploy
git push heroku main

# Open app
heroku open
```

### Option 2: Railway

1. Go to [Railway.app](https://railway.app)
2. Click "New Project" → "Deploy from GitHub"
3. Select your repository
4. Add PostgreSQL and Redis services
5. Set environment variables
6. Deploy!

### Option 3: DigitalOcean

```bash
# Create droplet (Ubuntu 22.04)
# SSH into server

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install Redis & PostgreSQL
sudo apt-get install redis-server postgresql

# Clone project
git clone your-repo.git
cd NEXUS-FINAL-PRO/backend

# Install dependencies
npm install --production

# Setup PM2 for process management
npm install -g pm2
pm2 start server.js --name nexus
pm2 save
pm2 startup
```

### Option 4: AWS EC2

Same as DigitalOcean, then:
1. Setup Load Balancer
2. Configure Auto Scaling
3. Add RDS (PostgreSQL)
4. Add ElastiCache (Redis)

---

## 📈 Monitoring & Logs

### View Logs

```bash
# Real-time logs
npm run dev

# Docker logs
docker-compose logs -f

# PM2 logs (production)
pm2 logs nexus
```

### Performance Monitoring

**Optional Integrations:**
- Sentry (error tracking)
- Datadog (APM)
- LogTail (log management)
- New Relic (performance)

Add to `.env`:
```env
SENTRY_DSN=https://...
```

---

## 🔐 Security Checklist

Before production:
- [ ] Change default admin password
- [ ] Generate strong JWT_SECRET
- [ ] Enable HTTPS/SSL
- [ ] Configure CORS properly
- [ ] Set up rate limiting
- [ ] Enable Helmet.js (already included)
- [ ] Regular database backups
- [ ] Use environment-specific .env files
- [ ] Never commit .env to Git

---

## 🆘 Troubleshooting

### "Cannot find module"
```bash
npm install
```

### "Port 3000 already in use"
```bash
# Find process
lsof -i :3000

# Kill process
kill -9 <PID>

# Or change port in .env
PORT=3001
```

### "Database locked"
```bash
# Stop all processes
killall node

# Restart
npm start
```

### "Redis connection failed"
```bash
# Start Redis
redis-server

# Or disable Redis features in .env
ENABLE_REDIS=false
```

### "Stripe webhook failed"
```bash
# Use Stripe CLI for local testing
stripe listen --forward-to localhost:3000/api/webhooks/stripe
```

---

## 📚 Additional Resources

- **Full Documentation**: See `/docs` folder
- **API Reference**: See `/docs/API.md`
- **Deployment Guide**: See `/docs/DEPLOYMENT.md`
- **Contributing**: See `/docs/CONTRIBUTING.md`

---

## 🎯 What's Next?

1. ✅ Complete setup (you're here!)
2. 📝 Configure environment variables
3. 🧪 Run tests to verify
4. 🚀 Deploy to staging
5. 💰 Launch to production
6. 📈 Monitor and scale

---

## 💡 Need Help?

- 📖 Read the docs: `/docs`
- 🐛 Report bugs: GitHub Issues
- 💬 Ask questions: Discussions
- 📧 Contact: support@nexussecurity.com

---

**NEXUS Ultimate Pro v5.0**
*The Most Complete Security Platform Ever Created*

Ready to dominate the $75B security market! 🚀
