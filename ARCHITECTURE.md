# 🏗️ NEXUS Architecture Documentation

## System Overview

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│   Frontend  │◄───────►│   Server.js  │◄───────►│   SQLite    │
│  (HTML/JS)  │  HTTPS  │   (Express)  │   DB    │  Database   │
└─────────────┘         └──────────────┘         └─────────────┘
                              │ │ │
                ┌─────────────┘ │ └──────────────┐
                ▼               ▼                 ▼
        ┌──────────────┐  ┌──────────┐  ┌──────────────┐
        │  WebSocket   │  │  Routes  │  │ Orchestrator │
        │   Server     │  │  (22)    │  │  (Parallel)  │
        └──────────────┘  └──────────┘  └──────────────┘
                                               │
                              ┌────────────────┼────────────────┐
                              ▼                ▼                ▼
                        ┌─────────┐      ┌─────────┐     ┌─────────┐
                        │Scanner 1│ ...  │Scanner │ ... │Scanner  │
                        │  (SQL)  │      │  (XSS) │     │ 23(XXE) │
                        └─────────┘      └─────────┘     └─────────┘
```

## Core Components

### 1. Server (server.js)
- **Express.js** HTTP server
- **WebSocket** real-time connection (ws library)
- **Security Middleware**: Helmet, CORS, rate limiting
- **Routes**: 22 API route files
- **Error Handling**: Global error handler + circuit breakers

### 2. Database (SQLite)
**Tables**:
- `users` — authentication, plans
- `domains` — registered domains
- `scans` — scan records with progress
- `vulnerabilities` — findings with CVSS scores
- `error_logs` — structured error logging
- `stripe_events` — billing webhook idempotency
- `circuit_breaker_stats` — failure tracking
- `security_events` — audit log

**Indexes**:
- `idx_scans_domain`, `idx_scans_user`, `idx_scans_status`
- `idx_vulns_scan`, `idx_vulns_severity`
- `idx_domains_user`

### 3. Scan Orchestrator
**File**: `services/complete-scan-orchestrator.js`

**Flow**:
1. `startScan(scanId, domainId, userId, url)` called
2. Updates scan status to 'running'
3. Builds array of 23 scanner promises
4. Executes `Promise.allSettled(promises)` — **TRUE PARALLEL**
5. Each scanner result normalized → saved to DB incrementally
6. Calculate final stats (total vulns, security score)
7. Update scan status to 'completed'
8. Emit 'completed' event

**Scanner Loading**:
```javascript
const scannerDefs = [
  { name: 'SQL Injection', file: 'real-sql-scanner.js', weight: 6 },
  { name: 'XSS', file: 'real-xss-scanner.js', weight: 5 },
  // ... 21 more
];

resolveScanner(def) {
  const exported = require(`../scanners/${def.file}`);
  // Handle both class exports and instance exports
  return typeof exported === 'function' ? new exported() : exported;
}
```

**Progress Calculation**:
```javascript
completedWeight = sum of weights of finished scanners
progress = (completedWeight / totalWeight) * 100
// Emits progress events for WebSocket
```

**Security Score**:
```javascript
score = 1000 - (critical*200) - (high*100) - (medium*30) - (low*10) - (info*2)
risk_level = score >= 800 ? 'low' : score >= 600 ? 'medium' : 'high/critical'
```

### 4. Scanners (23 total)
**Common Structure**:
```javascript
class Scanner {
  constructor() {
    this.httpClient = new SecureHttpClient();
  }

  async scan(url) {
    const vulnerabilities = [];
    const errors = [];
    try {
      // Detection logic here
      // Push to vulnerabilities array
    } catch (err) {
      errors.push({ message: err.message, phase: 'detection' });
    }
    return { vulnerabilities, errors, url, scanned: true };
  }
}
module.exports = Scanner;
```

**Scanner Categories**:
- **Critical**: SQL Injection, XSS, SSRF, Command Injection, XXE
- **High**: CSRF, Authentication, Access Control, Open Redirect
- **Medium**: Clickjacking, SSL/TLS, Headers, Info Disclosure, Crypto
- **Low**: API Security, Infrastructure, Components, Business Logic

### 5. SecureHttpClient
**File**: `utils/secure-http-client.js`

**Protection Features**:
- **SSRF Blocking**: Blocks localhost, 10.x, 192.168.x, 172.16-31.x
- **Protocol Whitelist**: Only http/https
- **Timeouts**: 10s per request, 5s connect timeout
- **Size Limits**: 10MB max response
- **Redirect Limits**: Max 5 redirects
- **Decompression**: brotli blocked (bomb protection)

**DNS Resolution Check**:
```javascript
validateTarget(url) {
  const ip = dns.resolve(hostname);
  if (isPrivateIP(ip)) throw new Error('SSRF blocked');
}
```

### 6. Circuit Breakers
**File**: `utils/error-handler.js`

**States**: CLOSED → OPEN → HALF_OPEN

**Logic**:
```javascript
if (failures >= threshold) state = 'OPEN';
if (state === 'OPEN' && now > nextAttempt) state = 'HALF_OPEN';
if (state === 'HALF_OPEN' && success) state = 'CLOSED';
```

**Used For**:
- Scan orchestrator
- Stripe API calls
- External service integrations

### 7. WebSocket Server
**File**: `services/real-websocket-server.js`

**Features**:
- JWT authentication via message: `{type:'auth',token}`
- Per-user connection tracking
- Broadcast and targeted messages
- Heartbeat/ping-pong for connection health

**Events Sent**:
- `scan_progress` — real-time scan updates
- `scan_complete` — final results
- `alert` — security notifications

### 8. PDF Report Generator
**File**: `services/pdf-report-generator.js`

**Sections**:
1. Cover page with security score badge
2. Executive summary with severity breakdown
3. Vulnerability table (sortable, top 40)
4. Detailed findings (critical/high only, top 15)
5. Recommendations (immediate/short/medium/long term)
6. Footer with timestamp

**Library**: PDFKit

### 9. Billing System
**File**: `services/real-stripe-billing.js`

**Features**:
- Idempotent webhook handling (stripe_events table)
- Circuit breaker for Stripe API
- Automatic retry on transient failures
- Rollback on database errors
- Event listeners for monitoring

**Webhook Flow**:
```javascript
1. Verify signature
2. Check idempotency (stripe_events.event_id)
3. Process event (subscription.created, invoice.paid, etc.)
4. Save to DB
5. Update user.plan / stripe_subscription_id
6. Emit event for downstream processing
```

### 10. Job Queue (Worker)
**File**: `workers/scan-worker.js`

**Features**:
- Polls database every 3s for pending scans
- Max 3 concurrent scans
- Connects to orchestrator
- Listens to progress/completed/failed events
- Updates DB on progress
- Cleanup stuck scans on startup (running > 30 min)

**Process**:
```javascript
while (true) {
  if (activeScans < MAX_CONCURRENT) {
    scan = db.get(pending scan);
    orchestrator.startScan(...).catch(log);
    activeScans++;
  }
  sleep(3s);
}
```

## Data Flow

### Scan Lifecycle

1. **User Request**
   ```
   POST /api/scans/start {domain_id: 123}
   ```

2. **Route Handler** (`routes/scans.js`)
   - Validate domain ownership
   - Check for running scan
   - Create scan record (status: 'pending')
   - Add to job queue OR call orchestrator directly

3. **Worker Picks Up**
   - Finds pending scan in DB
   - Calls `orchestrator.startScan(scanId, ...)`

4. **Orchestrator Executes**
   - Sets status to 'running'
   - Loads 23 scanners
   - Runs `Promise.allSettled([...scanners.map(s => s.scan(url))])`
   - Each scanner returns `{vulnerabilities, errors}`

5. **Results Processing**
   - Normalize scanner outputs
   - Insert vulnerabilities to DB (incremental)
   - Calculate stats (total, critical, high, medium, low)
   - Calculate security score
   - Update scan record

6. **Completion**
   - Status → 'completed'
   - Domain.security_score updated
   - WebSocket event sent to user
   - Worker decrements activeScans

### Authentication Flow

1. **Login**
   ```
   POST /api/auth/login {email, password}
   ```

2. **Validation**
   - Check user exists
   - bcrypt.compare(password, hash)

3. **Token Generation**
   ```javascript
   jwt.sign({userId, email, role, plan}, JWT_SECRET, {expiresIn:'7d'})
   ```

4. **Client Storage**
   - localStorage.setItem('nexus_token', token)

5. **Authenticated Requests**
   ```javascript
   headers: { Authorization: `Bearer ${token}` }
   ```

6. **Middleware Verification**
   - Extract token from header
   - jwt.verify(token, JWT_SECRET)
   - Attach user to req.user
   - Pass to route handler

## Security Architecture

### Layers

1. **Network Layer**
   - HTTPS only (TLS 1.2+)
   - HSTS header
   - Rate limiting per IP

2. **Application Layer**
   - JWT authentication
   - Role-based access control
   - Input validation
   - Parameterized SQL queries

3. **Scanner Layer**
   - SecureHttpClient SSRF protection
   - Timeout enforcement
   - Size limits
   - Redirect limits

4. **Data Layer**
   - SQLite prepared statements
   - Foreign key constraints
   - Audit logging (security_events table)

### Threat Model

**Protected Against**:
- ✅ SQL Injection (prepared statements)
- ✅ XSS (JSON API, no HTML rendering)
- ✅ SSRF (SecureHttpClient blocks private IPs)
- ✅ CSRF (JWT in header, not cookie)
- ✅ Brute Force (rate limiting)
- ✅ Token Theft (short expiry, HTTPS only)
- ✅ Denial of Service (timeouts, circuit breakers, rate limits)

**Residual Risks**:
- ⚠️ JWT Secret Compromise (rotate immediately if leaked)
- ⚠️ Database File Access (ensure file permissions)
- ⚠️ Dependency Vulnerabilities (run `npm audit` regularly)

## Performance Characteristics

### Benchmarks

- **Single Scan**: ~60 seconds (23 scanners parallel)
- **Throughput**: 3 concurrent scans per worker instance
- **Memory**: ~150MB per worker instance
- **Database**: SQLite handles 1000+ scans easily (<100MB)

### Bottlenecks

1. **Scanner Timeout** (10s per HTTP request)
   - Tune in secure-http-client.js
2. **Database Writes** (incremental vuln inserts)
   - Consider batch inserts for >1000 vulns/scan
3. **Worker Polling** (3s interval)
   - Switch to Redis pub/sub for instant pickup

### Scaling Limits

- **SQLite**: ~100k vulnerabilities, ~10k scans
- **Beyond**: Migrate to PostgreSQL
- **Horizontal**: Add workers, shared Redis queue

## Deployment Topology

### Single-Instance (Development)

```
┌─────────────────────────────────────┐
│         Ubuntu/Debian Server        │
│  ┌─────────┐  ┌────────┐  ┌──────┐ │
│  │  Node   │  │ SQLite │  │Redis?│ │
│  │ server  │  │  .db   │  │(opt) │ │
│  └─────────┘  └────────┘  └──────┘ │
└─────────────────────────────────────┘
```

### Multi-Instance (Production)

```
      ┌───────────────┐
      │ Load Balancer │
      │   (nginx)     │
      └───────┬───────┘
              │
    ┌─────────┼─────────┐
    ▼         ▼         ▼
┌────────┐ ┌────────┐ ┌────────┐
│ Node 1 │ │ Node 2 │ │ Node 3 │
└────┬───┘ └────┬───┘ └────┬───┘
     │          │          │
     └──────────┼──────────┘
                ▼
         ┌──────────────┐
         │ Shared Redis │
         └──────────────┘
                │
                ▼
         ┌──────────────┐
         │  PostgreSQL  │
         └──────────────┘
```

### Kubernetes (Cloud)

```
┌───────────────────────────────────────┐
│           Kubernetes Cluster          │
│  ┌─────────────────────────────────┐  │
│  │  Ingress (TLS termination)      │  │
│  └─────────┬───────────────────────┘  │
│            │                           │
│  ┌─────────▼──────────┐                │
│  │  Service (ClusterIP)│               │
│  └─────────┬───────────┘               │
│            │                           │
│  ┌─────────▼──────────┐                │
│  │ Deployment (3 pods)│                │
│  │  - nexus-scanner-1 │                │
│  │  - nexus-scanner-2 │                │
│  │  - nexus-scanner-3 │                │
│  └─────────┬───────────┘               │
│            │                           │
│  ┌─────────▼──────────┐  ┌──────────┐ │
│  │  Redis (StatefulSet)  │  CloudSQL  │ │
│  └────────────────────┘  └──────────┘ │
└───────────────────────────────────────┘
```

---

**NEXUS v2.1.0** — Production Architecture
