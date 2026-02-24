# 🔒 NEXUS Security Best Practices

## Guide de Sécurité pour Administrateurs

---

## 1. CONFIGURATION SÉCURISÉE

### Variables d'Environnement

**❌ JAMAIS faire:**
```bash
# NE JAMAIS commit .env dans Git
DB_PASSWORD=mypassword123
JWT_SECRET=secret
```

**✅ TOUJOURS faire:**
```bash
# Générer secrets forts
DB_PASSWORD=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 64)

# Utiliser gestionnaire secrets
aws secretsmanager create-secret --name nexus/prod/db-password
azure keyvault secret set --vault-name nexus --name db-password

# Variables environnement système
export DB_PASSWORD=$(aws secretsmanager get-secret-value --secret-id nexus/prod/db-password --query SecretString --output text)
```

### Rotation des Secrets

```bash
# Script de rotation automatique
#!/bin/bash

# Générer nouveau JWT secret
NEW_JWT_SECRET=$(openssl rand -base64 64)

# Update Secrets Manager
aws secretsmanager update-secret \
  --secret-id nexus/prod/jwt-secret \
  --secret-string "$NEW_JWT_SECRET"

# Rolling update des pods/containers
kubectl rollout restart deployment/nexus-backend
```

---

## 2. HARDENING DATABASE

### PostgreSQL Configuration

```sql
-- postgresql.conf

-- SSL obligatoire
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'

-- Logging
log_connections = on
log_disconnections = on
log_duration = on
log_statement = 'ddl'  # Log structure changes

-- Performance + Security
max_connections = 100
shared_buffers = 2GB
effective_cache_size = 6GB
```

```sql
-- pg_hba.conf

# Restreindre accès réseau
hostssl  nexus_pro  nexus  10.0.0.0/8  scram-sha-256
hostnossl all       all    all          reject

# Pas d'accès sans SSL
```

### Audit Logging

```sql
-- Activer pgAudit
CREATE EXTENSION pgaudit;

-- Auditer toutes modifications données sensibles
ALTER DATABASE nexus_pro SET pgaudit.log = 'write';
ALTER DATABASE nexus_pro SET pgaudit.log_catalog = off;
```

---

## 3. RATE LIMITING AVANCÉ

### Express Rate Limit

```javascript
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');

// Global API rate limit
const apiLimiter = rateLimit({
  store: new RedisStore({
    client: redis.createClient(process.env.REDIS_URL)
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests par IP
  message: 'Too many requests, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

// Auth endpoints - plus strict
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // 5 tentatives par IP
  skipSuccessfulRequests: true
});

// Scan endpoints - très limité
const scanLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 heure
  max: 10, // 10 scans par heure
  keyGenerator: (req) => req.user.id // Par user, pas IP
});

app.use('/api/', apiLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/scans/', scanLimiter);
```

### DDoS Protection

```nginx
# nginx.conf

# Connection limiting
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
limit_conn conn_limit 10;

# Request rate limiting
limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
limit_req zone=req_limit burst=20 nodelay;

# Timeout configuration
client_body_timeout 10s;
client_header_timeout 10s;
keepalive_timeout 15s;
send_timeout 10s;

# Buffer size limits
client_body_buffer_size 1M;
client_max_body_size 10M;
client_header_buffer_size 1k;
large_client_header_buffers 2 4k;
```

---

## 4. INPUT VALIDATION

### Validation Schema (Joi)

```javascript
const Joi = require('joi');

const domainSchema = Joi.object({
  url: Joi.string().uri().required(),
  name: Joi.string().max(100).optional(),
  revenue_per_hour: Joi.number().integer().min(0).max(1000000000).optional(),
  business_value: Joi.number().integer().min(0).max(100000000000).optional()
});

const scanSchema = Joi.object({
  domain_id: Joi.number().integer().required()
});

// Middleware
function validate(schema) {
  return (req, res, next) => {
    const {error} = schema.validate(req.body);
    if (error) {
      return res.status(400).json({error: error.details[0].message});
    }
    next();
  };
}

// Utilisation
router.post('/domains/add', auth, validate(domainSchema), addDomain);
router.post('/scans/start', auth, validate(scanSchema), startScan);
```

### SQL Injection Prevention

```javascript
// ❌ VULNÉRABLE
const query = `SELECT * FROM users WHERE email = '${email}'`;
db.prepare(query).all();

// ✅ SÉCURISÉ - Prepared statements
const query = `SELECT * FROM users WHERE email = ?`;
db.prepare(query).all(email);
```

### XSS Prevention

```javascript
// Sanitize output
const he = require('he');

function sanitizeHTML(str) {
  return he.encode(str);
}

// Avant envoi au client
response.title = sanitizeHTML(vulnerability.title);
response.description = sanitizeHTML(vulnerability.description);
```

---

## 5. AUTHENTIFICATION AVANCÉE

### MFA (2FA) Implementation

```javascript
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Générer secret 2FA
router.post('/auth/mfa/setup', auth, async (req, res) => {
  const secret = speakeasy.generateSecret({
    name: `NEXUS (${req.user.email})`,
    length: 32
  });

  // Sauvegarder secret
  db.prepare('UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?')
    .run(secret.base32, req.user.id);

  // Générer QR code
  const qrCode = await QRCode.toDataURL(secret.otpauth_url);

  res.json({secret: secret.base32, qrCode});
});

// Vérifier code 2FA
router.post('/auth/mfa/verify', auth, (req, res) => {
  const {token} = req.body;
  const user = db.prepare('SELECT mfa_secret FROM users WHERE id = ?').get(req.user.id);

  const verified = speakeasy.totp.verify({
    secret: user.mfa_secret,
    encoding: 'base32',
    token: token,
    window: 2
  });

  if (verified) {
    db.prepare('UPDATE users SET mfa_enabled = 1 WHERE id = ?').run(req.user.id);
    res.json({success: true});
  } else {
    res.status(400).json({error: 'Invalid code'});
  }
});

// Login avec 2FA
router.post('/auth/login', async (req, res) => {
  const {email, password, mfaToken} = req.body;
  
  // Vérifier password
  const user = await verifyPassword(email, password);
  if (!user) return res.status(401).json({error: 'Invalid credentials'});

  // Si 2FA activé
  if (user.mfa_enabled) {
    if (!mfaToken) {
      return res.status(403).json({error: 'MFA required', requireMFA: true});
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfa_secret,
      encoding: 'base32',
      token: mfaToken
    });

    if (!verified) {
      return res.status(401).json({error: 'Invalid MFA code'});
    }
  }

  // Générer JWT
  const token = generateJWT(user);
  res.json({token, user});
});
```

### Session Management

```javascript
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

app.use(session({
  store: new RedisStore({client: redisClient}),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // HTTPS only
    httpOnly: true, // Pas accessible via JS
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 jours
    sameSite: 'strict' // CSRF protection
  }
}));
```

---

## 6. CRYPTOGRAPHIE

### Password Hashing

```javascript
const bcrypt = require('bcryptjs');

// ✅ Hash password (rounds=12 minimum)
async function hashPassword(password) {
  return await bcrypt.hash(password, 12);
}

// ✅ Verify password
async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// ❌ JAMAIS utiliser MD5/SHA1 pour passwords
```

### Data Encryption

```javascript
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY = crypto.scryptSync(process.env.ENCRYPTION_KEY, 'salt', 32);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

function decrypt(encrypted, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    KEY,
    Buffer.from(iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
}
```

---

## 7. SECURITÉ API

### JWT Best Practices

```javascript
const jwt = require('jsonwebtoken');

// Générer JWT
function generateToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '7d',
      issuer: 'nexus-security',
      audience: 'nexus-api'
    }
  );
}

// Vérifier JWT
function verifyToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'nexus-security',
      audience: 'nexus-api'
    });
  } catch (err) {
    throw new Error('Invalid token');
  }
}

// Refresh token
router.post('/auth/refresh', (req, res) => {
  const {refreshToken} = req.body;
  
  const decoded = verifyToken(refreshToken);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.id);
  
  const newToken = generateToken(user);
  res.json({token: newToken});
});
```

### API Key Management

```javascript
const crypto = require('crypto');

// Générer API key
function generateAPIKey() {
  return crypto.randomBytes(32).toString('hex');
}

// Middleware API key auth
function apiKeyAuth(req, res, next) {
  const apiKey = req.header('X-API-Key');
  
  if (!apiKey) {
    return res.status(401).json({error: 'API key required'});
  }

  const user = db.prepare('SELECT * FROM users WHERE api_key = ?').get(apiKey);
  
  if (!user) {
    return res.status(403).json({error: 'Invalid API key'});
  }

  req.user = user;
  next();
}
```

---

## 8. MONITORING SÉCURITÉ

### Failed Login Tracking

```javascript
const redis = require('redis');
const client = redis.createClient();

async function trackFailedLogin(email, ip) {
  const key = `failed_login:${email}:${ip}`;
  const count = await client.incr(key);
  await client.expire(key, 3600); // 1 heure

  if (count >= 5) {
    // Bloquer temporairement
    await client.setEx(`blocked:${ip}`, 3600, '1');
    
    // Alerter
    await sendSecurityAlert({
      type: 'brute_force_attempt',
      email,
      ip,
      attempts: count
    });
  }
}

// Check if IP blocked
async function isBlocked(ip) {
  return await client.exists(`blocked:${ip}`);
}
```

### Security Event Logging

```javascript
function logSecurityEvent(event) {
  const logEntry = {
    timestamp: new Date(),
    type: event.type,
    severity: event.severity,
    user_id: event.user_id,
    ip: event.ip,
    details: event.details
  };

  db.prepare(`
    INSERT INTO security_events 
    (timestamp, type, severity, user_id, ip, details)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    logEntry.timestamp,
    logEntry.type,
    logEntry.severity,
    logEntry.user_id,
    logEntry.ip,
    JSON.stringify(logEntry.details)
  );

  // Alert si critique
  if (event.severity === 'critical') {
    sendSecurityAlert(event);
  }
}

// Exemples
logSecurityEvent({
  type: 'unauthorized_access_attempt',
  severity: 'high',
  user_id: req.user?.id,
  ip: req.ip,
  details: {endpoint: req.path}
});

logSecurityEvent({
  type: 'sql_injection_attempt',
  severity: 'critical',
  ip: req.ip,
  details: {payload: req.body}
});
```

---

## 9. INCIDENT RESPONSE

### Playbook

```markdown
# Incident de Sécurité

## 1. DÉTECTION (0-5 min)
- Alertes CloudWatch/Prometheus
- Logs anormaux
- Reports utilisateurs

## 2. TRIAGE (5-15 min)
- Évaluer sévérité (P0-P4)
- Identifier scope
- Activer équipe on-call

## 3. CONTAINMENT (15-60 min)
P0/P1:
- Isoler systèmes affectés
- Bloquer IPs malveillantes
- Désactiver comptes compromis
- Snapshot systèmes pour forensics

## 4. INVESTIGATION (1-4h)
- Analyser logs
- Identifier point d'entrée
- Déterminer données affectées
- Documenter timeline

## 5. ERADICATION (2-8h)
- Patcher vulnérabilités
- Changer credentials
- Nettoyer backdoors
- Vérifier autres systèmes

## 6. RECOVERY (4-24h)
- Restaurer depuis backups
- Valider intégrité
- Monitoring renforcé
- Tests de régression

## 7. POST-MORTEM (48h)
- Root cause analysis
- Documentation incident
- Mesures préventives
- Communication clients
```

---

## 10. CHECKLIST SÉCURITÉ

### Production Deployment

```markdown
## Infrastructure
- [ ] TLS 1.3 activé
- [ ] Certificats valides (<90j expiration)
- [ ] Firewall configuré (whitelist only)
- [ ] VPC/subnet isolation
- [ ] Security groups restrictifs

## Application
- [ ] Secrets en Secrets Manager (pas .env)
- [ ] JWT secret fort (64+ chars)
- [ ] Bcrypt rounds >= 12
- [ ] Rate limiting activé
- [ ] CORS configuré strictement
- [ ] Helmet middleware activé
- [ ] Input validation (Joi)
- [ ] SQL prepared statements
- [ ] XSS sanitization

## Database
- [ ] SSL/TLS obligatoire
- [ ] Encryption at rest
- [ ] Password fort (32+ chars)
- [ ] IP whitelist
- [ ] Audit logging activé
- [ ] Backups automatiques (daily)
- [ ] Backup retention (30j)

## Monitoring
- [ ] CloudWatch/Prometheus configuré
- [ ] Alertes critiques
- [ ] Failed login tracking
- [ ] Security event logging
- [ ] Audit logs conservés (1 an)

## Compliance
- [ ] GDPR data export
- [ ] GDPR data deletion
- [ ] SOC 2 controls
- [ ] Penetration test annuel
- [ ] Security training équipe
```

---

**NEXUS ULTIMATE PRO - Security Hardened**
