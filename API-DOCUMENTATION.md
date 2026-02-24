# 📘 NEXUS ULTIMATE PRO - API Documentation

## Base URL

```
http://localhost:3000/api
```

## Authentication

Tous les endpoints (sauf /auth/*) nécessitent un token JWT dans le header:

```
Authorization: Bearer <token>
```

---

## Authentication Endpoints

### Register

```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@company.com",
  "password": "SecurePassword123!",
  "name": "John Doe",
  "company": "Acme Corp"
}
```

**Response 200:**
```json
{
  "user": {
    "id": 1,
    "email": "user@company.com",
    "name": "John Doe",
    "company": "Acme Corp"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "demo@nexus.security",
  "password": "nexus2024"
}
```

**Response 200:**
```json
{
  "user": {
    "id": 1,
    "email": "demo@nexus.security",
    "name": "Demo User"
  },
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Get Current User

```http
GET /api/auth/me
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "user": {
    "id": 1,
    "email": "demo@nexus.security",
    "name": "Demo User",
    "company": "NEXUS Demo",
    "created_at": "2024-02-14T08:00:00.000Z"
  }
}
```

---

## Domains Endpoints

### List Domains

```http
GET /api/domains/list
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "domains": [
    {
      "id": 1,
      "url": "https://example.com",
      "name": "Example Site",
      "security_score": 75,
      "risk_exposure_eur": 1200000,
      "total_scans": 5,
      "critical_vulns": 2,
      "active_predictions": 3,
      "created_at": "2024-02-01T10:00:00.000Z"
    }
  ]
}
```

### Add Domain

```http
POST /api/domains/add
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://myapp.com",
  "name": "My Application",
  "revenue_per_hour": 25000,
  "business_value": 5000000,
  "criticality": "high"
}
```

**Response 200:**
```json
{
  "domain": {
    "id": 2,
    "url": "https://myapp.com",
    "name": "My Application",
    "revenue_per_hour": 25000,
    "business_value": 5000000,
    "criticality": "high",
    "status": "active"
  }
}
```

### Get Domain Details

```http
GET /api/domains/{id}
Authorization: Bearer <token>
```

### Delete Domain

```http
DELETE /api/domains/{id}
Authorization: Bearer <token>
```

---

## Scans Endpoints

### Start Scan

```http
POST /api/scans/start
Authorization: Bearer <token>
Content-Type: application/json

{
  "domain_id": 1
}
```

**Response 200:**
```json
{
  "scan": {
    "id": 123,
    "domain_id": 1,
    "status": "pending",
    "progress": 0,
    "started_at": "2024-02-14T09:00:00.000Z"
  },
  "message": "Scan started successfully"
}
```

### Get Scan Progress

```http
GET /api/scans/{id}/progress
Authorization: Bearer <token>
```

**Response 200 (En cours):**
```json
{
  "id": 123,
  "status": "running",
  "progress": 65,
  "phase": "API security testing",
  "vulnerabilities_found": 18
}
```

**Response 200 (Terminé):**
```json
{
  "id": 123,
  "status": "completed",
  "progress": 100,
  "security_score": 72,
  "vulnerabilities_found": 27,
  "vulnerabilities_fixed": 9,
  "risk_exposure_eur": 3200000
}
```

### Get Scan Results

```http
GET /api/scans/{id}
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "scan": {
    "id": 123,
    "domain_id": 1,
    "status": "completed",
    "security_score": 72,
    "vulnerabilities_found": 27,
    "started_at": "2024-02-14T09:00:00.000Z",
    "completed_at": "2024-02-14T09:01:30.000Z",
    "duration_seconds": 90
  },
  "vulnerabilities": [
    {
      "id": 1,
      "severity": "critical",
      "category": "injection",
      "title": "SQL Injection in Login Form",
      "description": "SQL injection vulnerability allows authentication bypass",
      "cvss_score": 9.8,
      "business_impact_eur": 1800000,
      "exploit_probability": 0.85,
      "expected_loss_eur": 1530000,
      "remediation_text": "Use parameterized queries",
      "remediation_effort_hours": 4,
      "auto_fixable": false,
      "auto_fixed": false,
      "status": "open"
    }
  ]
}
```

### List Scans

```http
GET /api/scans/list?limit=50
Authorization: Bearer <token>
```

---

## Analytics Endpoints

### Overview

```http
GET /api/analytics/overview
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "total_domains": 5,
  "total_scans": 42,
  "total_vulnerabilities": 156,
  "average_score": 76,
  "critical_count": 8,
  "high_count": 24,
  "medium_count": 67,
  "low_count": 57,
  "total_risk_exposure_eur": 8400000,
  "auto_fixed_count": 52
}
```

### Vulnerabilities Breakdown

```http
GET /api/analytics/vulnerabilities/breakdown
Authorization: Bearer <token>
```

### Top Vulnerabilities

```http
GET /api/analytics/vulnerabilities/top?limit=10
Authorization: Bearer <token>
```

### Industry Benchmark

```http
GET /api/analytics/benchmark
Authorization: Bearer <token>
```

---

## Reports Endpoints

### Generate Report

```http
POST /api/reports/generate
Authorization: Bearer <token>
Content-Type: application/json

{
  "scan_id": 123,
  "type": "executive"
}
```

**Types disponibles:**
- `executive` - Rapport pour CEO/Board
- `technical` - Rapport technique pour dev/sec teams
- `compliance` - Rapport conformité (GDPR/SOC2/ISO27001)

**Response 200:**
```json
{
  "report": {
    "id": 5,
    "title": "Executive Security Report - My Application",
    "file_path": "/reports/executive-report-123-1707900000.json",
    "generated_at": "2024-02-14T09:30:00.000Z"
  },
  "download_url": "/api/reports/download/5"
}
```

### Download Report

```http
GET /api/reports/download/{id}
Authorization: Bearer <token>
```

### List Reports

```http
GET /api/reports/list
Authorization: Bearer <token>
```

---

## Notifications Endpoints

### Get Alerts

```http
GET /api/notifications/alerts?limit=20&unread_only=true
Authorization: Bearer <token>
```

**Response 200:**
```json
{
  "alerts": [
    {
      "id": 1,
      "type": "scan_completed",
      "severity": "high",
      "title": "Critical Vulnerabilities Found",
      "message": "Scan #123 found 4 critical vulnerabilities",
      "impact_eur": 3200000,
      "is_read": false,
      "created_at": "2024-02-14T09:30:00.000Z"
    }
  ]
}
```

### Mark Alert as Read

```http
PATCH /api/notifications/alerts/{id}/read
Authorization: Bearer <token>
```

---

## Webhooks

### Configuration

Dans votre `.env`:
```bash
WEBHOOK_URL=https://your-server.com/webhook
WEBHOOK_SECRET=your-secret-key
```

### Payload

**Événement: scan_completed**

```json
{
  "event": "scan_completed",
  "timestamp": "2024-02-14T09:30:00.000Z",
  "scan": {
    "id": 123,
    "domain_url": "https://example.com",
    "security_score": 72,
    "risk_exposure_eur": 3200000,
    "vulnerabilities": {
      "critical": 4,
      "high": 8,
      "medium": 11,
      "low": 4
    }
  },
  "top_vulnerabilities": [
    {
      "severity": "critical",
      "title": "SQL Injection",
      "expected_loss_eur": 1530000
    }
  ]
}
```

**Vérification Signature:**

```javascript
const crypto = require('crypto');

function verifyWebhook(payload, signature, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  const digest = hmac.update(JSON.stringify(payload)).digest('hex');
  return signature === digest;
}
```

---

## Rate Limiting

- **Auth endpoints**: 5 requêtes/minute
- **API endpoints**: 100 requêtes/minute
- **Scans**: 5 scans concurrents maximum

**Headers de réponse:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1707900000
```

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "Invalid input data",
  "details": "URL is required"
}
```

### 401 Unauthorized
```json
{
  "error": "Authentication required"
}
```

### 403 Forbidden
```json
{
  "error": "Access denied"
}
```

### 404 Not Found
```json
{
  "error": "Resource not found"
}
```

### 429 Too Many Requests
```json
{
  "error": "Rate limit exceeded",
  "retry_after": 60
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "request_id": "abc123"
}
```

---

## SDKs & Examples

### cURL

```bash
# Login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@nexus.security","password":"nexus2024"}'

# Start scan
curl -X POST http://localhost:3000/api/scans/start \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain_id":1}'
```

### Python

```python
import requests

# Login
response = requests.post('http://localhost:3000/api/auth/login', json={
    'email': 'demo@nexus.security',
    'password': 'nexus2024'
})
token = response.json()['token']

# Start scan
headers = {'Authorization': f'Bearer {token}'}
scan = requests.post('http://localhost:3000/api/scans/start',
    headers=headers,
    json={'domain_id': 1}
)
print(scan.json())
```

### Node.js

```javascript
const axios = require('axios');

const api = axios.create({
  baseURL: 'http://localhost:3000/api'
});

// Login
const {data} = await api.post('/auth/login', {
  email: 'demo@nexus.security',
  password: 'nexus2024'
});

// Set token
api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;

// Start scan
const scan = await api.post('/scans/start', {domain_id: 1});
console.log(scan.data);
```

---

**NEXUS ULTIMATE PRO - Complete API Reference**
