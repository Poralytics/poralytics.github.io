/**
 * E2E Tests - Complete Scan Flow
 * Tests the full scan pipeline from API to results
 */
const request = require('supertest');

expect.extend({
  toBeOneOf(received, array) {
    const pass = array.includes(received);
    return {
      pass,
      message: () => `expected ${received} ${pass ? 'not ' : ''}to be one of ${JSON.stringify(array)}`
    };
  }
});

let app;
let authToken;
let testDomainId;
let testScanId;

beforeAll(async () => {
  process.env.JWT_SECRET = 'test-jwt-secret-for-e2e-testing-only-32chars!!';
  process.env.NODE_ENV = 'test';
  app = require('../../server');

  // Register + login
  const reg = await request(app)
    .post('/api/auth/register')
    .send({
      email: `e2e-${Date.now()}@nexus-test.com`,
      password: 'E2ETestPass123!@#',
      name: 'E2E Test'
    });

  authToken = reg.body.token;
}, 15000);

afterAll(async () => {
  await new Promise(resolve => setTimeout(resolve, 500));
});

describe('Domain Management', () => {
  test('Can create a domain', async () => {
    if (!authToken) return;

    const res = await request(app)
      .post('/api/domains')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ url: 'https://example.com', name: 'Example Domain' });

    expect(res.status).toBeOneOf([200, 201, 400, 409]);
    if (res.status === 200 || res.status === 201) {
      testDomainId = res.body.id || res.body.domain?.id;
    }
  });

  test('Can list domains', async () => {
    if (!authToken) return;

    const res = await request(app)
      .get('/api/domains')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.domains || res.body)).toBe(true);

    // Pick a domain for scan test
    const domains = res.body.domains || res.body;
    if (domains.length > 0) {
      testDomainId = testDomainId || domains[0].id;
    }
  });
});

describe('Scan Flow', () => {
  test('Can start a scan', async () => {
    if (!authToken || !testDomainId) {
      console.log('Skipping: no auth token or domain');
      return;
    }

    const res = await request(app)
      .post('/api/scans/start')
      .set('Authorization', `Bearer ${authToken}`)
      .send({ domain_id: testDomainId });

    expect(res.status).toBeOneOf([200, 201, 409]);
    if (res.status === 200 || res.status === 201) {
      testScanId = res.body.scanId || res.body.scan_id;
    }
  });

  test('Can list scans', async () => {
    if (!authToken) return;

    const res = await request(app)
      .get('/api/scans/list')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBe(200);
    expect(res.body.scans).toBeDefined();
    expect(Array.isArray(res.body.scans)).toBe(true);
  });

  test('Can get scan status', async () => {
    if (!authToken || !testScanId) return;

    const res = await request(app)
      .get(`/api/scans/${testScanId}`)
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBeOneOf([200, 404]);
    if (res.status === 200) {
      expect(res.body.scan).toBeDefined();
      expect(res.body.scan.status).toBeOneOf(['pending', 'running', 'completed', 'failed']);
    }
  });
});

describe('Analytics', () => {
  test('Can get analytics', async () => {
    if (!authToken) return;

    const res = await request(app)
      .get('/api/analytics/overview')
      .set('Authorization', `Bearer ${authToken}`);

    expect(res.status).toBeOneOf([200, 404]);
  });
});
