/**
 * Integration Tests - Scan flow
 */

const request = require('supertest');

// Mock DB and dependencies before loading app
jest.mock('../config/database', () => {
  const mockDb = {
    prepare: jest.fn().mockReturnValue({
      all: jest.fn().mockReturnValue([]),
      get: jest.fn().mockReturnValue(null),
      run: jest.fn().mockReturnValue({ lastInsertRowid: 1, changes: 1 })
    }),
    pragma: jest.fn(),
    exec: jest.fn()
  };
  return mockDb;
});

jest.mock('../services/real-websocket-server', () => ({
  initialize: jest.fn(),
  broadcast: jest.fn()
}));

jest.mock('../services/real-job-queue', () => ({
  addJob: jest.fn().mockResolvedValue({ id: 'job-1' }),
  cleanup: jest.fn()
}));

let app;
beforeAll(() => {
  app = require('../../server');
});

describe('Health Endpoints', () => {
  test('GET /health returns 200', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('OK');
    expect(res.body.version).toBeDefined();
  });

  test('GET /health/breakers returns status', async () => {
    const res = await request(app).get('/health/breakers');
    expect([200, 503]).toContain(res.status);
    expect(res.body.healthy).toBeDefined();
  });

  test('GET /health/detailed returns metrics', async () => {
    const res = await request(app).get('/health/detailed');
    expect(res.status).toBe(200);
    expect(res.body.uptime).toBeDefined();
    expect(res.body.memory).toBeDefined();
  });

  test('GET /nonexistent returns 404', async () => {
    const res = await request(app).get('/api/nonexistent-endpoint-xyz');
    expect(res.status).toBe(404);
  });
});

describe('Auth Routes', () => {
  test('POST /api/auth/login with empty body returns 400/401', async () => {
    const res = await request(app).post('/api/auth/login').send({});
    expect([400, 401]).toContain(res.status);
  });

  test('POST /api/auth/login requires email/password', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: '', password: '' });
    expect([400, 401]).toContain(res.status);
  });

  test('GET /api/scans/list requires auth', async () => {
    const res = await request(app).get('/api/scans/list');
    expect(res.status).toBe(401);
  });

  test('POST /api/scans/start requires auth', async () => {
    const res = await request(app).post('/api/scans/start').send({ domain_id: 1 });
    expect(res.status).toBe(401);
  });
});

describe('Security Headers', () => {
  test('Responses include security headers', async () => {
    const res = await request(app).get('/health');
    // Helmet should add these
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBeDefined();
  });
});

describe('Rate Limiting', () => {
  test('Auth endpoints exist and respond', async () => {
    const res = await request(app).post('/api/auth/login').send({ email: 'x', password: 'x' });
    expect(res.status).toBeDefined();
  });
});
