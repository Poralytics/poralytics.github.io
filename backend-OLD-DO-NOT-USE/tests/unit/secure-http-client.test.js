/**
 * Unit Tests - SecureHttpClient
 * Tests real security protections
 */

const { SecureHttpClient } = require('../../utils/secure-http-client');

describe('SecureHttpClient - SSRF Protection', () => {
  let client;
  beforeEach(() => { client = new SecureHttpClient({ timeout: 5000 }); });

  test('blocks localhost by hostname', async () => {
    await expect(client.get('http://localhost:8080')).rejects.toThrow();
  });

  test('blocks 127.0.0.1', async () => {
    await expect(client.get('http://127.0.0.1')).rejects.toThrow();
  });

  test('blocks 192.168.x.x (private)', async () => {
    await expect(client.get('http://192.168.1.1')).rejects.toThrow();
  });

  test('blocks 10.x.x.x (private)', async () => {
    await expect(client.get('http://10.0.0.1')).rejects.toThrow();
  });

  test('blocks 172.16.x.x (private)', async () => {
    await expect(client.get('http://172.16.0.1')).rejects.toThrow();
  });

  test('blocks file:// protocol', async () => {
    await expect(client.get('file:///etc/passwd')).rejects.toThrow(/Protocol not allowed/);
  });

  test('blocks ftp:// protocol', async () => {
    await expect(client.get('ftp://example.com')).rejects.toThrow(/Protocol not allowed/);
  });

  test('allows https:// to public host', async () => {
    const res = await client.get('https://httpbin.org/status/200');
    expect(res.status).toBe(200);
  }, 10000);
});

describe('SecureHttpClient - URL Validation', () => {
  let client;
  beforeEach(() => { client = new SecureHttpClient(); });

  test('throws on invalid URL', async () => {
    await expect(client.get('not-a-url')).rejects.toThrow();
  });

  test('throws on empty URL', async () => {
    await expect(client.get('')).rejects.toThrow();
  });
});

describe('SecureHttpClient - isReachable', () => {
  let client;
  beforeEach(() => { client = new SecureHttpClient({ timeout: 5000 }); });

  test('returns false for unreachable private host', async () => {
    const result = await client.isReachable('http://192.168.99.99');
    expect(result).toBe(false);
  });

  test('returns true for reachable public host', async () => {
    const result = await client.isReachable('https://httpbin.org/status/200');
    expect(result).toBe(true);
  }, 10000);
});
