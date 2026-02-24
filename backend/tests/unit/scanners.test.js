/**
 * Unit Tests - All Scanners
 * Tests scanner instantiation, API contract, and error handling
 */

const path = require('path');
const scannersDir = path.join(__dirname, '../../scanners');

// List of all scanners with expected behavior
const scannerFiles = [
  'real-sql-scanner.js',
  'real-xss-scanner.js',
  'ssrf-scanner.js',
  'xxe-scanner.js',
  'command-injection-scanner.js',
  'headers-scanner.js',
  'authentication-scanner.js',
  'csrf-scanner.js',
  'cors-scanner.js',
  'ssl-scanner.js',
  'info-disclosure-scanner.js',
  'clickjacking-scanner.js',
  'open-redirect-scanner.js',
  'crypto-scanner.js',
  'access-control-scanner.js',
  'component-scanner.js',
  'api-security-scanner.js',
  'infrastructure-scanner.js',
  'business-logic-scanner.js',
  'file-upload-scanner.js',
  'advanced-sql-scanner.js',
  'sql-injection-scanner.js',
  'xss-scanner.js'
];

describe('All Scanners - API Contract', () => {
  for (const scannerFile of scannerFiles) {
    describe(`Scanner: ${scannerFile}`, () => {
      let ScannerClass;
      let scanner;

      beforeAll(() => {
        const exported = require(path.join(scannersDir, scannerFile));
        // Handle both instance exports and class exports
        if (typeof exported === 'object' && exported !== null && typeof exported.scan === 'function') {
          scanner = exported;
          ScannerClass = null;
        } else if (typeof exported === 'function') {
          ScannerClass = exported;
          scanner = new ScannerClass();
        } else {
          throw new Error(`${scannerFile}: unexpected export type`);
        }
      });

      test('has a scan(url) method', () => {
        expect(typeof scanner.scan).toBe('function');
      });

      test('has httpClient property', () => {
        expect(scanner.httpClient).toBeDefined();
      });

      test('scan() returns correct structure on invalid URL', async () => {
        const result = await scanner.scan('http://this-domain-does-not-exist-nexus-test.invalid');
        expect(result).toBeDefined();
        expect(typeof result).toBe('object');
        expect(Array.isArray(result.vulnerabilities)).toBe(true);
        expect(Array.isArray(result.errors)).toBe(true);
      }, 20000);

      test('scan() does not throw on unreachable target', async () => {
        await expect(
          scanner.scan('http://this-domain-does-not-exist-nexus-test.invalid')
        ).resolves.toBeDefined();
      }, 20000);

      test('vulnerabilities have required fields', async () => {
        // Use a real test target if available, otherwise check structure
        const result = await scanner.scan('http://this-domain-does-not-exist-nexus-test.invalid');
        for (const vuln of result.vulnerabilities) {
          expect(vuln).toHaveProperty('severity');
          expect(vuln).toHaveProperty('category');
          expect(vuln).toHaveProperty('title');
          expect(vuln).toHaveProperty('cvss_score');
          expect(['critical', 'high', 'medium', 'low', 'info']).toContain(vuln.severity);
        }
      }, 20000);
    });
  }
});

describe('SecureHttpClient SSRF Protection', () => {
  const { SecureHttpClient } = require('../../utils/secure-http-client');

  test('blocks localhost', async () => {
    const client = new SecureHttpClient();
    await expect(client.get('http://localhost')).rejects.toThrow();
  });

  test('blocks 127.0.0.1', async () => {
    const client = new SecureHttpClient();
    await expect(client.get('http://127.0.0.1')).rejects.toThrow();
  });

  test('blocks 192.168.1.1', async () => {
    const client = new SecureHttpClient();
    await expect(client.get('http://192.168.1.1')).rejects.toThrow();
  });

  test('blocks 10.0.0.1', async () => {
    const client = new SecureHttpClient();
    await expect(client.get('http://10.0.0.1')).rejects.toThrow();
  });

  test('blocks file:// protocol', async () => {
    const client = new SecureHttpClient();
    await expect(client.get('file:///etc/passwd')).rejects.toThrow();
  });
});
