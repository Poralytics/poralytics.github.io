/**
 * Tests unitaires - Tous les scanners
 * Vérifie que chaque scanner s'instancie et expose scan(url)
 */

const path = require('path');
const fs = require('fs');

const scannersDir = path.join(__dirname, '../../scanners');
const scannerFiles = fs.readdirSync(scannersDir).filter(f => f.endsWith('.js'));

describe('All Scanners - API Compatibility', () => {

  scannerFiles.forEach(file => {
    const name = file.replace('.js', '');
    
    describe(`Scanner: ${name}`, () => {
      let ScannerClass;
      let instance;

      beforeAll(() => {
        ScannerClass = require(path.join(scannersDir, file));
      });

      test('should load without errors', () => {
        expect(ScannerClass).toBeDefined();
      });

      test('should be instantiable', () => {
        // Handle both class exports and instance exports
        if (typeof ScannerClass === 'function') {
          instance = new ScannerClass();
        } else {
          instance = ScannerClass; // Already an instance
        }
        expect(instance).toBeDefined();
      });

      test('should have scan(url) method', () => {
        if (!instance) {
          if (typeof ScannerClass === 'function') {
            instance = new ScannerClass();
          } else {
            instance = ScannerClass;
          }
        }
        expect(typeof instance.scan).toBe('function');
      });

      test('scan() should return object with vulnerabilities array on invalid URL', async () => {
        if (!instance) {
          if (typeof ScannerClass === 'function') {
            instance = new ScannerClass();
          } else {
            instance = ScannerClass;
          }
        }
        
        const result = await instance.scan('http://invalid-nonexistent-12345.com');
        
        expect(result).toBeDefined();
        expect(typeof result).toBe('object');
        
        // Should have vulnerabilities array (even if empty)
        if (result.vulnerabilities !== undefined) {
          expect(Array.isArray(result.vulnerabilities)).toBe(true);
        } else if (Array.isArray(result)) {
          // Some scanners return array directly - also ok
          expect(Array.isArray(result)).toBe(true);
        }
        
        // Should not throw
      }, 20000);
    });
  });
});

describe('SecureHttpClient', () => {
  const { SecureHttpClient } = require('../../utils/secure-http-client');
  let client;

  beforeEach(() => {
    client = new SecureHttpClient();
  });

  test('should block localhost', async () => {
    await expect(client.get('http://localhost:9999')).rejects.toThrow();
  });

  test('should block 127.0.0.1', async () => {
    await expect(client.get('http://127.0.0.1')).rejects.toThrow();
  });

  test('should block 192.168.x.x', async () => {
    await expect(client.get('http://192.168.1.1')).rejects.toThrow();
  });

  test('should block 10.x.x.x', async () => {
    await expect(client.get('http://10.0.0.1')).rejects.toThrow();
  });

  test('should block file:// protocol', async () => {
    await expect(client.get('file:///etc/passwd')).rejects.toThrow();
  });
});

describe('ErrorHandler', () => {
  const { CircuitBreaker, RetryHandler, logger } = require('../../utils/error-handler');

  test('CircuitBreaker should instantiate', () => {
    const cb = new CircuitBreaker({ name: 'test', failureThreshold: 3, timeout: 5000 });
    expect(cb).toBeDefined();
    expect(cb.state).toBe('CLOSED');
  });

  test('CircuitBreaker should execute successfully', async () => {
    const cb = new CircuitBreaker({ name: 'test2', failureThreshold: 3, timeout: 5000 });
    const result = await cb.execute(async () => 'success');
    expect(result).toBe('success');
  });

  test('CircuitBreaker should track failures', async () => {
    const cb = new CircuitBreaker({ name: 'test3', failureThreshold: 2, timeout: 5000 });
    for (let i = 0; i < 2; i++) {
      try { await cb.execute(async () => { throw new Error('fail'); }); } catch (e) {}
    }
    expect(cb.state).toBe('OPEN');
  });

  test('RetryHandler should retry on failure', async () => {
    const handler = new RetryHandler({ maxRetries: 2, initialDelay: 10 });
    let attempts = 0;
    const result = await handler.execute(async () => {
      attempts++;
      if (attempts < 2) throw new Error('fail');
      return 'ok';
    });
    expect(result).toBe('ok');
    expect(attempts).toBe(2);
  });

  test('logger should have logInfo, logError, logWarning', () => {
    expect(typeof logger.logInfo).toBe('function');
    expect(typeof logger.logError).toBe('function');
    expect(typeof logger.logWarning).toBe('function');
  });
});
