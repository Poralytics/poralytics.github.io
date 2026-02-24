/**
 * Unit Tests - Error Handler & Circuit Breaker
 */
const { CircuitBreaker, RetryHandler, ErrorLogger } = require('../../utils/error-handler');

describe('CircuitBreaker', () => {
  let breaker;

  beforeEach(() => {
    breaker = new CircuitBreaker({
      name: 'test-breaker',
      failureThreshold: 3,
      timeout: 1000,
      successThreshold: 2
    });
  });

  test('starts in CLOSED state', () => {
    expect(breaker.state).toBe('CLOSED');
  });

  test('opens after failure threshold', async () => {
    const failing = async () => { throw new Error('fail'); };
    for (let i = 0; i < 3; i++) {
      try { await breaker.execute(failing); } catch (e) {}
    }
    expect(breaker.state).toBe('OPEN');
  });

  test('throws when OPEN', async () => {
    const failing = async () => { throw new Error('fail'); };
    for (let i = 0; i < 3; i++) {
      try { await breaker.execute(failing); } catch (e) {}
    }
    await expect(breaker.execute(async () => 'ok')).rejects.toThrow();
  });

  test('executes successfully in CLOSED state', async () => {
    const result = await breaker.execute(async () => 'success');
    expect(result).toBe('success');
  });

  test('uses fallback when OPEN', async () => {
    const failing = async () => { throw new Error('fail'); };
    const fallback = async () => 'fallback_value';
    for (let i = 0; i < 3; i++) {
      try { await breaker.execute(failing); } catch (e) {}
    }
    breaker.fallback = fallback;
    // When open and fallback set, should use fallback
    const stats = breaker.getStats();
    expect(stats.state).toBe('OPEN');
    expect(stats.totalFailures).toBe(3);
  });

  test('getStats returns correct structure', () => {
    const stats = breaker.getStats();
    expect(stats).toHaveProperty('name');
    expect(stats).toHaveProperty('state');
    expect(stats).toHaveProperty('totalCalls');
    expect(stats).toHaveProperty('totalFailures');
  });
});

describe('RetryHandler', () => {
  let retrier;

  beforeEach(() => {
    retrier = new RetryHandler({ maxRetries: 3, initialDelay: 10, maxDelay: 100 });
  });

  test('succeeds on first try', async () => {
    const result = await retrier.execute(async () => 'ok');
    expect(result).toBe('ok');
  });

  test('retries on failure and succeeds', async () => {
    let attempts = 0;
    const result = await retrier.execute(async () => {
      attempts++;
      if (attempts < 3) throw new Error('temporary');
      return 'success';
    });
    expect(result).toBe('success');
    expect(attempts).toBe(3);
  });

  test('throws after max retries', async () => {
    let attempts = 0;
    await expect(retrier.execute(async () => {
      attempts++;
      throw new Error('persistent');
    })).rejects.toThrow('persistent');
    expect(attempts).toBe(4); // initial + 3 retries
  });

  test('does not retry on 404 errors', async () => {
    let attempts = 0;
    const err = new Error('Not found');
    err.response = { status: 404 };
    await expect(retrier.execute(async () => {
      attempts++;
      throw err;
    })).rejects.toThrow();
    expect(attempts).toBe(1);
  });
});

describe('ErrorLogger', () => {
  let logger;
  const consoleSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

  beforeEach(() => {
    logger = new ErrorLogger({ service: 'test', environment: 'test' });
  });

  afterAll(() => {
    consoleSpy.mockRestore();
    errorSpy.mockRestore();
  });

  test('logInfo outputs JSON', () => {
    logger.logInfo('test message', { key: 'value' });
    expect(consoleSpy).toHaveBeenCalled();
    const call = consoleSpy.mock.calls[consoleSpy.mock.calls.length - 1][0];
    const parsed = JSON.parse(call);
    expect(parsed.level).toBe('info');
    expect(parsed.message).toBe('test message');
  });

  test('logError outputs JSON with stack', () => {
    const err = new Error('test error');
    logger.logError(err, { context: 'test' });
    expect(errorSpy).toHaveBeenCalled();
    const call = errorSpy.mock.calls[errorSpy.mock.calls.length - 1][0];
    const parsed = JSON.parse(call);
    expect(parsed.level).toBe('error');
    expect(parsed.stack).toBeDefined();
  });

  test('logWarning outputs warning level', () => {
    logger.logWarning('warning message');
    const call = consoleSpy.mock.calls[consoleSpy.mock.calls.length - 1][0];
    const parsed = JSON.parse(call);
    expect(parsed.level).toBe('warn');
  });
});
