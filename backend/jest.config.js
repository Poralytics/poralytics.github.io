module.exports = {
  testEnvironment: 'node',
  testTimeout: 30000,
  detectOpenHandles: true,
  forceExit: true,
  testMatch: ['**/tests/**/*.test.js'],
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'scanners/**/*.js',
    'utils/**/*.js',
    'services/complete-scan-orchestrator.js',
    'services/real-stripe-billing.js',
    '!**/*.test.js'
  ],
  verbose: true
};
