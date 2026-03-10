// Set environment variables required for tests before any modules load.
// This must be a plain JS/TS file (not a jest setup file that runs after module init).

// Provide required JWT secrets so config/index.ts does not throw
process.env.JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'test-access-secret';
process.env.JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'test-refresh-secret';

// Use a separate SQLite file for tests
process.env.DATABASE_URL = process.env.DATABASE_URL || 'file:./test.db';

// Raise rate limits so that they do not interfere with test execution
process.env.AUTH_RATE_LIMIT_MAX_REQUESTS = '10000';
process.env.RATE_LIMIT_MAX_REQUESTS = '10000';
