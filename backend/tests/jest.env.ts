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

// OAuth credentials (stubbed — real calls are mocked in social auth tests)
process.env.GOOGLE_CLIENT_ID = 'test-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
process.env.GOOGLE_REDIRECT_URI = 'http://localhost:3000/api/auth/google/callback';

process.env.APPLE_CLIENT_ID = 'com.example.app';
process.env.APPLE_TEAM_ID = 'TEAMID1234';
process.env.APPLE_KEY_ID = 'KEYID12345';
// Minimal valid ES256 private key for tests (not used for real verification)
process.env.APPLE_PRIVATE_KEY = [
  '-----BEGIN EC PRIVATE KEY-----',
  'MHQCAQEEIOatheNNBpxDFMlP3bKGrZcUUOPDovWVvEXMKUXurZ2NoAoGCCqGSM49',
  'AwEHoWQDYgAEkuFv4spWAep3uyBMXxRPVdQy0pM8JhHbmrxCBEekEBp5TzLWv4S9',
  'iH4G1lsBRr+VLKO6XXWV+sHuHj0bGEUm',
  '-----END EC PRIVATE KEY-----',
].join('\n');
process.env.APPLE_REDIRECT_URI = 'http://localhost:3000/api/auth/apple/callback';
