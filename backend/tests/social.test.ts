/**
 * Integration tests for Google OAuth and Apple Sign-In endpoints.
 *
 * External HTTP calls (to Google and Apple) are mocked via jest.mock so that
 * no real network requests are made during test execution.  The tests exercise
 * the full HTTP layer (route → service → database) using supertest.
 */

import crypto from 'crypto';
import request from 'supertest';
import jwt from 'jsonwebtoken';
import { app } from '../src/app';
import prisma from '../src/config/database';
import { generateOAuthState, findOrCreateSocialUser } from '../src/services/socialAuthService';

// ---------------------------------------------------------------------------
// Mock the HTTP client module BEFORE the service loads so that all calls made
// by the social auth service go through the mocks.
// ---------------------------------------------------------------------------
jest.mock('../src/utils/httpClient');
import { httpPost, httpGet } from '../src/utils/httpClient';

const mockHttpPost = httpPost as jest.MockedFunction<typeof httpPost>;
const mockHttpGet = httpGet as jest.MockedFunction<typeof httpGet>;

// ---------------------------------------------------------------------------
// Shared RSA key pair for Apple identity token tests.
//
// All Apple tests sign their identity tokens with the same key pair so that
// the module-level JWKS cache stays consistent once it is populated by the
// first Apple test that triggers a httpGet('...auth/keys') call.
// ---------------------------------------------------------------------------
const { privateKey: appleTestPrivateKey, publicKey: appleTestPublicKey } =
  crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

const appleTestJwk = appleTestPublicKey.export({ format: 'jwk' });
const appleJwksResponse = {
  keys: [{ ...appleTestJwk, kid: 'test-key-id', use: 'sig', alg: 'RS256' }],
};

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await prisma.$connect();
});

afterEach(async () => {
  // resetAllMocks clears call history AND drains any un-consumed mockResolvedValueOnce
  // queues, preventing stale return values from leaking between tests.
  jest.resetAllMocks();
  await prisma.refreshToken.deleteMany();
  await prisma.emailVerificationToken.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.mfaBackupCode.deleteMany();
  await prisma.mfaToken.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Generate a valid OAuth state token using the real implementation. */
function validState(): string {
  return generateOAuthState();
}

/** Expired state JWT for testing. */
function expiredState(): string {
  // Set exp to 10 seconds in the past to ensure the token is definitively expired
  return jwt.sign(
    { nonce: 'old', exp: Math.floor(Date.now() / 1000) - 10 },
    process.env.JWT_ACCESS_SECRET!,
  );
}

/**
 * Set up httpPost and httpGet mocks for the Google flow.
 * httpPost → Google token exchange response
 * httpGet  → Google userinfo response
 */
function setupGoogleMocks(overrides: Partial<{ sub: string; email: string; email_verified: boolean }> = {}) {
  mockHttpPost.mockResolvedValueOnce({ access_token: 'ga_token', id_token: 'gi_token' });
  mockHttpGet.mockResolvedValueOnce({
    sub: 'google-uid-123',
    email: 'google@example.com',
    email_verified: true,
    ...overrides,
  });
}

/**
 * Build an Apple identity token signed with the shared test key pair.
 * httpPost → Apple token exchange (returns the same idToken)
 * httpGet  → Apple JWKS (returns the shared public key)
 *
 * Only the first Apple test that triggers a JWKS fetch needs httpGet mocked;
 * subsequent tests hit the in-memory cache.  We always set it up to be safe —
 * unused mocks are cleared by resetAllMocks() in afterEach.
 */
function buildAppleScenario(sub: string, email?: string): { idToken: string } {
  const idToken = jwt.sign(
    { sub, ...(email ? { email } : {}), email_verified: true },
    appleTestPrivateKey,
    {
      algorithm: 'RS256',
      keyid: 'test-key-id',
      issuer: 'https://appleid.apple.com',
      audience: 'com.example.app',
      expiresIn: '5m',
    },
  );

  // Code exchange
  mockHttpPost.mockResolvedValueOnce({ id_token: idToken });
  // JWKS (may be served from cache after first Apple test, but set it up anyway)
  mockHttpGet.mockResolvedValueOnce(appleJwksResponse);

  return { idToken };
}

// ---------------------------------------------------------------------------
// GET /api/auth/google — initiate Google OAuth
// ---------------------------------------------------------------------------

describe('GET /api/auth/google', () => {
  it('returns a Google authorization URL', async () => {
    const res = await request(app).get('/api/auth/google').expect(200);
    expect(res.body).toHaveProperty('url');
    expect(res.body.url).toContain('accounts.google.com');
    expect(res.body.url).toContain('state=');
    expect(res.body.url).toContain('response_type=code');
    expect(res.body.url).toContain('scope=openid');
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/google/callback — handle Google redirect
// ---------------------------------------------------------------------------

describe('GET /api/auth/google/callback', () => {
  it('redirects to frontend with tokens for a new user', async () => {
    setupGoogleMocks();

    const state = validState();
    const res = await request(app)
      .get(`/api/auth/google/callback?code=auth_code&state=${encodeURIComponent(state)}`)
      .expect(302);

    expect(res.headers.location).toContain('/auth/callback#');
    expect(res.headers.location).toContain('accessToken=');
    expect(res.headers.location).toContain('refreshToken=');

    // Verify a user was created in the DB
    const user = await prisma.user.findUnique({ where: { email: 'google@example.com' } });
    expect(user).not.toBeNull();
    expect(user?.googleId).toBe('google-uid-123');
    expect(user?.isEmailVerified).toBe(true);
    expect(user?.passwordHash).toBeNull();
  });

  it('links Google ID to an existing email/password account', async () => {
    // Pre-create a user with the same email
    await prisma.user.create({
      data: {
        email: 'google@example.com',
        passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy',
        isEmailVerified: true,
      },
    });

    setupGoogleMocks();

    const state = validState();
    await request(app)
      .get(`/api/auth/google/callback?code=auth_code&state=${encodeURIComponent(state)}`)
      .expect(302);

    const user = await prisma.user.findUnique({ where: { email: 'google@example.com' } });
    expect(user?.googleId).toBe('google-uid-123');
    // Original passwordHash should be preserved
    expect(user?.passwordHash).not.toBeNull();
  });

  it('returns the same user on repeated sign-ins (idempotent)', async () => {
    setupGoogleMocks();
    const state1 = validState();
    await request(app)
      .get(`/api/auth/google/callback?code=auth_code&state=${encodeURIComponent(state1)}`)
      .expect(302);

    setupGoogleMocks();
    const state2 = validState();
    await request(app)
      .get(`/api/auth/google/callback?code=auth_code&state=${encodeURIComponent(state2)}`)
      .expect(302);

    const users = await prisma.user.findMany({ where: { googleId: 'google-uid-123' } });
    expect(users).toHaveLength(1);
  });

  it('redirects with error=access_denied when the user denies access', async () => {
    const state = validState();
    const res = await request(app)
      .get(`/api/auth/google/callback?error=access_denied&state=${encodeURIComponent(state)}`)
      .expect(302);

    expect(res.headers.location).toContain('error=access_denied');
    expect(res.headers.location).not.toContain('accessToken=');
  });

  it('redirects with error=invalid_state for a tampered state', async () => {
    const res = await request(app)
      .get('/api/auth/google/callback?code=auth_code&state=tampered-state-value')
      .expect(302);

    expect(res.headers.location).toContain('error=invalid_state');
  });

  it('redirects with error=invalid_state for a missing state', async () => {
    const res = await request(app)
      .get('/api/auth/google/callback?code=auth_code')
      .expect(302);

    expect(res.headers.location).toContain('error=invalid_state');
  });

  it('redirects with error=invalid_state for an expired state', async () => {
    const res = await request(app)
      .get(`/api/auth/google/callback?code=auth_code&state=${encodeURIComponent(expiredState())}`)
      .expect(302);

    expect(res.headers.location).toContain('error=invalid_state');
  });

  it('redirects with error=server_error when the code exchange fails', async () => {
    mockHttpPost.mockRejectedValueOnce(new Error('network error'));

    const state = validState();
    const res = await request(app)
      .get(`/api/auth/google/callback?code=bad_code&state=${encodeURIComponent(state)}`)
      .expect(302);

    expect(res.headers.location).toContain('error=server_error');
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/apple — initiate Apple Sign-In
// ---------------------------------------------------------------------------

describe('GET /api/auth/apple', () => {
  it('returns an Apple Sign-In authorization URL', async () => {
    const res = await request(app).get('/api/auth/apple').expect(200);
    expect(res.body).toHaveProperty('url');
    expect(res.body.url).toContain('appleid.apple.com');
    expect(res.body.url).toContain('state=');
    expect(res.body.url).toContain('response_mode=form_post');
  });
});

// ---------------------------------------------------------------------------
// POST /api/auth/apple/callback — handle Apple POST callback
// ---------------------------------------------------------------------------

describe('POST /api/auth/apple/callback', () => {
  it('redirects to frontend with tokens for a new user', async () => {
    const { idToken } = buildAppleScenario('apple-uid-456', 'apple@example.com');

    const state = validState();
    const res = await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: idToken, state })
      .expect(302);

    expect(res.headers.location).toContain('/auth/callback#');
    expect(res.headers.location).toContain('accessToken=');
    expect(res.headers.location).toContain('refreshToken=');

    const user = await prisma.user.findUnique({ where: { email: 'apple@example.com' } });
    expect(user).not.toBeNull();
    expect(user?.appleId).toBe('apple-uid-456');
    expect(user?.isEmailVerified).toBe(true);
    expect(user?.passwordHash).toBeNull();
  });

  it('links Apple ID to an existing email/password account', async () => {
    await prisma.user.create({
      data: {
        email: 'apple@example.com',
        passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy',
        isEmailVerified: true,
      },
    });

    const { idToken } = buildAppleScenario('apple-uid-456', 'apple@example.com');

    const state = validState();
    await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: idToken, state })
      .expect(302);

    const user = await prisma.user.findUnique({ where: { email: 'apple@example.com' } });
    expect(user?.appleId).toBe('apple-uid-456');
    expect(user?.passwordHash).not.toBeNull();
  });

  it('links Apple ID to an existing Google account for the same email', async () => {
    await prisma.user.create({
      data: {
        email: 'apple@example.com',
        googleId: 'google-uid-existing',
        isEmailVerified: true,
      },
    });

    const { idToken } = buildAppleScenario('apple-uid-456', 'apple@example.com');

    const state = validState();
    await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: idToken, state })
      .expect(302);

    const user = await prisma.user.findUnique({ where: { email: 'apple@example.com' } });
    expect(user?.appleId).toBe('apple-uid-456');
    expect(user?.googleId).toBe('google-uid-existing');
  });

  it('creates a user even when no email is in the identity token', async () => {
    const { idToken } = buildAppleScenario('apple-uid-noemail');

    const state = validState();
    const res = await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: idToken, state })
      .expect(302);

    expect(res.headers.location).toContain('accessToken=');
    const user = await prisma.user.findFirst({ where: { appleId: 'apple-uid-noemail' } });
    expect(user).not.toBeNull();
  });

  it('returns the same user on repeated Apple sign-ins', async () => {
    // First sign-in
    const { idToken: idToken1 } = buildAppleScenario('apple-uid-456', 'apple@example.com');
    const state1 = validState();
    await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: idToken1, state: state1 })
      .expect(302);

    // Second sign-in
    const { idToken: idToken2 } = buildAppleScenario('apple-uid-456', 'apple@example.com');
    const state2 = validState();
    await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: idToken2, state: state2 })
      .expect(302);

    const users = await prisma.user.findMany({ where: { appleId: 'apple-uid-456' } });
    expect(users).toHaveLength(1);
  });

  it('redirects with error=access_denied when fields are missing', async () => {
    const state = validState();
    const res = await request(app)
      .post('/api/auth/apple/callback')
      .send({ state }) // missing code and id_token
      .expect(302);

    expect(res.headers.location).toContain('error=access_denied');
  });

  it('redirects with error=invalid_state for a tampered state', async () => {
    const res = await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: 'some_token', state: 'tampered' })
      .expect(302);

    expect(res.headers.location).toContain('error=invalid_state');
  });

  it('redirects with error=server_error when identity token verification fails', async () => {
    // The service will try to decode the invalid JWT and fail
    const state = validState();
    const res = await request(app)
      .post('/api/auth/apple/callback')
      .send({ code: 'apple_auth_code', id_token: 'not.a.valid.jwt', state })
      .expect(302);

    expect(res.headers.location).toContain('error=server_error');
  });
});

// ---------------------------------------------------------------------------
// findOrCreateSocialUser — unit tests for account linking logic
// ---------------------------------------------------------------------------

describe('findOrCreateSocialUser', () => {
  it('creates a new Google user', async () => {
    const userId = await findOrCreateSocialUser({
      provider: 'google',
      providerId: 'gid-new',
      email: 'new@example.com',
      emailVerified: true,
    });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user).not.toBeNull();
    expect(user?.googleId).toBe('gid-new');
    expect(user?.email).toBe('new@example.com');
    expect(user?.isEmailVerified).toBe(true);
    expect(user?.passwordHash).toBeNull();
  });

  it('creates a new Apple user', async () => {
    const userId = await findOrCreateSocialUser({
      provider: 'apple',
      providerId: 'aid-new',
      email: 'apple-new@example.com',
      emailVerified: true,
    });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user?.appleId).toBe('aid-new');
    expect(user?.isEmailVerified).toBe(true);
  });

  it('returns the existing user ID on second sign-in with same provider ID', async () => {
    const id1 = await findOrCreateSocialUser({
      provider: 'google',
      providerId: 'gid-repeat',
      email: 'repeat@example.com',
      emailVerified: true,
    });

    const id2 = await findOrCreateSocialUser({
      provider: 'google',
      providerId: 'gid-repeat',
      email: 'repeat@example.com',
      emailVerified: true,
    });

    expect(id1).toBe(id2);
  });

  it('links provider to existing email/password user', async () => {
    const existing = await prisma.user.create({
      data: {
        email: 'existing@example.com',
        passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy',
        isEmailVerified: true,
      },
    });

    const userId = await findOrCreateSocialUser({
      provider: 'google',
      providerId: 'gid-link',
      email: 'existing@example.com',
      emailVerified: true,
    });

    expect(userId).toBe(existing.id);

    const user = await prisma.user.findUnique({ where: { id: existing.id } });
    expect(user?.googleId).toBe('gid-link');
    expect(user?.passwordHash).not.toBeNull(); // password preserved
  });

  it('upgrades isEmailVerified on linking when provider confirms email', async () => {
    const existing = await prisma.user.create({
      data: {
        email: 'unverified-link@example.com',
        passwordHash: '$argon2id$v=19$m=65536,t=3,p=4$dummy$dummy',
        isEmailVerified: false,
      },
    });

    await findOrCreateSocialUser({
      provider: 'google',
      providerId: 'gid-upgrade',
      email: 'unverified-link@example.com',
      emailVerified: true,
    });

    const user = await prisma.user.findUnique({ where: { id: existing.id } });
    expect(user?.isEmailVerified).toBe(true);
  });

  it('links Apple to an existing Google-linked user', async () => {
    const existing = await prisma.user.create({
      data: {
        email: 'dual@example.com',
        googleId: 'gid-dual',
        isEmailVerified: true,
      },
    });

    const userId = await findOrCreateSocialUser({
      provider: 'apple',
      providerId: 'aid-dual',
      email: 'dual@example.com',
      emailVerified: true,
    });

    expect(userId).toBe(existing.id);

    const user = await prisma.user.findUnique({ where: { id: existing.id } });
    expect(user?.googleId).toBe('gid-dual');
    expect(user?.appleId).toBe('aid-dual');
  });

  it('creates a user with a placeholder email when no email is provided', async () => {
    const userId = await findOrCreateSocialUser({
      provider: 'apple',
      providerId: 'aid-noemail',
      email: null,
      emailVerified: false,
    });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user?.email).toMatch(/apple\.aid-noemail@social\.invalid/);
  });
});

// ---------------------------------------------------------------------------
// Cross-feature: social tokens work with existing auth endpoints
// ---------------------------------------------------------------------------

describe('Social login tokens work with existing auth endpoints', () => {
  it('access token from Google login can be refreshed', async () => {
    setupGoogleMocks();
    const state = validState();
    const loginRes = await request(app)
      .get(`/api/auth/google/callback?code=auth_code&state=${encodeURIComponent(state)}`)
      .expect(302);

    // Extract refreshToken from redirect location hash
    const location = loginRes.headers.location as string;
    const hash = new URL(location.replace('#', '?'), 'http://localhost').searchParams;
    const refreshToken = hash.get('refreshToken')!;
    expect(refreshToken).toBeTruthy();

    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken })
      .expect(200);

    expect(refreshRes.body).toHaveProperty('accessToken');
    expect(refreshRes.body).toHaveProperty('refreshToken');
  });

  it('social-only user cannot log in with a password', async () => {
    // Create a social-only user directly (no passwordHash)
    await prisma.user.create({
      data: {
        email: 'social-only@example.com',
        googleId: 'google-uid-socialonly',
        isEmailVerified: true,
      },
    });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'social-only@example.com', password: 'AnyPass@1' })
      .expect(401);

    expect(res.body.error).toMatch(/invalid email or password/i);
  });
});
