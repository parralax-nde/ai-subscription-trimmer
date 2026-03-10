/**
 * Integration tests for biometric authentication endpoints.
 *
 * Uses an in-memory SQLite database (via Prisma) isolated per test suite.
 * Uses real crypto key pairs for challenge-response verification.
 */

import crypto from 'crypto';
import request from 'supertest';
import { app } from '../src/app';
import prisma from '../src/config/database';

// Mock email sending so no real SMTP calls occur during tests
jest.mock('../src/config/email', () => ({
  default: {
    sendMail: jest.fn().mockResolvedValue({}),
  },
}));

// Helper to generate an RSA key pair for testing
function generateTestKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

// Helper to sign a challenge with a private key
function signChallenge(challenge: string, privateKey: string): string {
  const signer = crypto.createSign('SHA256');
  signer.update(challenge);
  signer.end();
  return signer.sign(privateKey, 'base64');
}

// Helper to register + verify a user and return their tokens
async function registerAndVerify(
  email: string,
  password: string,
): Promise<{ accessToken: string; refreshToken: string }> {
  await request(app).post('/api/auth/register').send({ email, password }).expect(202);

  const user = await prisma.user.findUniqueOrThrow({ where: { email } });
  const { token } = await prisma.emailVerificationToken.findFirstOrThrow({
    where: { userId: user.id },
  });

  await request(app).post('/api/auth/verify-email').send({ token }).expect(200);

  const loginRes = await request(app)
    .post('/api/auth/login')
    .send({ email, password })
    .expect(200);

  return loginRes.body as { accessToken: string; refreshToken: string };
}

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await prisma.$connect();
});

afterEach(async () => {
  await prisma.magicLinkToken.deleteMany();
  await prisma.mfaToken.deleteMany();
  await prisma.mfaBackupCode.deleteMany();
  await prisma.refreshToken.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.emailVerificationToken.deleteMany();
  await prisma.biometricCredential.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

// ---------------------------------------------------------------------------
// Register Biometric Credential
// ---------------------------------------------------------------------------

describe('POST /api/auth/biometric/register', () => {
  it('registers a biometric credential for an authenticated user', async () => {
    const { accessToken } = await registerAndVerify('bio@example.com', 'Secure@Pass1');
    const { publicKey } = generateTestKeyPair();

    const res = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'device-123', deviceName: 'iPhone 15' })
      .expect(201);

    expect(res.body.message).toMatch(/registered/i);
    expect(res.body).toHaveProperty('credentialId');
  });

  it('replaces credential for same user and device', async () => {
    const { accessToken } = await registerAndVerify('bio-replace@example.com', 'Secure@Pass1');
    const { publicKey: publicKey1 } = generateTestKeyPair();
    const { publicKey: publicKey2 } = generateTestKeyPair();

    const res1 = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey: publicKey1, deviceId: 'device-same' })
      .expect(201);

    const res2 = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey: publicKey2, deviceId: 'device-same' })
      .expect(201);

    // Different credential IDs
    expect(res2.body.credentialId).not.toBe(res1.body.credentialId);

    // Should only have one credential
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'bio-replace@example.com' } });
    const credentials = await prisma.biometricCredential.findMany({ where: { userId: user.id } });
    expect(credentials).toHaveLength(1);
  });

  it('requires authentication', async () => {
    const { publicKey } = generateTestKeyPair();

    await request(app)
      .post('/api/auth/biometric/register')
      .send({ publicKey, deviceId: 'device-123' })
      .expect(401);
  });

  it('rejects missing fields', async () => {
    const { accessToken } = await registerAndVerify('bio-missing@example.com', 'Secure@Pass1');

    await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({})
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// Biometric Challenge
// ---------------------------------------------------------------------------

describe('POST /api/auth/biometric/challenge', () => {
  it('generates a challenge for a valid credential', async () => {
    const { accessToken } = await registerAndVerify('challenge@example.com', 'Secure@Pass1');
    const { publicKey } = generateTestKeyPair();

    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'device-123' })
      .expect(201);

    const res = await request(app)
      .post('/api/auth/biometric/challenge')
      .send({ credentialId: registerRes.body.credentialId })
      .expect(200);

    expect(res.body).toHaveProperty('challenge');
    expect(typeof res.body.challenge).toBe('string');
  });

  it('returns 404 for an unknown credential', async () => {
    const res = await request(app)
      .post('/api/auth/biometric/challenge')
      .send({ credentialId: 'unknown-credential-id' })
      .expect(404);

    expect(res.body.error).toMatch(/not found/i);
  });

  it('rejects missing credential ID', async () => {
    await request(app)
      .post('/api/auth/biometric/challenge')
      .send({})
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// Biometric Verify
// ---------------------------------------------------------------------------

describe('POST /api/auth/biometric/verify', () => {
  it('returns tokens after valid biometric verification', async () => {
    const { accessToken } = await registerAndVerify('verify-bio@example.com', 'Secure@Pass1');
    const { publicKey, privateKey } = generateTestKeyPair();

    // Register credential
    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'device-123' })
      .expect(201);

    const credentialId = registerRes.body.credentialId;

    // Get challenge
    const challengeRes = await request(app)
      .post('/api/auth/biometric/challenge')
      .send({ credentialId })
      .expect(200);

    // Sign the challenge
    const signature = signChallenge(challengeRes.body.challenge, privateKey);

    // Verify
    const verifyRes = await request(app)
      .post('/api/auth/biometric/verify')
      .send({ credentialId, signature })
      .expect(200);

    expect(verifyRes.body).toHaveProperty('accessToken');
    expect(verifyRes.body).toHaveProperty('refreshToken');
  });

  it('returns 401 for an invalid signature', async () => {
    const { accessToken } = await registerAndVerify('bad-sig@example.com', 'Secure@Pass1');
    const { publicKey } = generateTestKeyPair();
    const { privateKey: wrongKey } = generateTestKeyPair(); // Different key pair

    // Register credential
    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'device-123' })
      .expect(201);

    const credentialId = registerRes.body.credentialId;

    // Get challenge
    const challengeRes = await request(app)
      .post('/api/auth/biometric/challenge')
      .send({ credentialId })
      .expect(200);

    // Sign with wrong key
    const signature = signChallenge(challengeRes.body.challenge, wrongKey);

    // Verify should fail
    const res = await request(app)
      .post('/api/auth/biometric/verify')
      .send({ credentialId, signature })
      .expect(401);

    expect(res.body.error).toMatch(/invalid/i);
  });

  it('returns 401 for expired challenge', async () => {
    const { accessToken } = await registerAndVerify('expired-bio@example.com', 'Secure@Pass1');
    const { publicKey, privateKey } = generateTestKeyPair();

    // Register credential
    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'device-123' })
      .expect(201);

    const credentialId = registerRes.body.credentialId;

    // Get challenge
    const challengeRes = await request(app)
      .post('/api/auth/biometric/challenge')
      .send({ credentialId })
      .expect(200);

    // Manually expire the challenge by manipulating the internal store
    const { _pendingChallenges } = await import('../src/services/biometricService');
    const entry = _pendingChallenges.get(credentialId);
    if (entry) {
      entry.expiresAt = Date.now() - 1000;
    }

    const signature = signChallenge(challengeRes.body.challenge, privateKey);

    const res = await request(app)
      .post('/api/auth/biometric/verify')
      .send({ credentialId, signature })
      .expect(401);

    expect(res.body.error).toMatch(/expired/i);
  });

  it('challenge is single-use', async () => {
    const { accessToken } = await registerAndVerify('single-use@example.com', 'Secure@Pass1');
    const { publicKey, privateKey } = generateTestKeyPair();

    // Register credential
    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'device-123' })
      .expect(201);

    const credentialId = registerRes.body.credentialId;

    // Get challenge
    const challengeRes = await request(app)
      .post('/api/auth/biometric/challenge')
      .send({ credentialId })
      .expect(200);

    const signature = signChallenge(challengeRes.body.challenge, privateKey);

    // First use — succeeds
    await request(app)
      .post('/api/auth/biometric/verify')
      .send({ credentialId, signature })
      .expect(200);

    // Second use — fails (challenge consumed)
    await request(app)
      .post('/api/auth/biometric/verify')
      .send({ credentialId, signature })
      .expect(401);
  });

  it('returns 404 for unknown credential', async () => {
    await request(app)
      .post('/api/auth/biometric/verify')
      .send({ credentialId: 'unknown-id', signature: 'fake-sig' })
      .expect(404);
  });
});

// ---------------------------------------------------------------------------
// List Biometric Credentials
// ---------------------------------------------------------------------------

describe('GET /api/auth/biometric/credentials', () => {
  it('lists credentials for the authenticated user', async () => {
    const { accessToken } = await registerAndVerify('list@example.com', 'Secure@Pass1');
    const { publicKey: pk1 } = generateTestKeyPair();
    const { publicKey: pk2 } = generateTestKeyPair();

    await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey: pk1, deviceId: 'device-1', deviceName: 'iPhone 15' })
      .expect(201);

    await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey: pk2, deviceId: 'device-2', deviceName: 'iPad Pro' })
      .expect(201);

    const res = await request(app)
      .get('/api/auth/biometric/credentials')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.credentials).toHaveLength(2);
    expect(res.body.credentials[0]).toHaveProperty('credentialId');
    expect(res.body.credentials[0]).toHaveProperty('deviceId');
    expect(res.body.credentials[0]).toHaveProperty('deviceName');
  });

  it('returns empty list when no credentials exist', async () => {
    const { accessToken } = await registerAndVerify('empty@example.com', 'Secure@Pass1');

    const res = await request(app)
      .get('/api/auth/biometric/credentials')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.credentials).toHaveLength(0);
  });

  it('requires authentication', async () => {
    await request(app)
      .get('/api/auth/biometric/credentials')
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// Remove Biometric Credential
// ---------------------------------------------------------------------------

describe('DELETE /api/auth/biometric/:credentialId', () => {
  it('removes a credential for the authenticated user', async () => {
    const { accessToken } = await registerAndVerify('remove@example.com', 'Secure@Pass1');
    const { publicKey } = generateTestKeyPair();

    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'device-123' })
      .expect(201);

    await request(app)
      .delete(`/api/auth/biometric/${registerRes.body.credentialId}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    // Verify it's gone
    const res = await request(app)
      .get('/api/auth/biometric/credentials')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.credentials).toHaveLength(0);
  });

  it('returns 404 for unknown credential', async () => {
    const { accessToken } = await registerAndVerify('remove-unknown@example.com', 'Secure@Pass1');

    await request(app)
      .delete('/api/auth/biometric/unknown-credential-id')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(404);
  });

  it('prevents removing another user\'s credential', async () => {
    const { accessToken: token1 } = await registerAndVerify('user1@example.com', 'Secure@Pass1');
    const { accessToken: token2 } = await registerAndVerify('user2@example.com', 'Secure@Pass1');
    const { publicKey } = generateTestKeyPair();

    // User 1 registers a credential
    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${token1}`)
      .send({ publicKey, deviceId: 'device-123' })
      .expect(201);

    // User 2 tries to delete it
    await request(app)
      .delete(`/api/auth/biometric/${registerRes.body.credentialId}`)
      .set('Authorization', `Bearer ${token2}`)
      .expect(404);
  });

  it('requires authentication', async () => {
    await request(app)
      .delete('/api/auth/biometric/some-credential-id')
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// Full Biometric Flow
// ---------------------------------------------------------------------------

describe('Full biometric authentication flow', () => {
  it('register → challenge → verify → refresh', async () => {
    const { accessToken } = await registerAndVerify('flow@example.com', 'Secure@Pass1');
    const { publicKey, privateKey } = generateTestKeyPair();

    // Step 1: Register biometric credential
    const registerRes = await request(app)
      .post('/api/auth/biometric/register')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ publicKey, deviceId: 'iphone-uuid', deviceName: 'My iPhone' })
      .expect(201);

    const credentialId = registerRes.body.credentialId;

    // Step 2: Request challenge
    const challengeRes = await request(app)
      .post('/api/auth/biometric/challenge')
      .send({ credentialId })
      .expect(200);

    // Step 3: Sign challenge with biometric-protected private key
    const signature = signChallenge(challengeRes.body.challenge, privateKey);

    // Step 4: Verify biometric
    const verifyRes = await request(app)
      .post('/api/auth/biometric/verify')
      .send({ credentialId, signature })
      .expect(200);

    expect(verifyRes.body).toHaveProperty('accessToken');
    expect(verifyRes.body).toHaveProperty('refreshToken');

    // Step 5: Verify refresh token works
    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: verifyRes.body.refreshToken })
      .expect(200);

    expect(refreshRes.body).toHaveProperty('accessToken');
    expect(refreshRes.body).toHaveProperty('refreshToken');
  });
});
