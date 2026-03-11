/**
 * Integration tests for magic link authentication endpoints.
 *
 * Uses an in-memory SQLite database (via Prisma) isolated per test suite.
 * Email sending is mocked — no real emails are sent.
 */

import request from 'supertest';
import { app } from '../src/app';
import prisma from '../src/config/database';

// Mock email sending so no real SMTP calls occur during tests
jest.mock('../src/config/email', () => ({
  default: {
    sendMail: jest.fn().mockResolvedValue({}),
  },
}));

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
  await prisma.securityLog.deleteMany();
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
// Send Magic Link
// ---------------------------------------------------------------------------

describe('POST /api/auth/magic-link/send', () => {
  it('returns 202 with generic message for a new email', async () => {
    const res = await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'newuser@example.com' })
      .expect(202);

    expect(res.body.message).toMatch(/sign-in link/i);

    // A user and magic link token should have been created
    const user = await prisma.user.findUnique({ where: { email: 'newuser@example.com' } });
    expect(user).not.toBeNull();

    const tokens = await prisma.magicLinkToken.findMany({ where: { userId: user!.id } });
    expect(tokens).toHaveLength(1);
  });

  it('returns 202 for an existing user', async () => {
    await registerAndVerify('existing@example.com', 'Secure@Pass1');

    const res = await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'existing@example.com' })
      .expect(202);

    expect(res.body.message).toMatch(/sign-in link/i);
  });

  it('normalises email to lowercase', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'User@EXAMPLE.com' })
      .expect(202);

    const user = await prisma.user.findUnique({ where: { email: 'user@example.com' } });
    expect(user).not.toBeNull();
  });

  it('invalidates previous magic link tokens', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'multi@example.com' })
      .expect(202);

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'multi@example.com' } });
    const firstTokens = await prisma.magicLinkToken.findMany({ where: { userId: user.id } });
    expect(firstTokens).toHaveLength(1);

    // Send another magic link
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'multi@example.com' })
      .expect(202);

    // Old token should be deleted, new one created
    const allTokens = await prisma.magicLinkToken.findMany({ where: { userId: user.id } });
    expect(allTokens).toHaveLength(1);
    expect(allTokens[0].token).not.toBe(firstTokens[0].token);
  });

  it('rejects invalid email format', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'not-an-email' })
      .expect(400);
  });

  it('rejects missing email', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({})
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// Verify Magic Link
// ---------------------------------------------------------------------------

describe('POST /api/auth/magic-link/verify', () => {
  it('returns access and refresh tokens for a valid magic link', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'magic@example.com' });

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'magic@example.com' } });
    const { token } = await prisma.magicLinkToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    const res = await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token })
      .expect(200);

    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
  });

  it('auto-verifies email on first magic link login', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'unverified-magic@example.com' });

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'unverified-magic@example.com' } });
    expect(user.isEmailVerified).toBe(false);

    const { token } = await prisma.magicLinkToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token })
      .expect(200);

    const updatedUser = await prisma.user.findUniqueOrThrow({ where: { email: 'unverified-magic@example.com' } });
    expect(updatedUser.isEmailVerified).toBe(true);
  });

  it('returns 400 for an invalid token', async () => {
    const res = await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token: 'invalid-token-xxx' })
      .expect(400);

    expect(res.body.error).toMatch(/invalid or expired/i);
  });

  it('returns 400 for an expired token', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'expired-magic@example.com' });

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'expired-magic@example.com' } });

    // Artificially expire the token
    await prisma.magicLinkToken.updateMany({
      where: { userId: user.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const { token } = await prisma.magicLinkToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token })
      .expect(400);
  });

  it('returns 400 when reusing a magic link token', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'reuse-magic@example.com' });

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'reuse-magic@example.com' } });
    const { token } = await prisma.magicLinkToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    // First use — succeeds
    await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token })
      .expect(200);

    // Second use — should fail
    await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token })
      .expect(400);
  });

  it('rejects missing token', async () => {
    await request(app)
      .post('/api/auth/magic-link/verify')
      .send({})
      .expect(400);
  });

  it('returns MFA challenge for a user with MFA enabled', async () => {
    const { authenticator } = await import('@otplib/preset-default');

    // Register a user with password and enable MFA
    const { accessToken } = await registerAndVerify('mfa-magic@example.com', 'Secure@Pass1');

    // Setup TOTP
    const setupRes = await request(app)
      .post('/api/auth/mfa/totp/setup')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const totpCode = authenticator.generate(setupRes.body.secret);

    // Enable MFA
    await request(app)
      .post('/api/auth/mfa/totp/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totpCode })
      .expect(200);

    // Send magic link
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'mfa-magic@example.com' })
      .expect(202);

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'mfa-magic@example.com' } });
    const { token } = await prisma.magicLinkToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    // Verify magic link should return MFA challenge
    const verifyRes = await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token })
      .expect(200);

    expect(verifyRes.body).toHaveProperty('mfaRequired', true);
    expect(verifyRes.body).toHaveProperty('mfaToken');
  });

  it('refresh tokens from magic link login work correctly', async () => {
    await request(app)
      .post('/api/auth/magic-link/send')
      .send({ email: 'refresh-magic@example.com' });

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'refresh-magic@example.com' } });
    const { token } = await prisma.magicLinkToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    const verifyRes = await request(app)
      .post('/api/auth/magic-link/verify')
      .send({ token })
      .expect(200);

    // Use the refresh token
    const refreshRes = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: verifyRes.body.refreshToken })
      .expect(200);

    expect(refreshRes.body).toHaveProperty('accessToken');
    expect(refreshRes.body).toHaveProperty('refreshToken');
  });
});
