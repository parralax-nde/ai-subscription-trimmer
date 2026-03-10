/**
 * Integration tests for authentication endpoints.
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
  // Register
  await request(app).post('/api/auth/register').send({ email, password }).expect(202);

  // Grab the verification token from DB
  const user = await prisma.user.findUniqueOrThrow({ where: { email } });
  const { token } = await prisma.emailVerificationToken.findFirstOrThrow({
    where: { userId: user.id },
  });

  // Verify email
  await request(app).post('/api/auth/verify-email').send({ token }).expect(200);

  // Log in
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
  // Clean DB between tests for isolation
  await prisma.refreshToken.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.emailVerificationToken.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

describe('GET /health', () => {
  it('returns 200 ok', async () => {
    const res = await request(app).get('/health').expect(200);
    expect(res.body.status).toBe('ok');
  });
});

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe('POST /api/auth/register', () => {
  it('accepts valid registration and returns 202 with generic message', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'user@example.com', password: 'Secure@Pass1' })
      .expect(202);

    expect(res.body.message).toMatch(/verification email/i);
  });

  it('returns 202 even when email is already registered (prevents enumeration)', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'dup@example.com', password: 'Secure@Pass1' })
      .expect(202);

    // Second registration with same email
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'dup@example.com', password: 'Secure@Pass1' })
      .expect(202);

    expect(res.body.message).toMatch(/verification email/i);
  });

  it('normalises email to lowercase', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'User@Example.COM', password: 'Secure@Pass1' })
      .expect(202);

    const user = await prisma.user.findUnique({ where: { email: 'user@example.com' } });
    expect(user).not.toBeNull();
  });

  it('rejects an invalid email', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'not-an-email', password: 'Secure@Pass1' })
      .expect(400);

    expect(res.body.error).toMatch(/validation/i);
  });

  it('rejects a weak password (too short)', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'user2@example.com', password: 'Abc1!' })
      .expect(400);

    expect(res.body.error).toMatch(/validation/i);
  });

  it('rejects a password without a special character', async () => {
    const res = await request(app)
      .post('/api/auth/register')
      .send({ email: 'user3@example.com', password: 'Password1234' })
      .expect(400);

    expect(res.body.error).toMatch(/validation/i);
  });

  it('rejects missing fields', async () => {
    await request(app).post('/api/auth/register').send({}).expect(400);
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'user@example.com' })
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// Email Verification
// ---------------------------------------------------------------------------

describe('POST /api/auth/verify-email', () => {
  it('verifies a valid token and marks user as verified', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'verify@example.com', password: 'Secure@Pass1' });

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'verify@example.com' } });
    expect(user.isEmailVerified).toBe(false);

    const { token } = await prisma.emailVerificationToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    const res = await request(app)
      .post('/api/auth/verify-email')
      .send({ token })
      .expect(200);

    expect(res.body.message).toMatch(/verified/i);

    const updatedUser = await prisma.user.findUniqueOrThrow({ where: { email: 'verify@example.com' } });
    expect(updatedUser.isEmailVerified).toBe(true);
  });

  it('returns 400 for an invalid token', async () => {
    const res = await request(app)
      .post('/api/auth/verify-email')
      .send({ token: 'invalid-token-xxx' })
      .expect(400);

    expect(res.body.error).toMatch(/invalid or expired/i);
  });

  it('returns 400 for an expired token', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'expired@example.com', password: 'Secure@Pass1' });

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'expired@example.com' } });
    // Artificially expire the token
    await prisma.emailVerificationToken.updateMany({
      where: { userId: user.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const { token } = await prisma.emailVerificationToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    await request(app).post('/api/auth/verify-email').send({ token }).expect(400);
  });

  it('rejects missing token', async () => {
    await request(app).post('/api/auth/verify-email').send({}).expect(400);
  });
});

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

describe('POST /api/auth/login', () => {
  it('returns access and refresh tokens for valid credentials', async () => {
    await registerAndVerify('login@example.com', 'Secure@Pass1');

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login@example.com', password: 'Secure@Pass1' })
      .expect(200);

    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
  });

  it('returns 401 for wrong password', async () => {
    await registerAndVerify('wrong@example.com', 'Secure@Pass1');

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'wrong@example.com', password: 'WrongPass@1' })
      .expect(401);

    expect(res.body.error).toMatch(/invalid email or password/i);
  });

  it('returns 401 for non-existent user (prevents enumeration)', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'ghost@example.com', password: 'Secure@Pass1' })
      .expect(401);

    expect(res.body.error).toMatch(/invalid email or password/i);
  });

  it('returns 403 when email is not verified', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'unverified@example.com', password: 'Secure@Pass1' });

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'unverified@example.com', password: 'Secure@Pass1' })
      .expect(403);

    expect(res.body.error).toMatch(/verify your email/i);
  });

  it('rejects invalid email format', async () => {
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'not-valid', password: 'Secure@Pass1' })
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// Token Refresh
// ---------------------------------------------------------------------------

describe('POST /api/auth/refresh', () => {
  it('returns new access and refresh tokens for a valid refresh token', async () => {
    const { refreshToken } = await registerAndVerify('refresh@example.com', 'Secure@Pass1');

    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken })
      .expect(200);

    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).toHaveProperty('refreshToken');
    expect(res.body.refreshToken).not.toBe(refreshToken); // rotated
  });

  it('returns 401 for an invalid refresh token', async () => {
    await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: 'invalid.token.here' })
      .expect(401);
  });

  it('returns 401 when reusing a revoked refresh token', async () => {
    const { refreshToken } = await registerAndVerify('reuse@example.com', 'Secure@Pass1');

    // First use — should succeed and rotate
    await request(app).post('/api/auth/refresh').send({ refreshToken }).expect(200);

    // Second use of the same (now revoked) token
    await request(app).post('/api/auth/refresh').send({ refreshToken }).expect(401);
  });
});

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

describe('POST /api/auth/logout', () => {
  it('revokes the refresh token', async () => {
    const { refreshToken } = await registerAndVerify('logout@example.com', 'Secure@Pass1');

    await request(app).post('/api/auth/logout').send({ refreshToken }).expect(200);

    // Refresh should now fail
    await request(app).post('/api/auth/refresh').send({ refreshToken }).expect(401);
  });

  it('returns 200 even for an unknown refresh token', async () => {
    await request(app)
      .post('/api/auth/logout')
      .send({ refreshToken: 'unknown.token.value' })
      .expect(200);
  });
});

// ---------------------------------------------------------------------------
// Forgot Password
// ---------------------------------------------------------------------------

describe('POST /api/auth/forgot-password', () => {
  it('returns 202 with generic message for registered email', async () => {
    await registerAndVerify('forgot@example.com', 'Secure@Pass1');

    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'forgot@example.com' })
      .expect(202);

    expect(res.body.message).toMatch(/password reset email/i);
  });

  it('returns 202 even for non-existent email (prevents enumeration)', async () => {
    const res = await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'nobody@example.com' })
      .expect(202);

    expect(res.body.message).toMatch(/password reset email/i);
  });

  it('rejects invalid email format', async () => {
    await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'bad-email' })
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// Reset Password
// ---------------------------------------------------------------------------

describe('POST /api/auth/reset-password', () => {
  async function getForgotToken(email: string): Promise<string> {
    const user = await prisma.user.findUniqueOrThrow({ where: { email } });
    const { token } = await prisma.passwordResetToken.findFirstOrThrow({
      where: { userId: user.id },
    });
    return token;
  }

  it('resets the password with a valid token and allows login with new password', async () => {
    await registerAndVerify('reset@example.com', 'Secure@Pass1');
    await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reset@example.com' });

    const token = await getForgotToken('reset@example.com');

    await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'NewSecure@Pass9' })
      .expect(200);

    // Login with old password should fail
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'reset@example.com', password: 'Secure@Pass1' })
      .expect(401);

    // Login with new password should succeed
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'reset@example.com', password: 'NewSecure@Pass9' })
      .expect(200);

    expect(res.body).toHaveProperty('accessToken');
  });

  it('returns 400 for an invalid token', async () => {
    await request(app)
      .post('/api/auth/reset-password')
      .send({ token: 'bad-token', password: 'NewSecure@Pass9' })
      .expect(400);
  });

  it('returns 400 when reusing a reset token', async () => {
    await registerAndVerify('reuse-reset@example.com', 'Secure@Pass1');
    await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reuse-reset@example.com' });

    const token = await getForgotToken('reuse-reset@example.com');

    // First use — succeeds
    await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'NewSecure@Pass9' })
      .expect(200);

    // Second use — should fail
    await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'AnotherPass@1' })
      .expect(400);
  });

  it('rejects weak new passwords', async () => {
    await registerAndVerify('weakreset@example.com', 'Secure@Pass1');
    await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'weakreset@example.com' });

    const token = await getForgotToken('weakreset@example.com');

    await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'weak' })
      .expect(400);
  });

  it('revokes existing refresh tokens after password reset', async () => {
    const { refreshToken } = await registerAndVerify('revoke@example.com', 'Secure@Pass1');

    await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'revoke@example.com' });

    const token = await getForgotToken('revoke@example.com');

    await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'NewSecure@Pass9' })
      .expect(200);

    // Old refresh token should be revoked
    await request(app).post('/api/auth/refresh').send({ refreshToken }).expect(401);
  });
});

// ---------------------------------------------------------------------------
// Unknown routes
// ---------------------------------------------------------------------------

describe('Unknown routes', () => {
  it('returns 404 for unknown paths', async () => {
    const res = await request(app).get('/api/unknown').expect(404);
    expect(res.body.error).toBe('Not found.');
  });
});
