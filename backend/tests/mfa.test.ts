/**
 * Integration tests for MFA endpoints.
 *
 * Uses SQLite database (via Prisma) isolated per test suite.
 * Email sending is mocked — no real emails are sent.
 * TOTP verification is tested via the @otplib/preset-default library.
 */

import crypto from 'crypto';
import request from 'supertest';
import { authenticator } from '@otplib/preset-default';
import { app } from '../src/app';
import prisma from '../src/config/database';
import {
  setupTotp,
  verifyAndEnableTotp,
  createMfaToken,
  verifyMfaLogin,
} from '../src/services/mfaService';
import { registerUser, verifyEmail, loginUser } from '../src/services/authService';

// Mock email sending
jest.mock('../src/config/email', () => ({
  default: {
    sendMail: jest.fn().mockResolvedValue({}),
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const TEST_PASSWORD = 'Secure@Pass1';

/**
 * Create a user and verify their email directly (bypassing HTTP rate limiter).
 */
async function createVerifiedUser(email: string): Promise<string> {
  await registerUser(email, TEST_PASSWORD);

  const user = await prisma.user.findUniqueOrThrow({ where: { email } });
  const tokenRecord = await prisma.emailVerificationToken.findFirstOrThrow({
    where: { userId: user.id },
  });
  await verifyEmail(tokenRecord.token);

  return user.id;
}

/**
 * Create a user with MFA already enabled.
 * Returns userId, TOTP secret, and backup codes.
 */
async function createMfaUser(email: string): Promise<{
  userId: string;
  secret: string;
  backupCodes: string[];
}> {
  const userId = await createVerifiedUser(email);
  const { secret } = await setupTotp(userId);
  const totpCode = authenticator.generate(secret);
  const backupCodes = await verifyAndEnableTotp(userId, totpCode);
  return { userId, secret, backupCodes };
}

/**
 * Complete the MFA login flow and return tokens.
 */
async function loginWithMfa(userId: string, secret: string): Promise<{ accessToken: string; refreshToken: string }> {
  const mfaLoginToken = await createMfaToken(userId);
  const code = authenticator.generate(secret);
  return verifyMfaLogin(mfaLoginToken, code);
}

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await prisma.$connect();
});

afterEach(async () => {
  await prisma.mfaToken.deleteMany();
  await prisma.mfaBackupCode.deleteMany();
  await prisma.refreshToken.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.emailVerificationToken.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

// ---------------------------------------------------------------------------
// TOTP Setup
// ---------------------------------------------------------------------------

describe('POST /api/auth/mfa/totp/setup', () => {
  it('returns 401 without auth', async () => {
    await request(app).post('/api/auth/mfa/totp/setup').expect(401);
  });

  it('returns secret and QR code for authenticated user without MFA', async () => {
    const userId = await createVerifiedUser('setup@example.com');
    const { accessToken } = await loginUser('setup@example.com', TEST_PASSWORD) as any;

    const res = await request(app)
      .post('/api/auth/mfa/totp/setup')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body).toHaveProperty('secret');
    expect(res.body).toHaveProperty('qrCodeDataUrl');
    expect(res.body).toHaveProperty('otpauthUrl');
    expect(res.body.otpauthUrl).toContain('otpauth://totp/');
    expect(res.body.qrCodeDataUrl).toMatch(/^data:image\/png;base64,/);

    // Secret should be stored (but MFA not yet enabled)
    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user?.mfaTotpSecret).toBe(res.body.secret);
    expect(user?.mfaEnabled).toBe(false);
  });

  it('returns 409 when MFA is already enabled', async () => {
    const { userId, secret } = await createMfaUser('setup2@example.com');
    const { accessToken } = await loginWithMfa(userId, secret);

    const res = await request(app)
      .post('/api/auth/mfa/totp/setup')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(409);

    expect(res.body.error).toMatch(/already enabled/i);
  });
});

// ---------------------------------------------------------------------------
// TOTP Enable
// ---------------------------------------------------------------------------

describe('POST /api/auth/mfa/totp/enable', () => {
  it('enables MFA and returns backup codes for valid TOTP code', async () => {
    const userId = await createVerifiedUser('enable@example.com');
    const { accessToken } = await loginUser('enable@example.com', TEST_PASSWORD) as any;

    // Initiate setup
    const setupRes = await request(app)
      .post('/api/auth/mfa/totp/setup')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const { secret } = setupRes.body;
    const totpCode = authenticator.generate(secret);

    const enableRes = await request(app)
      .post('/api/auth/mfa/totp/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totpCode })
      .expect(200);

    expect(enableRes.body.message).toMatch(/enabled/i);
    expect(enableRes.body.backupCodes).toHaveLength(10);
    expect(typeof enableRes.body.backupCodes[0]).toBe('string');

    // Verify MFA is enabled in DB
    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user?.mfaEnabled).toBe(true);

    const storedCodes = await prisma.mfaBackupCode.findMany({ where: { userId } });
    expect(storedCodes).toHaveLength(10);
  });

  it('returns 400 for invalid TOTP code', async () => {
    await createVerifiedUser('enable2@example.com');
    const { accessToken } = await loginUser('enable2@example.com', TEST_PASSWORD) as any;

    await request(app)
      .post('/api/auth/mfa/totp/setup')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const res = await request(app)
      .post('/api/auth/mfa/totp/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totpCode: '000000' })
      .expect(400);

    expect(res.body.error).toMatch(/invalid totp code/i);
  });

  it('returns 400 if setup was not initiated', async () => {
    await createVerifiedUser('enable3@example.com');
    const { accessToken } = await loginUser('enable3@example.com', TEST_PASSWORD) as any;

    const res = await request(app)
      .post('/api/auth/mfa/totp/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totpCode: '123456' })
      .expect(400);

    expect(res.body.error).toMatch(/setup/i);
  });

  it('rejects invalid TOTP code format', async () => {
    await createVerifiedUser('enable4@example.com');
    const { accessToken } = await loginUser('enable4@example.com', TEST_PASSWORD) as any;

    const res = await request(app)
      .post('/api/auth/mfa/totp/enable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totpCode: 'abc' })
      .expect(400);

    expect(res.body.error).toMatch(/validation/i);
  });
});

// ---------------------------------------------------------------------------
// Login with MFA
// ---------------------------------------------------------------------------

describe('POST /api/auth/login (with MFA)', () => {
  it('returns mfaRequired and mfaToken when MFA is enabled', async () => {
    await createMfaUser('mfalogin@example.com');

    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'mfalogin@example.com', password: TEST_PASSWORD })
      .expect(200);

    expect(res.body.mfaRequired).toBe(true);
    expect(res.body).toHaveProperty('mfaToken');
    expect(res.body).not.toHaveProperty('accessToken');
  });
});

// ---------------------------------------------------------------------------
// MFA Verify Login
// ---------------------------------------------------------------------------

describe('POST /api/auth/mfa/verify', () => {
  it('returns access and refresh tokens for valid MFA token and TOTP code', async () => {
    const { secret } = await createMfaUser('verify@example.com');

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'verify@example.com', password: TEST_PASSWORD })
      .expect(200);

    const totpCode = authenticator.generate(secret);

    const verifyRes = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: loginRes.body.mfaToken, code: totpCode })
      .expect(200);

    expect(verifyRes.body).toHaveProperty('accessToken');
    expect(verifyRes.body).toHaveProperty('refreshToken');
  });

  it('returns 401 for an invalid TOTP code', async () => {
    await createMfaUser('verify2@example.com');

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'verify2@example.com', password: TEST_PASSWORD })
      .expect(200);

    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: loginRes.body.mfaToken, code: '000000' })
      .expect(401);

    expect(res.body.error).toMatch(/invalid mfa code/i);
  });

  it('returns 401 for an invalid MFA token', async () => {
    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: 'invalid-mfa-token', code: '123456' })
      .expect(401);

    expect(res.body.error).toMatch(/invalid or expired mfa token/i);
  });

  it('returns 401 when reusing an MFA token', async () => {
    const { secret } = await createMfaUser('verify3@example.com');

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'verify3@example.com', password: TEST_PASSWORD })
      .expect(200);

    const { mfaToken } = loginRes.body;
    const totpCode = authenticator.generate(secret);

    // First use — should succeed
    await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken, code: totpCode })
      .expect(200);

    // Second use — should fail (token consumed)
    await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken, code: totpCode })
      .expect(401);
  });

  it('accepts a backup code instead of TOTP code', async () => {
    const { backupCodes } = await createMfaUser('verify4@example.com');

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'verify4@example.com', password: TEST_PASSWORD })
      .expect(200);

    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: loginRes.body.mfaToken, code: backupCodes[0] })
      .expect(200);

    expect(res.body).toHaveProperty('accessToken');
  });

  it('invalidates backup code after use', async () => {
    const { userId, backupCodes } = await createMfaUser('verify5@example.com');

    // First login: use backup code
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'verify5@example.com', password: TEST_PASSWORD })
      .expect(200);

    await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: loginRes.body.mfaToken, code: backupCodes[0] })
      .expect(200);

    // Verify the code is marked as used in the DB
    const usedCode = await prisma.mfaBackupCode.findFirst({
      where: { userId, usedAt: { not: null } },
    });
    expect(usedCode).not.toBeNull();

    // Try to use the same backup code again with a new MFA token
    const staleMfaToken = await createMfaToken(userId);
    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: staleMfaToken, code: backupCodes[0] })
      .expect(401);

    expect(res.body.error).toMatch(/invalid mfa code/i);
  });

  it('returns 400 for missing fields', async () => {
    await request(app).post('/api/auth/mfa/verify').send({}).expect(400);
    await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: 'token' })
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// MFA Disable
// ---------------------------------------------------------------------------

describe('POST /api/auth/mfa/disable', () => {
  it('disables MFA after verifying TOTP code', async () => {
    const { userId, secret } = await createMfaUser('disable@example.com');
    const { accessToken } = await loginWithMfa(userId, secret);

    const disableCode = authenticator.generate(secret);
    const res = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ code: disableCode })
      .expect(200);

    expect(res.body.message).toMatch(/disabled/i);

    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user?.mfaEnabled).toBe(false);
    expect(user?.mfaTotpSecret).toBeNull();
  });

  it('disables MFA using a backup code', async () => {
    const { userId, secret, backupCodes } = await createMfaUser('disable2@example.com');
    const { accessToken } = await loginWithMfa(userId, secret);

    const res = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ code: backupCodes[0] })
      .expect(200);

    expect(res.body.message).toMatch(/disabled/i);
  });

  it('returns 400 for an invalid code', async () => {
    const { userId, secret } = await createMfaUser('disable3@example.com');
    const { accessToken } = await loginWithMfa(userId, secret);

    const res = await request(app)
      .post('/api/auth/mfa/disable')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ code: '000000' })
      .expect(400);

    expect(res.body.error).toMatch(/invalid mfa code/i);
  });

  it('returns 401 without auth', async () => {
    await request(app)
      .post('/api/auth/mfa/disable')
      .send({ code: '123456' })
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// Backup Code Regeneration
// ---------------------------------------------------------------------------

describe('POST /api/auth/mfa/backup-codes/regenerate', () => {
  it('regenerates backup codes after verifying TOTP code', async () => {
    const { userId, secret, backupCodes: oldCodes } = await createMfaUser('regen@example.com');
    const { accessToken } = await loginWithMfa(userId, secret);

    const totpCode = authenticator.generate(secret);
    const res = await request(app)
      .post('/api/auth/mfa/backup-codes/regenerate')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totpCode })
      .expect(200);

    expect(res.body.backupCodes).toHaveLength(10);
    expect(res.body.backupCodes[0]).not.toBe(oldCodes[0]);

    // Old backup codes should no longer work
    const staleMfaToken = await createMfaToken(userId);
    const invalidRes = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: staleMfaToken, code: oldCodes[0] })
      .expect(401);

    expect(invalidRes.body.error).toMatch(/invalid mfa code/i);
  });

  it('returns 400 for invalid TOTP code', async () => {
    const { userId, secret } = await createMfaUser('regen2@example.com');
    const { accessToken } = await loginWithMfa(userId, secret);

    const res = await request(app)
      .post('/api/auth/mfa/backup-codes/regenerate')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ totpCode: '000000' })
      .expect(400);

    expect(res.body.error).toMatch(/invalid totp code/i);
  });

  it('returns 401 without auth', async () => {
    await request(app)
      .post('/api/auth/mfa/backup-codes/regenerate')
      .send({ totpCode: '123456' })
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// MFA token expiry
// ---------------------------------------------------------------------------

describe('MFA token expiry', () => {
  it('rejects an expired MFA login token', async () => {
    const { userId } = await createMfaUser('expired@example.com');

    // Create an already-expired MFA token directly in DB
    const token = crypto.randomBytes(32).toString('hex');
    await prisma.mfaToken.create({
      data: {
        token,
        userId,
        expiresAt: new Date(Date.now() - 1000),
      },
    });

    const res = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: token, code: '123456' })
      .expect(401);

    expect(res.body.error).toMatch(/invalid or expired mfa token/i);
  });
});

// ---------------------------------------------------------------------------
// Full MFA flow: setup → enable → login → verify
// ---------------------------------------------------------------------------

describe('Full MFA login flow', () => {
  it('completes the full setup and login flow', async () => {
    const email = 'fullflow@example.com';
    await createVerifiedUser(email);
    const { accessToken: setupAccessToken } = await loginUser(email, TEST_PASSWORD) as any;

    // 1. Setup TOTP
    const setupRes = await request(app)
      .post('/api/auth/mfa/totp/setup')
      .set('Authorization', `Bearer ${setupAccessToken}`)
      .expect(200);

    const { secret } = setupRes.body;

    // 2. Enable MFA
    const enableCode = authenticator.generate(secret);
    const enableRes = await request(app)
      .post('/api/auth/mfa/totp/enable')
      .set('Authorization', `Bearer ${setupAccessToken}`)
      .send({ totpCode: enableCode })
      .expect(200);

    expect(enableRes.body.backupCodes).toHaveLength(10);

    // 3. Login now requires MFA
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email, password: TEST_PASSWORD })
      .expect(200);

    expect(loginRes.body.mfaRequired).toBe(true);
    expect(loginRes.body).toHaveProperty('mfaToken');

    // 4. Complete MFA verification
    const verifyCode = authenticator.generate(secret);
    const verifyRes = await request(app)
      .post('/api/auth/mfa/verify')
      .send({ mfaToken: loginRes.body.mfaToken, code: verifyCode })
      .expect(200);

    expect(verifyRes.body).toHaveProperty('accessToken');
    expect(verifyRes.body).toHaveProperty('refreshToken');
  });
});
