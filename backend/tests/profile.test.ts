/**
 * Integration tests for profile and preferences endpoints.
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

// Helper: register + verify a user and return their tokens + userId
async function registerAndVerify(
  email: string,
  password: string,
): Promise<{ accessToken: string; refreshToken: string; userId: string }> {
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

  return { ...(loginRes.body as { accessToken: string; refreshToken: string }), userId: user.id };
}

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await prisma.$connect();
});

afterEach(async () => {
  await prisma.securityLog.deleteMany();
  await prisma.emailChangeToken.deleteMany();
  await prisma.userPreferences.deleteMany();
  await prisma.refreshToken.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.emailVerificationToken.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

// ---------------------------------------------------------------------------
// GET /api/profile
// ---------------------------------------------------------------------------

describe('GET /api/profile', () => {
  it('returns the user profile for an authenticated user', async () => {
    const { accessToken } = await registerAndVerify('profile@example.com', 'Secure@Pass1');

    const res = await request(app)
      .get('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.email).toBe('profile@example.com');
    expect(res.body.name).toBeNull();
    expect(res.body.phoneNumber).toBeNull();
    expect(res.body.isEmailVerified).toBe(true);
    expect(res.body).not.toHaveProperty('passwordHash');
    expect(res.body).not.toHaveProperty('mfaTotpSecret');
  });

  it('returns 401 when no token is provided', async () => {
    await request(app).get('/api/profile').expect(401);
  });

  it('returns 401 for an invalid token', async () => {
    await request(app)
      .get('/api/profile')
      .set('Authorization', 'Bearer invalid.token.here')
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// PATCH /api/profile
// ---------------------------------------------------------------------------

describe('PATCH /api/profile', () => {
  it('updates the user name', async () => {
    const { accessToken } = await registerAndVerify('patchname@example.com', 'Secure@Pass1');

    const res = await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Alice Smith' })
      .expect(200);

    expect(res.body.message).toMatch(/profile updated/i);

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'patchname@example.com' } });
    expect(user.name).toBe('Alice Smith');
  });

  it('updates the phone number and resets phoneVerified', async () => {
    const { accessToken } = await registerAndVerify('patchphone@example.com', 'Secure@Pass1');

    await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ phoneNumber: '+12125551234' })
      .expect(200);

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'patchphone@example.com' } });
    expect(user.phoneNumber).toBe('+12125551234');
    expect(user.phoneVerified).toBe(false);
  });

  it('can clear name and phoneNumber with null', async () => {
    const { accessToken } = await registerAndVerify('clearnull@example.com', 'Secure@Pass1');

    await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: 'Bob', phoneNumber: '+12125559999' })
      .expect(200);

    await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ name: null, phoneNumber: null })
      .expect(200);

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'clearnull@example.com' } });
    expect(user.name).toBeNull();
    expect(user.phoneNumber).toBeNull();
  });

  it('requesting an email change sends a verification email and does not change email yet', async () => {
    const { accessToken } = await registerAndVerify('emailchange@example.com', 'Secure@Pass1');

    const res = await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email: 'newemail@example.com' })
      .expect(200);

    expect(res.body.message).toMatch(/verification email/i);

    // Email in DB should NOT change yet
    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'emailchange@example.com' } });
    expect(user.email).toBe('emailchange@example.com');

    // An email change token should have been created for the new email
    const tokenRecord = await prisma.emailChangeToken.findFirst({
      where: { userId: user.id, newEmail: 'newemail@example.com' },
    });
    expect(tokenRecord).not.toBeNull();
  });

  it('returns 409 when requesting email change to an already-used email', async () => {
    await registerAndVerify('taken@example.com', 'Secure@Pass1');
    const { accessToken } = await registerAndVerify('requester@example.com', 'Secure@Pass1');

    const res = await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email: 'taken@example.com' })
      .expect(409);

    expect(res.body.error).toMatch(/already in use/i);
  });

  it('returns 409 when phone number is already used by another user', async () => {
    const { accessToken: token1 } = await registerAndVerify('phone1@example.com', 'Secure@Pass1');
    const { accessToken: token2 } = await registerAndVerify('phone2@example.com', 'Secure@Pass1');

    await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${token1}`)
      .send({ phoneNumber: '+12125550001' })
      .expect(200);

    const res = await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${token2}`)
      .send({ phoneNumber: '+12125550001' })
      .expect(409);

    expect(res.body.error).toMatch(/already in use/i);
  });

  it('returns 400 for invalid phone number format', async () => {
    const { accessToken } = await registerAndVerify('badphone@example.com', 'Secure@Pass1');

    const res = await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ phoneNumber: 'not-a-phone' })
      .expect(400);

    expect(res.body.error).toMatch(/validation/i);
  });

  it('returns 400 for invalid email format', async () => {
    const { accessToken } = await registerAndVerify('bademail@example.com', 'Secure@Pass1');

    const res = await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email: 'not-an-email' })
      .expect(400);

    expect(res.body.error).toMatch(/validation/i);
  });

  it('returns 400 for unknown fields', async () => {
    const { accessToken } = await registerAndVerify('unknown@example.com', 'Secure@Pass1');

    await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ unknownField: 'value' })
      .expect(400);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app)
      .patch('/api/profile')
      .send({ name: 'Hacker' })
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// POST /api/profile/email/confirm-change
// ---------------------------------------------------------------------------

describe('POST /api/profile/email/confirm-change', () => {
  it('confirms the email change and updates the email', async () => {
    const { accessToken, userId } = await registerAndVerify(
      'confirm@example.com',
      'Secure@Pass1',
    );

    await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email: 'confirmed-new@example.com' })
      .expect(200);

    const tokenRecord = await prisma.emailChangeToken.findFirstOrThrow({
      where: { userId, newEmail: 'confirmed-new@example.com' },
    });

    const res = await request(app)
      .post('/api/profile/email/confirm-change')
      .send({ token: tokenRecord.token })
      .expect(200);

    expect(res.body.message).toMatch(/updated successfully/i);

    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
    expect(user.email).toBe('confirmed-new@example.com');
    expect(user.isEmailVerified).toBe(true);
  });

  it('returns 400 for an invalid token', async () => {
    const res = await request(app)
      .post('/api/profile/email/confirm-change')
      .send({ token: 'invalid-token-xxx' })
      .expect(400);

    expect(res.body.error).toMatch(/invalid or expired/i);
  });

  it('returns 400 for an expired token', async () => {
    const { accessToken, userId } = await registerAndVerify(
      'expired-change@example.com',
      'Secure@Pass1',
    );

    await request(app)
      .patch('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email: 'expired-new@example.com' })
      .expect(200);

    // Artificially expire the token
    await prisma.emailChangeToken.updateMany({
      where: { userId },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });

    const tokenRecord = await prisma.emailChangeToken.findFirstOrThrow({
      where: { userId },
    });

    await request(app)
      .post('/api/profile/email/confirm-change')
      .send({ token: tokenRecord.token })
      .expect(400);
  });

  it('returns 400 for missing token', async () => {
    await request(app)
      .post('/api/profile/email/confirm-change')
      .send({})
      .expect(400);
  });
});

// ---------------------------------------------------------------------------
// GET /api/profile/preferences
// ---------------------------------------------------------------------------

describe('GET /api/profile/preferences', () => {
  it('returns default preferences for a new user', async () => {
    const { accessToken } = await registerAndVerify('prefs@example.com', 'Secure@Pass1');

    const res = await request(app)
      .get('/api/profile/preferences')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.emailNotifications).toBe(true);
    expect(res.body.theme).toBe('light');
    expect(res.body.language).toBe('en');
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app).get('/api/profile/preferences').expect(401);
  });
});

// ---------------------------------------------------------------------------
// PATCH /api/profile/preferences
// ---------------------------------------------------------------------------

describe('PATCH /api/profile/preferences', () => {
  it('updates preferences', async () => {
    const { accessToken } = await registerAndVerify('updateprefs@example.com', 'Secure@Pass1');

    const res = await request(app)
      .patch('/api/profile/preferences')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ theme: 'dark', emailNotifications: false, language: 'fr' })
      .expect(200);

    expect(res.body.theme).toBe('dark');
    expect(res.body.emailNotifications).toBe(false);
    expect(res.body.language).toBe('fr');
  });

  it('updates only the specified preferences', async () => {
    const { accessToken } = await registerAndVerify('partialprefs@example.com', 'Secure@Pass1');

    await request(app)
      .patch('/api/profile/preferences')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ theme: 'dark' })
      .expect(200);

    const res = await request(app)
      .get('/api/profile/preferences')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.theme).toBe('dark');
    expect(res.body.emailNotifications).toBe(true);
    expect(res.body.language).toBe('en');
  });

  it('returns 400 for invalid theme value', async () => {
    const { accessToken } = await registerAndVerify('badtheme@example.com', 'Secure@Pass1');

    const res = await request(app)
      .patch('/api/profile/preferences')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ theme: 'rainbow' })
      .expect(400);

    expect(res.body.error).toMatch(/validation/i);
  });

  it('returns 400 for unknown preference fields', async () => {
    const { accessToken } = await registerAndVerify('unknownpref@example.com', 'Secure@Pass1');

    await request(app)
      .patch('/api/profile/preferences')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ unknownPref: true })
      .expect(400);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app)
      .patch('/api/profile/preferences')
      .send({ theme: 'dark' })
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// POST /api/profile/deactivate
// ---------------------------------------------------------------------------

describe('POST /api/profile/deactivate', () => {
  it('deactivates the account, sets deactivatedAt, and revokes all refresh tokens', async () => {
    const { accessToken, userId } = await registerAndVerify('deactivate@example.com', 'Secure@Pass1');

    const res = await request(app)
      .post('/api/profile/deactivate')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: 'Secure@Pass1' })
      .expect(200);

    expect(res.body.message).toMatch(/deactivated/i);

    const user = await prisma.user.findUniqueOrThrow({ where: { id: userId } });
    expect(user.deactivatedAt).not.toBeNull();

    const activeTokens = await prisma.refreshToken.findMany({
      where: { userId, revokedAt: null },
    });
    expect(activeTokens).toHaveLength(0);
  });

  it('prevents login after deactivation', async () => {
    const { accessToken } = await registerAndVerify('deactivated-login@example.com', 'Secure@Pass1');

    await request(app)
      .post('/api/profile/deactivate')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: 'Secure@Pass1' })
      .expect(200);

    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'deactivated-login@example.com', password: 'Secure@Pass1' })
      .expect(403);

    expect(loginRes.body.error).toMatch(/deactivated/i);
  });

  it('returns 401 for wrong password', async () => {
    const { accessToken } = await registerAndVerify('deactivate-wrongpw@example.com', 'Secure@Pass1');

    const res = await request(app)
      .post('/api/profile/deactivate')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: 'WrongPassword!' })
      .expect(401);

    expect(res.body.error).toMatch(/incorrect password/i);
  });

  it('returns 409 if account is already deactivated', async () => {
    const { accessToken } = await registerAndVerify('already-deactivated@example.com', 'Secure@Pass1');

    await request(app)
      .post('/api/profile/deactivate')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: 'Secure@Pass1' })
      .expect(200);

    // The token is still valid for this call since JWT is stateless
    const res = await request(app)
      .post('/api/profile/deactivate')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: 'Secure@Pass1' })
      .expect(409);

    expect(res.body.error).toMatch(/already deactivated/i);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app)
      .post('/api/profile/deactivate')
      .send({ password: 'Secure@Pass1' })
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// DELETE /api/profile
// ---------------------------------------------------------------------------

describe('DELETE /api/profile', () => {
  it('permanently deletes the account and all associated data', async () => {
    const { accessToken, userId } = await registerAndVerify('delete@example.com', 'Secure@Pass1');

    const res = await request(app)
      .delete('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: 'Secure@Pass1' })
      .expect(200);

    expect(res.body.message).toMatch(/permanently deleted/i);

    const user = await prisma.user.findUnique({ where: { id: userId } });
    expect(user).toBeNull();
  });

  it('returns 401 for wrong password', async () => {
    const { accessToken } = await registerAndVerify('delete-wrongpw@example.com', 'Secure@Pass1');

    const res = await request(app)
      .delete('/api/profile')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ password: 'WrongPassword!' })
      .expect(401);

    expect(res.body.error).toMatch(/incorrect password/i);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app)
      .delete('/api/profile')
      .send({ password: 'Secure@Pass1' })
      .expect(401);
  });
});

// ---------------------------------------------------------------------------
// GET /api/profile/export
// ---------------------------------------------------------------------------

describe('GET /api/profile/export', () => {
  it('returns personal data as a JSON export', async () => {
    const { accessToken, userId } = await registerAndVerify('export@example.com', 'Secure@Pass1');

    // Set a preference to verify it appears in the export
    await request(app)
      .patch('/api/profile/preferences')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ theme: 'dark', language: 'fr' })
      .expect(200);

    const res = await request(app)
      .get('/api/profile/export')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.exportedAt).toBeDefined();
    expect(res.body.profile.id).toBe(userId);
    expect(res.body.profile.email).toBe('export@example.com');
    expect(res.body.profile.isEmailVerified).toBe(true);
    expect(res.body.profile).not.toHaveProperty('passwordHash');
    expect(res.body.profile).not.toHaveProperty('mfaTotpSecret');
    expect(res.body.preferences.theme).toBe('dark');
    expect(res.body.preferences.language).toBe('fr');
    expect(res.body.profile.deactivatedAt).toBeNull();
  });

  it('includes null preferences when none have been set', async () => {
    const { accessToken } = await registerAndVerify('export-noprefs@example.com', 'Secure@Pass1');

    const res = await request(app)
      .get('/api/profile/export')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.preferences).toBeNull();
  });

  it('returns the Content-Disposition header for file download', async () => {
    const { accessToken } = await registerAndVerify('export-header@example.com', 'Secure@Pass1');

    const res = await request(app)
      .get('/api/profile/export')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.headers['content-disposition']).toMatch(/attachment/i);
    expect(res.headers['content-disposition']).toMatch(/my-data\.json/i);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app).get('/api/profile/export').expect(401);
  });
});
