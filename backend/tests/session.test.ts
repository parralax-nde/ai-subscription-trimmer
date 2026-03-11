/**
 * Integration tests for session management and security log endpoints.
 *
 * Tests cover:
 *  - GET  /api/auth/sessions            — list active sessions
 *  - DELETE /api/auth/sessions/:id      — revoke a specific session
 *  - DELETE /api/auth/sessions          — revoke all sessions
 *  - GET  /api/auth/security-logs       — retrieve security history
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

  return {
    ...(loginRes.body as { accessToken: string; refreshToken: string }),
    userId: user.id,
  };
}

// ---------------------------------------------------------------------------
// Setup / Teardown
// ---------------------------------------------------------------------------

beforeAll(async () => {
  await prisma.$connect();
});

afterEach(async () => {
  await prisma.securityLog.deleteMany();
  await prisma.refreshToken.deleteMany();
  await prisma.passwordResetToken.deleteMany();
  await prisma.emailVerificationToken.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});

// ---------------------------------------------------------------------------
// GET /api/auth/sessions
// ---------------------------------------------------------------------------

describe('GET /api/auth/sessions', () => {
  it('returns a list of active sessions for the authenticated user', async () => {
    const { accessToken } = await registerAndVerify('sessions@example.com', 'Secure@Pass1');

    const res = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(Array.isArray(res.body.sessions)).toBe(true);
    expect(res.body.sessions.length).toBe(1);
    expect(res.body.sessions[0]).toHaveProperty('id');
    expect(res.body.sessions[0]).toHaveProperty('createdAt');
  });

  it('reflects multiple logins as multiple sessions', async () => {
    const { accessToken } = await registerAndVerify('multi-session@example.com', 'Secure@Pass1');

    // Second login from the same user
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'multi-session@example.com', password: 'Secure@Pass1' })
      .expect(200);

    const res = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.sessions.length).toBe(2);
  });

  it('does not show revoked sessions', async () => {
    const { accessToken, refreshToken } = await registerAndVerify(
      'revoked-session@example.com',
      'Secure@Pass1',
    );

    // Logout (revoke the session)
    await request(app).post('/api/auth/logout').send({ refreshToken }).expect(200);

    const res = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.sessions.length).toBe(0);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app).get('/api/auth/sessions').expect(401);
  });
});

// ---------------------------------------------------------------------------
// DELETE /api/auth/sessions/:sessionId
// ---------------------------------------------------------------------------

describe('DELETE /api/auth/sessions/:sessionId', () => {
  it('revokes a specific session by ID', async () => {
    const { accessToken, userId } = await registerAndVerify(
      'revoke-specific@example.com',
      'Secure@Pass1',
    );

    // Get session ID from DB
    const session = await prisma.refreshToken.findFirstOrThrow({ where: { userId, revokedAt: null } });

    const res = await request(app)
      .delete(`/api/auth/sessions/${session.id}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.message).toMatch(/revoked/i);

    // Session should now be revoked in DB
    const updated = await prisma.refreshToken.findUniqueOrThrow({ where: { id: session.id } });
    expect(updated.revokedAt).not.toBeNull();
  });

  it('returns 404 for a session that does not belong to the user', async () => {
    const { accessToken: token1 } = await registerAndVerify(
      'owner@example.com',
      'Secure@Pass1',
    );
    await registerAndVerify(
      'other@example.com',
      'Secure@Pass1',
    );

    // Get a session ID belonging to the other user
    const otherUser = await prisma.user.findUniqueOrThrow({ where: { email: 'other@example.com' } });
    const otherSession = await prisma.refreshToken.findFirstOrThrow({
      where: { userId: otherUser.id, revokedAt: null },
    });

    const res = await request(app)
      .delete(`/api/auth/sessions/${otherSession.id}`)
      .set('Authorization', `Bearer ${token1}`)
      .expect(404);

    expect(res.body.error).toMatch(/not found/i);

    // Verify it was NOT revoked
    const unchanged = await prisma.refreshToken.findUniqueOrThrow({ where: { id: otherSession.id } });
    expect(unchanged.revokedAt).toBeNull();
  });

  it('returns 404 when revoking an already-revoked session', async () => {
    const { accessToken, refreshToken, userId } = await registerAndVerify(
      'already-revoked@example.com',
      'Secure@Pass1',
    );

    // Revoke via logout first
    await request(app).post('/api/auth/logout').send({ refreshToken }).expect(200);

    const session = await prisma.refreshToken.findFirstOrThrow({ where: { userId } });

    await request(app)
      .delete(`/api/auth/sessions/${session.id}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(404);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app).delete('/api/auth/sessions/some-id').expect(401);
  });
});

// ---------------------------------------------------------------------------
// DELETE /api/auth/sessions (revoke all)
// ---------------------------------------------------------------------------

describe('DELETE /api/auth/sessions', () => {
  it('revokes all active sessions for the user', async () => {
    const { accessToken, userId } = await registerAndVerify(
      'revoke-all@example.com',
      'Secure@Pass1',
    );

    // Create a second session
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'revoke-all@example.com', password: 'Secure@Pass1' })
      .expect(200);

    const res = await request(app)
      .delete('/api/auth/sessions')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.message).toMatch(/2 session\(s\)/i);

    // All sessions revoked
    const active = await prisma.refreshToken.count({ where: { userId, revokedAt: null } });
    expect(active).toBe(0);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app).delete('/api/auth/sessions').expect(401);
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/security-logs
// ---------------------------------------------------------------------------

describe('GET /api/auth/security-logs', () => {
  it('returns security log entries for the user', async () => {
    const { accessToken } = await registerAndVerify('security-log@example.com', 'Secure@Pass1');

    const res = await request(app)
      .get('/api/auth/security-logs')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(Array.isArray(res.body.logs)).toBe(true);
    // At least a LOGIN_SUCCESS event should be logged
    const eventTypes = (res.body.logs as Array<{ eventType: string }>).map((l) => l.eventType);
    expect(eventTypes).toContain('LOGIN_SUCCESS');
  });

  it('records LOGIN_FAILED for invalid credentials', async () => {
    const { accessToken } = await registerAndVerify(
      'login-failed@example.com',
      'Secure@Pass1',
    );

    // Attempt login with wrong password
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'login-failed@example.com', password: 'WrongPass@1' })
      .expect(401);

    const res = await request(app)
      .get('/api/auth/security-logs')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const eventTypes = (res.body.logs as Array<{ eventType: string }>).map((l) => l.eventType);
    expect(eventTypes).toContain('LOGIN_FAILED');
  });

  it('records LOGOUT event', async () => {
    const { accessToken, refreshToken } = await registerAndVerify(
      'logout-log@example.com',
      'Secure@Pass1',
    );

    await request(app).post('/api/auth/logout').send({ refreshToken }).expect(200);

    const res = await request(app)
      .get('/api/auth/security-logs')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const eventTypes = (res.body.logs as Array<{ eventType: string }>).map((l) => l.eventType);
    expect(eventTypes).toContain('LOGOUT');
  });

  it('records PASSWORD_RESET_REQUESTED event', async () => {
    const { accessToken } = await registerAndVerify(
      'forgot-log@example.com',
      'Secure@Pass1',
    );

    await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'forgot-log@example.com' })
      .expect(202);

    const res = await request(app)
      .get('/api/auth/security-logs')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const eventTypes = (res.body.logs as Array<{ eventType: string }>).map((l) => l.eventType);
    expect(eventTypes).toContain('PASSWORD_RESET_REQUESTED');
  });

  it('records PASSWORD_CHANGED event after password reset', async () => {
    const { accessToken } = await registerAndVerify(
      'reset-log@example.com',
      'Secure@Pass1',
    );

    await request(app)
      .post('/api/auth/forgot-password')
      .send({ email: 'reset-log@example.com' })
      .expect(202);

    const user = await prisma.user.findUniqueOrThrow({ where: { email: 'reset-log@example.com' } });
    const { token } = await prisma.passwordResetToken.findFirstOrThrow({
      where: { userId: user.id },
    });

    await request(app)
      .post('/api/auth/reset-password')
      .send({ token, password: 'NewSecure@Pass9' })
      .expect(200);

    const res = await request(app)
      .get('/api/auth/security-logs')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const eventTypes = (res.body.logs as Array<{ eventType: string }>).map((l) => l.eventType);
    expect(eventTypes).toContain('PASSWORD_CHANGED');
  });

  it('records SESSION_REVOKED when a specific session is revoked', async () => {
    const { accessToken, userId } = await registerAndVerify(
      'session-revoke-log@example.com',
      'Secure@Pass1',
    );

    const session = await prisma.refreshToken.findFirstOrThrow({ where: { userId, revokedAt: null } });

    await request(app)
      .delete(`/api/auth/sessions/${session.id}`)
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const res = await request(app)
      .get('/api/auth/security-logs')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const eventTypes = (res.body.logs as Array<{ eventType: string }>).map((l) => l.eventType);
    expect(eventTypes).toContain('SESSION_REVOKED');
  });

  it('supports the limit query parameter', async () => {
    const { accessToken } = await registerAndVerify(
      'limit-test@example.com',
      'Secure@Pass1',
    );

    const res = await request(app)
      .get('/api/auth/security-logs?limit=1')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    expect(res.body.logs.length).toBeLessThanOrEqual(1);
  });

  it('returns 401 when unauthenticated', async () => {
    await request(app).get('/api/auth/security-logs').expect(401);
  });
});

// ---------------------------------------------------------------------------
// Session metadata — IP and user agent stored with session
// ---------------------------------------------------------------------------

describe('Session metadata', () => {
  it('sessions include metadata fields', async () => {
    const { accessToken } = await registerAndVerify(
      'meta@example.com',
      'Secure@Pass1',
    );

    const res = await request(app)
      .get('/api/auth/sessions')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);

    const session = res.body.sessions[0] as {
      id: string;
      ipAddress: string | null;
      userAgent: string | null;
      deviceName: string | null;
      createdAt: string;
      lastUsedAt: string | null;
    };

    expect(session).toHaveProperty('id');
    expect(session).toHaveProperty('ipAddress');
    expect(session).toHaveProperty('userAgent');
    expect(session).toHaveProperty('deviceName');
    expect(session).toHaveProperty('createdAt');
    expect(session).toHaveProperty('lastUsedAt');
  });
});
