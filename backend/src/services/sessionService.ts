import prisma from '../config/database';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SessionInfo {
  id: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  ipAddress: string | null;
  userAgent: string | null;
  deviceName: string | null;
}

// ---------------------------------------------------------------------------
// List active sessions
// ---------------------------------------------------------------------------

/**
 * Return all active (non-revoked, non-expired) sessions for a user.
 * Each session corresponds to a live refresh token.
 * Results are ordered most-recent-first.
 */
export async function listActiveSessions(userId: string): Promise<SessionInfo[]> {
  const sessions = await prisma.refreshToken.findMany({
    where: {
      userId,
      revokedAt: null,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      createdAt: true,
      lastUsedAt: true,
      ipAddress: true,
      userAgent: true,
      deviceName: true,
    },
  });

  return sessions;
}

// ---------------------------------------------------------------------------
// Revoke a specific session
// ---------------------------------------------------------------------------

/**
 * Revoke a specific session (refresh token) by its ID.
 * Verifies the session belongs to the authenticated user before revoking.
 * Throws 'SESSION_NOT_FOUND' if the session does not exist or is already revoked.
 */
export async function revokeSession(userId: string, sessionId: string): Promise<void> {
  const session = await prisma.refreshToken.findFirst({
    where: {
      id: sessionId,
      userId,
      revokedAt: null,
    },
  });

  if (!session) {
    throw new Error('SESSION_NOT_FOUND');
  }

  await prisma.refreshToken.update({
    where: { id: sessionId },
    data: { revokedAt: new Date() },
  });
}

// ---------------------------------------------------------------------------
// Revoke all sessions
// ---------------------------------------------------------------------------

/**
 * Revoke all active sessions for a user.
 * Returns the count of revoked sessions.
 */
export async function revokeAllSessions(userId: string): Promise<number> {
  const result = await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });

  return result.count;
}
