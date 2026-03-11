import prisma from '../config/database';

// ---------------------------------------------------------------------------
// Security event types
// ---------------------------------------------------------------------------

export type SecurityEventType =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGOUT'
  | 'PASSWORD_RESET_REQUESTED'
  | 'PASSWORD_CHANGED'
  | 'MFA_ENABLED'
  | 'MFA_DISABLED'
  | 'MFA_BACKUP_CODES_REGENERATED'
  | 'SESSION_REVOKED'
  | 'ALL_SESSIONS_REVOKED'
  | 'EMAIL_VERIFIED';

export interface SecurityLogEntry {
  id: string;
  userId: string | null;
  eventType: string;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: Record<string, unknown> | null;
  createdAt: Date;
}

export interface LogEventOptions {
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Log a security event
// ---------------------------------------------------------------------------

/**
 * Record a security event.
 * userId is optional — e.g. for failed login attempts where the user may not exist.
 */
export async function logSecurityEvent(
  userId: string | null,
  eventType: SecurityEventType,
  options: LogEventOptions = {},
): Promise<void> {
  const { ipAddress, userAgent, metadata } = options;

  await prisma.securityLog.create({
    data: {
      userId: userId ?? null,
      eventType,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      metadata: metadata ? JSON.stringify(metadata) : null,
    },
  });
}

// ---------------------------------------------------------------------------
// Query security logs for a user
// ---------------------------------------------------------------------------

const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;

/**
 * Return the most recent security log entries for a user.
 * Results are ordered newest-first.
 */
export async function getSecurityLogs(
  userId: string,
  limit = DEFAULT_LIMIT,
): Promise<SecurityLogEntry[]> {
  const safeLimit = Math.min(Math.max(1, limit), MAX_LIMIT);

  const rows = await prisma.securityLog.findMany({
    where: { userId },
    orderBy: { createdAt: 'desc' },
    take: safeLimit,
  });

  return rows.map((row) => ({
    id: row.id,
    userId: row.userId,
    eventType: row.eventType,
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    metadata: row.metadata ? (JSON.parse(row.metadata) as Record<string, unknown>) : null,
    createdAt: row.createdAt,
  }));
}
