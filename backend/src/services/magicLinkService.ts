import prisma from '../config/database';
import { config } from '../config';
import { generateSecureToken } from '../utils/crypto';
import { generateAccessToken, generateRefreshToken, parseDurationMs } from '../utils/tokens';
import { sendMagicLinkEmail } from './emailService';
import { createMfaToken } from './mfaService';

// ---------------------------------------------------------------------------
// Send Magic Link
// ---------------------------------------------------------------------------

/**
 * Send a magic link to the user's email for passwordless login.
 * Always returns successfully to prevent user enumeration.
 * Creates a user account (without password) if one doesn't exist.
 */
export async function sendMagicLink(email: string): Promise<void> {
  const normalizedEmail = email.toLowerCase().trim();

  let user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (!user) {
    // Create a passwordless user account
    user = await prisma.user.create({
      data: { email: normalizedEmail, isEmailVerified: false },
    });
  }

  // Invalidate any existing magic link tokens for this user
  await prisma.magicLinkToken.deleteMany({ where: { userId: user.id } });

  const token = generateSecureToken();
  const expiresAt = new Date(Date.now() + config.tokens.magicLinkExpiresMs);

  await prisma.magicLinkToken.create({
    data: { token, userId: user.id, expiresAt },
  });

  await sendMagicLinkEmail(normalizedEmail, token).catch(() => {/* silent */});
}

// ---------------------------------------------------------------------------
// Verify Magic Link
// ---------------------------------------------------------------------------

export interface MagicLinkResultSuccess {
  accessToken: string;
  refreshToken: string;
}

export interface MagicLinkResultMfaRequired {
  mfaRequired: true;
  mfaToken: string;
}

export type MagicLinkResult = MagicLinkResultSuccess | MagicLinkResultMfaRequired;

/**
 * Verify a magic link token and authenticate the user.
 * Automatically verifies the user's email if not already verified.
 * Returns access/refresh tokens, or an MFA challenge if MFA is enabled.
 */
export async function verifyMagicLink(token: string): Promise<MagicLinkResult> {
  const record = await prisma.magicLinkToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    throw new Error('INVALID_TOKEN');
  }

  // Mark the token as used
  await prisma.magicLinkToken.update({
    where: { token },
    data: { usedAt: new Date() },
  });

  // Auto-verify email if not already verified
  if (!record.user.isEmailVerified) {
    await prisma.user.update({
      where: { id: record.userId },
      data: { isEmailVerified: true },
    });
  }

  // If MFA is enabled, return an MFA challenge
  if (record.user.mfaEnabled) {
    const mfaToken = await createMfaToken(record.userId);
    return { mfaRequired: true, mfaToken };
  }

  return issueTokens(record.userId);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function issueTokens(userId: string): Promise<MagicLinkResultSuccess> {
  const accessToken = generateAccessToken(userId);
  const { token: refreshToken } = generateRefreshToken(userId);

  const expiresAt = new Date(
    Date.now() + parseDurationMs(config.jwt.refreshExpiresIn),
  );

  await prisma.refreshToken.create({
    data: { token: refreshToken, userId, expiresAt },
  });

  return { accessToken, refreshToken };
}
