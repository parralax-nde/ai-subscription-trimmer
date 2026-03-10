import argon2 from 'argon2';
import prisma from '../config/database';
import { config } from '../config';
import { generateSecureToken } from '../utils/crypto';
import { generateAccessToken, generateRefreshToken, parseDurationMs } from '../utils/tokens';
import { sendVerificationEmail, sendPasswordResetEmail } from './emailService';
import { createMfaToken } from './mfaService';

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/**
 * Register a new user with email and password.
 * Returns a generic success message regardless of whether the email already
 * exists to prevent user enumeration attacks.
 */
export async function registerUser(email: string, password: string): Promise<void> {
  const normalizedEmail = email.toLowerCase().trim();

  const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (existing) {
    // Do not reveal that the email is already registered.
    // Still send the verification email so legitimate users are not confused.
    if (!existing.isEmailVerified) {
      const token = await createEmailVerificationToken(existing.id);
      await sendVerificationEmail(normalizedEmail, token).catch(() => {/* silent */});
    }
    return;
  }

  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,   // 64 MiB
    timeCost: 3,
    parallelism: 4,
  });

  const user = await prisma.user.create({
    data: { email: normalizedEmail, passwordHash },
  });

  const token = await createEmailVerificationToken(user.id);
  await sendVerificationEmail(normalizedEmail, token).catch(() => {/* silent */});
}

// ---------------------------------------------------------------------------
// Email Verification
// ---------------------------------------------------------------------------

async function createEmailVerificationToken(userId: string): Promise<string> {
  // Invalidate any existing tokens for this user
  await prisma.emailVerificationToken.deleteMany({ where: { userId } });

  const token = generateSecureToken();
  const expiresAt = new Date(Date.now() + config.tokens.emailVerificationExpiresMs);

  await prisma.emailVerificationToken.create({
    data: { token, userId, expiresAt },
  });

  return token;
}

/**
 * Verify a user's email using the token sent to them.
 */
export async function verifyEmail(token: string): Promise<void> {
  const record = await prisma.emailVerificationToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!record || record.expiresAt < new Date()) {
    throw new Error('INVALID_TOKEN');
  }

  if (record.user.isEmailVerified) {
    // Already verified — just clean up and succeed silently
    await prisma.emailVerificationToken.delete({ where: { token } });
    return;
  }

  await prisma.$transaction([
    prisma.user.update({
      where: { id: record.userId },
      data: { isEmailVerified: true },
    }),
    prisma.emailVerificationToken.delete({ where: { token } }),
  ]);
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export interface LoginResultSuccess {
  accessToken: string;
  refreshToken: string;
}

export interface LoginResultMfaRequired {
  mfaRequired: true;
  mfaToken: string;
}

export type LoginResult = LoginResultSuccess | LoginResultMfaRequired;

/**
 * Authenticate a user with email and password.
 * Returns access and refresh tokens when MFA is not enabled.
 * Returns an MFA challenge token when MFA is enabled.
 * Throws 'INVALID_CREDENTIALS' for any authentication failure to prevent
 * user enumeration attacks.
 */
export async function loginUser(
  email: string,
  password: string,
): Promise<LoginResult> {
  const normalizedEmail = email.toLowerCase().trim();
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  // Use a timing-safe comparison even when the user doesn't exist
  // by verifying against a dummy hash if needed.
  const DUMMY_HASH =
    '$argon2id$v=19$m=65536,t=3,p=4$dummysaltdummysaltdummysa$dummyhashvaluefortimingatttack';

  // Social-only users (no password set) cannot log in with a password.
  // Use DUMMY_HASH to keep timing consistent and avoid revealing account existence.
  const hashToVerify = user?.passwordHash ?? DUMMY_HASH;

  let passwordValid = false;
  try {
    passwordValid = await argon2.verify(hashToVerify, password);
  } catch {
    passwordValid = false;
  }

  if (!user || !passwordValid) {
    throw new Error('INVALID_CREDENTIALS');
  }

  if (!user.isEmailVerified) {
    throw new Error('EMAIL_NOT_VERIFIED');
  }

  if (user.mfaEnabled) {
    const mfaToken = await createMfaToken(user.id);
    return { mfaRequired: true, mfaToken };
  }

  return issueTokens(user.id);
}

// ---------------------------------------------------------------------------
// Token Refresh
// ---------------------------------------------------------------------------

/**
 * Rotate refresh token — revoke the old one and issue new access + refresh tokens.
 */
export async function refreshTokens(refreshToken: string): Promise<LoginResultSuccess> {
  const { verifyRefreshToken } = await import('../utils/tokens');

  let payload: { sub: string; jti: string };
  try {
    payload = verifyRefreshToken(refreshToken) as { sub: string; jti: string };
  } catch {
    throw new Error('INVALID_TOKEN');
  }

  const stored = await prisma.refreshToken.findUnique({ where: { token: refreshToken } });

  if (!stored || stored.revokedAt || stored.expiresAt < new Date()) {
    // Possible token reuse — revoke all tokens for this user (security measure)
    if (stored) {
      await prisma.refreshToken.updateMany({
        where: { userId: stored.userId },
        data: { revokedAt: new Date() },
      });
    }
    throw new Error('INVALID_TOKEN');
  }

  // Revoke the used refresh token
  await prisma.refreshToken.update({
    where: { token: refreshToken },
    data: { revokedAt: new Date() },
  });

  return issueTokens(payload.sub);
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

/**
 * Revoke the provided refresh token, effectively logging the user out.
 */
export async function logoutUser(refreshToken: string): Promise<void> {
  await prisma.refreshToken.updateMany({
    where: { token: refreshToken, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

// ---------------------------------------------------------------------------
// Forgot / Reset Password
// ---------------------------------------------------------------------------

/**
 * Initiate a password reset flow.
 * Always returns successfully to prevent user enumeration.
 */
export async function forgotPassword(email: string): Promise<void> {
  const normalizedEmail = email.toLowerCase().trim();
  const user = await prisma.user.findUnique({ where: { email: normalizedEmail } });

  if (!user) {
    // Return silently — do not reveal whether the email exists
    return;
  }

  // Invalidate existing reset tokens
  await prisma.passwordResetToken.deleteMany({ where: { userId: user.id } });

  const token = generateSecureToken();
  const expiresAt = new Date(Date.now() + config.tokens.passwordResetExpiresMs);

  await prisma.passwordResetToken.create({
    data: { token, userId: user.id, expiresAt },
  });

  await sendPasswordResetEmail(normalizedEmail, token).catch(() => {/* silent */});
}

/**
 * Reset a user's password using a valid reset token.
 */
export async function resetPassword(token: string, newPassword: string): Promise<void> {
  const record = await prisma.passwordResetToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!record || record.usedAt || record.expiresAt < new Date()) {
    throw new Error('INVALID_TOKEN');
  }

  const passwordHash = await argon2.hash(newPassword, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  await prisma.$transaction([
    prisma.user.update({
      where: { id: record.userId },
      data: { passwordHash },
    }),
    prisma.passwordResetToken.update({
      where: { token },
      data: { usedAt: new Date() },
    }),
    // Revoke all existing refresh tokens on password change
    prisma.refreshToken.updateMany({
      where: { userId: record.userId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function issueTokens(userId: string): Promise<LoginResultSuccess> {
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
