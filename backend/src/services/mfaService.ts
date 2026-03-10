import { authenticator } from '@otplib/preset-default';
import QRCode from 'qrcode';
import argon2 from 'argon2';
import crypto from 'crypto';
import prisma from '../config/database';
import { generateSecureToken } from '../utils/crypto';
import { generateAccessToken, generateRefreshToken, parseDurationMs } from '../utils/tokens';
import { config } from '../config';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BACKUP_CODE_COUNT = 10;
const BACKUP_CODE_LENGTH = 8;
const MFA_TOKEN_EXPIRES_MS = 5 * 60 * 1000; // 5 minutes
const APP_NAME = 'AI Subscription Trimmer';

const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 4,
} as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function generateBackupCode(): string {
  return crypto.randomBytes(BACKUP_CODE_LENGTH / 2).toString('hex').toUpperCase();
}

async function hashBackupCode(code: string): Promise<string> {
  return argon2.hash(code, ARGON2_OPTIONS);
}

async function verifyBackupCode(code: string, hash: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, code);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// TOTP Setup
// ---------------------------------------------------------------------------

/**
 * Initiate TOTP setup for a user.
 * Generates a new secret, stores it (unenabled), and returns a QR code data URL.
 * The user must call verifyAndEnableTotp to complete setup.
 */
export async function setupTotp(userId: string): Promise<{
  secret: string;
  qrCodeDataUrl: string;
  otpauthUrl: string;
}> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  if (user.mfaEnabled) {
    throw new Error('MFA_ALREADY_ENABLED');
  }

  const secret = authenticator.generateSecret();

  // Store the secret (not yet enabled) so it can be verified
  await prisma.user.update({
    where: { id: userId },
    data: { mfaTotpSecret: secret },
  });

  const otpauthUrl = authenticator.keyuri(user.email, APP_NAME, secret);
  const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);

  return { secret, qrCodeDataUrl, otpauthUrl };
}

// ---------------------------------------------------------------------------
// Enable TOTP
// ---------------------------------------------------------------------------

/**
 * Verify the TOTP code and enable MFA for the user.
 * Returns plaintext backup codes (shown once to the user).
 */
export async function verifyAndEnableTotp(
  userId: string,
  totpCode: string,
): Promise<string[]> {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  if (user.mfaEnabled) {
    throw new Error('MFA_ALREADY_ENABLED');
  }

  if (!user.mfaTotpSecret) {
    throw new Error('MFA_SETUP_NOT_INITIATED');
  }

  const isValid = authenticator.verify({ token: totpCode, secret: user.mfaTotpSecret });
  if (!isValid) {
    throw new Error('INVALID_TOTP_CODE');
  }

  // Generate backup codes
  const plainCodes: string[] = [];
  const hashPromises: Promise<string>[] = [];
  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const code = generateBackupCode();
    plainCodes.push(code);
    hashPromises.push(hashBackupCode(code));
  }
  const hashes = await Promise.all(hashPromises);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: true },
    }),
    // Remove any existing backup codes
    prisma.mfaBackupCode.deleteMany({ where: { userId } }),
    ...hashes.map((codeHash) =>
      prisma.mfaBackupCode.create({ data: { userId, codeHash } }),
    ),
  ]);

  return plainCodes;
}

// ---------------------------------------------------------------------------
// Disable MFA
// ---------------------------------------------------------------------------

/**
 * Disable MFA for a user after verifying their current TOTP code or a backup code.
 */
export async function disableMfa(userId: string, code: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { mfaBackupCodes: { where: { usedAt: null } } },
  });

  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  if (!user.mfaEnabled) {
    throw new Error('MFA_NOT_ENABLED');
  }

  const valid = await verifyCode(user, code);
  if (!valid) {
    throw new Error('INVALID_MFA_CODE');
  }

  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { mfaEnabled: false, mfaTotpSecret: null },
    }),
    prisma.mfaBackupCode.deleteMany({ where: { userId } }),
    // Invalidate any pending MFA login tokens
    prisma.mfaToken.deleteMany({ where: { userId } }),
  ]);
}

// ---------------------------------------------------------------------------
// Regenerate Backup Codes
// ---------------------------------------------------------------------------

/**
 * Regenerate backup codes after verifying the current TOTP code.
 * Returns new plaintext backup codes.
 */
export async function regenerateBackupCodes(
  userId: string,
  totpCode: string,
): Promise<string[]> {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user || !user.mfaEnabled || !user.mfaTotpSecret) {
    throw new Error('MFA_NOT_ENABLED');
  }

  const isValid = authenticator.verify({ token: totpCode, secret: user.mfaTotpSecret });
  if (!isValid) {
    throw new Error('INVALID_TOTP_CODE');
  }

  const plainCodes: string[] = [];
  const hashPromises: Promise<string>[] = [];
  for (let i = 0; i < BACKUP_CODE_COUNT; i++) {
    const code = generateBackupCode();
    plainCodes.push(code);
    hashPromises.push(hashBackupCode(code));
  }
  const hashes = await Promise.all(hashPromises);

  await prisma.$transaction([
    prisma.mfaBackupCode.deleteMany({ where: { userId } }),
    ...hashes.map((codeHash) =>
      prisma.mfaBackupCode.create({ data: { userId, codeHash } }),
    ),
  ]);

  return plainCodes;
}

// ---------------------------------------------------------------------------
// MFA Login Verification
// ---------------------------------------------------------------------------

export interface MfaLoginResult {
  accessToken: string;
  refreshToken: string;
}

/**
 * Create a short-lived MFA challenge token after successful password verification.
 * Used when MFA is required during login.
 */
export async function createMfaToken(userId: string): Promise<string> {
  // Clean up expired/used tokens for this user
  await prisma.mfaToken.deleteMany({
    where: {
      userId,
      OR: [{ expiresAt: { lt: new Date() } }, { usedAt: { not: null } }],
    },
  });

  const token = generateSecureToken();
  const expiresAt = new Date(Date.now() + MFA_TOKEN_EXPIRES_MS);

  await prisma.mfaToken.create({ data: { token, userId, expiresAt } });

  return token;
}

/**
 * Verify a TOTP code or backup code using a previously issued MFA challenge token.
 * On success, the MFA token is consumed and access/refresh tokens are returned.
 */
export async function verifyMfaLogin(
  mfaToken: string,
  code: string,
): Promise<MfaLoginResult> {
  const mfaRecord = await prisma.mfaToken.findUnique({
    where: { token: mfaToken },
    include: {
      user: {
        include: { mfaBackupCodes: { where: { usedAt: null } } },
      },
    },
  });

  if (!mfaRecord || mfaRecord.usedAt || mfaRecord.expiresAt < new Date()) {
    throw new Error('INVALID_MFA_TOKEN');
  }

  const { user } = mfaRecord;

  if (!user.mfaEnabled || !user.mfaTotpSecret) {
    throw new Error('MFA_NOT_ENABLED');
  }

  const codeVerification = await verifyCode(user, code);
  if (!codeVerification) {
    throw new Error('INVALID_MFA_CODE');
  }

  // Mark the MFA token as used
  await prisma.mfaToken.update({
    where: { token: mfaToken },
    data: { usedAt: new Date() },
  });

  return issueTokens(user.id);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

type UserWithBackupCodes = {
  mfaTotpSecret: string | null;
  mfaBackupCodes: Array<{ id: string; codeHash: string }>;
};

/**
 * Verify a code against the user's TOTP secret or unused backup codes.
 * If a backup code matches, it is marked as used.
 */
async function verifyCode(user: UserWithBackupCodes, code: string): Promise<boolean> {
  // Try TOTP first
  if (user.mfaTotpSecret) {
    const totpValid = authenticator.verify({ token: code, secret: user.mfaTotpSecret });
    if (totpValid) {
      return true;
    }
  }

  // Try backup codes
  for (const backupCode of user.mfaBackupCodes) {
    const matches = await verifyBackupCode(code, backupCode.codeHash);
    if (matches) {
      // Mark backup code as used
      await prisma.mfaBackupCode.update({
        where: { id: backupCode.id },
        data: { usedAt: new Date() },
      });
      return true;
    }
  }

  return false;
}

async function issueTokens(userId: string): Promise<MfaLoginResult> {
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
