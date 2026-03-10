import crypto from 'crypto';
import prisma from '../config/database';
import { config } from '../config';
import { generateSecureToken } from '../utils/crypto';
import { generateAccessToken, generateRefreshToken, parseDurationMs } from '../utils/tokens';

// ---------------------------------------------------------------------------
// In-memory challenge store (short-lived, keyed by credentialId)
// ---------------------------------------------------------------------------

interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

const pendingChallenges = new Map<string, ChallengeEntry>();

function cleanExpiredChallenges(): void {
  const now = Date.now();
  for (const [key, entry] of pendingChallenges) {
    if (entry.expiresAt < now) {
      pendingChallenges.delete(key);
    }
  }
}

// ---------------------------------------------------------------------------
// Register Biometric Credential
// ---------------------------------------------------------------------------

/**
 * Register a biometric credential for the authenticated user.
 * Stores the public key from the device's biometric-protected key pair.
 * If a credential already exists for the same device, it is replaced.
 */
export async function registerBiometric(
  userId: string,
  publicKey: string,
  deviceId: string,
  deviceName?: string,
): Promise<{ credentialId: string }> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  const credentialId = generateSecureToken();

  // Upsert: replace existing credential for same user+device
  await prisma.biometricCredential.upsert({
    where: {
      userId_deviceId: { userId, deviceId },
    },
    update: {
      credentialId,
      publicKey,
      deviceName: deviceName ?? null,
    },
    create: {
      credentialId,
      publicKey,
      deviceId,
      deviceName: deviceName ?? null,
      userId,
    },
  });

  return { credentialId };
}

// ---------------------------------------------------------------------------
// Generate Challenge
// ---------------------------------------------------------------------------

/**
 * Generate a time-limited challenge for biometric authentication.
 * The mobile client must sign this challenge with the biometric-protected private key.
 */
export async function generateChallenge(credentialId: string): Promise<{ challenge: string }> {
  const credential = await prisma.biometricCredential.findUnique({
    where: { credentialId },
  });

  if (!credential) {
    throw new Error('CREDENTIAL_NOT_FOUND');
  }

  cleanExpiredChallenges();

  const challenge = generateSecureToken();
  const expiresAt = Date.now() + config.tokens.biometricChallengeExpiresMs;

  pendingChallenges.set(credentialId, { challenge, expiresAt });

  return { challenge };
}

// ---------------------------------------------------------------------------
// Verify Biometric
// ---------------------------------------------------------------------------

export interface BiometricVerifyResult {
  accessToken: string;
  refreshToken: string;
}

/**
 * Verify a biometric authentication attempt.
 * The client signs the challenge with their biometric-protected private key.
 * The backend verifies the signature using the stored public key.
 */
export async function verifyBiometric(
  credentialId: string,
  signature: string,
): Promise<BiometricVerifyResult> {
  const credential = await prisma.biometricCredential.findUnique({
    where: { credentialId },
    include: { user: true },
  });

  if (!credential) {
    throw new Error('CREDENTIAL_NOT_FOUND');
  }

  cleanExpiredChallenges();

  const entry = pendingChallenges.get(credentialId);
  if (!entry || entry.expiresAt < Date.now()) {
    pendingChallenges.delete(credentialId);
    throw new Error('CHALLENGE_EXPIRED');
  }

  // Verify the signature against the stored public key
  let isValid = false;
  try {
    const verifier = crypto.createVerify('SHA256');
    verifier.update(entry.challenge);
    verifier.end();
    isValid = verifier.verify(credential.publicKey, signature, 'base64');
  } catch {
    isValid = false;
  }

  // Remove the challenge regardless of outcome (single-use)
  pendingChallenges.delete(credentialId);

  if (!isValid) {
    throw new Error('INVALID_SIGNATURE');
  }

  return issueTokens(credential.userId);
}

// ---------------------------------------------------------------------------
// List Credentials
// ---------------------------------------------------------------------------

export interface CredentialInfo {
  credentialId: string;
  deviceId: string;
  deviceName: string | null;
  createdAt: Date;
}

/**
 * List all biometric credentials for the authenticated user.
 */
export async function listCredentials(userId: string): Promise<CredentialInfo[]> {
  const credentials = await prisma.biometricCredential.findMany({
    where: { userId },
    select: {
      credentialId: true,
      deviceId: true,
      deviceName: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });

  return credentials;
}

// ---------------------------------------------------------------------------
// Remove Credential
// ---------------------------------------------------------------------------

/**
 * Remove a biometric credential for the authenticated user.
 */
export async function removeCredential(
  userId: string,
  credentialId: string,
): Promise<void> {
  const credential = await prisma.biometricCredential.findUnique({
    where: { credentialId },
  });

  if (!credential || credential.userId !== userId) {
    throw new Error('CREDENTIAL_NOT_FOUND');
  }

  await prisma.biometricCredential.delete({
    where: { credentialId },
  });

  // Clean up any pending challenges for this credential
  pendingChallenges.delete(credentialId);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function issueTokens(userId: string): Promise<BiometricVerifyResult> {
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

// Exported for testing only
export { pendingChallenges as _pendingChallenges };
