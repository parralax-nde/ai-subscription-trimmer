import argon2 from 'argon2';
import prisma from '../config/database';
import { config } from '../config';
import { generateSecureToken } from '../utils/crypto';
import { sendEmailChangeVerificationEmail } from './emailService';

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

export interface UserProfile {
  id: string;
  email: string;
  name: string | null;
  phoneNumber: string | null;
  phoneVerified: boolean;
  isEmailVerified: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface UpdateProfileInput {
  name?: string | null;
  phoneNumber?: string | null;
  email?: string;
}

/**
 * Get the authenticated user's profile.
 */
export async function getProfile(userId: string): Promise<UserProfile> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      name: true,
      phoneNumber: true,
      phoneVerified: true,
      isEmailVerified: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  return user;
}

/**
 * Update the authenticated user's profile.
 * - name and phoneNumber are updated immediately.
 * - Changing phoneNumber resets phoneVerified to false.
 * - email changes are not applied immediately; a verification email is sent
 *   to the new address and the change only takes effect when confirmed.
 * Returns an object indicating whether an email change was requested.
 */
export async function updateProfile(
  userId: string,
  input: UpdateProfileInput,
): Promise<{ emailChangeRequested: boolean }> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  const updateData: Record<string, unknown> = {};
  let emailChangeRequested = false;

  if (input.name !== undefined) {
    updateData.name = input.name;
  }

  if (input.phoneNumber !== undefined) {
    if (input.phoneNumber !== null) {
      // Check uniqueness against other users
      const existing = await prisma.user.findUnique({
        where: { phoneNumber: input.phoneNumber },
      });
      if (existing && existing.id !== userId) {
        throw new Error('PHONE_NUMBER_TAKEN');
      }
    }
    updateData.phoneNumber = input.phoneNumber;
    updateData.phoneVerified = false;
  }

  if (input.email !== undefined) {
    const normalizedEmail = input.email.toLowerCase().trim();

    if (normalizedEmail !== user.email) {
      // Check that the new email is not already in use
      const existing = await prisma.user.findUnique({
        where: { email: normalizedEmail },
      });
      if (existing) {
        throw new Error('EMAIL_TAKEN');
      }

      // Invalidate any pending email change tokens for this user
      await prisma.emailChangeToken.deleteMany({ where: { userId } });

      const token = generateSecureToken();
      const expiresAt = new Date(Date.now() + config.tokens.emailChangeExpiresMs);

      await prisma.emailChangeToken.create({
        data: { token, userId, newEmail: normalizedEmail, expiresAt },
      });

      await sendEmailChangeVerificationEmail(normalizedEmail, token).catch((err) => {
        console.error('[profile] failed to send email change verification email:', err);
      });
      emailChangeRequested = true;
    }
  }

  if (Object.keys(updateData).length > 0) {
    await prisma.user.update({ where: { id: userId }, data: updateData });
  }

  return { emailChangeRequested };
}

/**
 * Confirm an email change using the token sent to the new email address.
 */
export async function confirmEmailChange(token: string): Promise<void> {
  const record = await prisma.emailChangeToken.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!record || record.expiresAt < new Date()) {
    throw new Error('INVALID_TOKEN');
  }

  // Ensure the new email is still available
  const existing = await prisma.user.findUnique({
    where: { email: record.newEmail },
  });
  if (existing && existing.id !== record.userId) {
    throw new Error('EMAIL_TAKEN');
  }

  await prisma.$transaction([
    prisma.user.update({
      where: { id: record.userId },
      data: { email: record.newEmail, isEmailVerified: true },
    }),
    prisma.emailChangeToken.delete({ where: { token } }),
  ]);
}

// ---------------------------------------------------------------------------
// Preferences
// ---------------------------------------------------------------------------

export interface UserPreferencesData {
  emailNotifications: boolean;
  theme: string;
  language: string;
}

/**
 * Get the authenticated user's preferences, creating defaults if they don't exist.
 */
export async function getPreferences(userId: string): Promise<UserPreferencesData> {
  let prefs = await prisma.userPreferences.findUnique({ where: { userId } });

  if (!prefs) {
    prefs = await prisma.userPreferences.create({
      data: { userId },
    });
  }

  return {
    emailNotifications: prefs.emailNotifications,
    theme: prefs.theme,
    language: prefs.language,
  };
}

/**
 * Update the authenticated user's preferences.
 */
export async function updatePreferences(
  userId: string,
  input: Partial<UserPreferencesData>,
): Promise<UserPreferencesData> {
  const prefs = await prisma.userPreferences.upsert({
    where: { userId },
    create: { userId, ...input },
    update: input,
  });

  return {
    emailNotifications: prefs.emailNotifications,
    theme: prefs.theme,
    language: prefs.language,
  };
}

// ---------------------------------------------------------------------------
// Account Deactivation & Deletion
// ---------------------------------------------------------------------------

/**
 * Verify password for a sensitive operation, or skip if the user has no password.
 * Throws 'INVALID_CREDENTIALS' when the supplied password is wrong.
 */
async function verifyPasswordIfSet(user: { passwordHash: string | null }, password?: string): Promise<void> {
  if (!user.passwordHash) {
    // Social-only account — no password to verify; authentication alone is sufficient.
    return;
  }

  const hashToVerify = user.passwordHash;
  let valid = false;
  try {
    valid = await argon2.verify(hashToVerify, password ?? '');
  } catch {
    valid = false;
  }

  if (!valid) {
    throw new Error('INVALID_CREDENTIALS');
  }
}

/**
 * Soft-deactivate the authenticated user's account.
 * - Sets deactivatedAt timestamp (prevents future logins).
 * - Revokes all active refresh tokens (forces logout everywhere).
 * For password-based accounts the current password must be supplied.
 */
export async function deactivateAccount(userId: string, password?: string): Promise<void> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  if (user.deactivatedAt) {
    throw new Error('ACCOUNT_ALREADY_DEACTIVATED');
  }

  await verifyPasswordIfSet(user, password);

  await prisma.$transaction([
    prisma.user.update({
      where: { id: userId },
      data: { deactivatedAt: new Date() },
    }),
    prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    }),
  ]);
}

/**
 * Permanently delete the authenticated user's account and all associated data.
 * Cascading deletes in the database handle related records automatically.
 * For password-based accounts the current password must be supplied.
 */
export async function deleteAccount(userId: string, password?: string): Promise<void> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  await verifyPasswordIfSet(user, password);

  await prisma.user.delete({ where: { id: userId } });
}

// ---------------------------------------------------------------------------
// Data Export
// ---------------------------------------------------------------------------

export interface UserDataExport {
  exportedAt: string;
  profile: {
    id: string;
    email: string;
    name: string | null;
    phoneNumber: string | null;
    phoneVerified: boolean;
    isEmailVerified: boolean;
    mfaEnabled: boolean;
    createdAt: string;
    updatedAt: string;
    deactivatedAt: string | null;
  };
  preferences: UserPreferencesData | null;
}

/**
 * Export all personal data for the authenticated user in a machine-readable format.
 * Returns a structured JSON object suitable for download.
 */
export async function exportData(userId: string): Promise<UserDataExport> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      name: true,
      phoneNumber: true,
      phoneVerified: true,
      isEmailVerified: true,
      mfaEnabled: true,
      createdAt: true,
      updatedAt: true,
      deactivatedAt: true,
      preferences: {
        select: {
          emailNotifications: true,
          theme: true,
          language: true,
        },
      },
    },
  });

  if (!user) {
    throw new Error('USER_NOT_FOUND');
  }

  return {
    exportedAt: new Date().toISOString(),
    profile: {
      id: user.id,
      email: user.email,
      name: user.name,
      phoneNumber: user.phoneNumber,
      phoneVerified: user.phoneVerified,
      isEmailVerified: user.isEmailVerified,
      mfaEnabled: user.mfaEnabled,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
      deactivatedAt: user.deactivatedAt ? user.deactivatedAt.toISOString() : null,
    },
    preferences: user.preferences
      ? {
          emailNotifications: user.preferences.emailNotifications,
          theme: user.preferences.theme,
          language: user.preferences.language,
        }
      : null,
  };
}
