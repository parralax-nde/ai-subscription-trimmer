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
