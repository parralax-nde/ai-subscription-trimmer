import { Router, Response } from 'express';
import { z } from 'zod';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth';
import { validate } from '../middleware/validate';
import {
  getProfile,
  updateProfile,
  confirmEmailChange,
  getPreferences,
  updatePreferences,
  deactivateAccount,
  deleteAccount,
  exportData,
} from '../services/profileService';

const router = Router();

// ---------------------------------------------------------------------------
// Validation schemas
// ---------------------------------------------------------------------------

const updateProfileSchema = z
  .object({
    name: z
      .string()
      .min(1, 'Name must not be empty.')
      .max(100, 'Name must not exceed 100 characters.')
      .nullable()
      .optional(),
    phoneNumber: z
      .string()
      .regex(
        /^\+?[1-9]\d{6,14}$/,
        'Phone number must be in E.164 format (e.g. +12125551234).',
      )
      .nullable()
      .optional(),
    email: z
      .string()
      .email('Invalid email address.')
      .max(254, 'Email must not exceed 254 characters.')
      .optional(),
  })
  .strict();

const confirmEmailChangeSchema = z.object({
  token: z.string().min(1, 'Token is required.'),
});

const updatePreferencesSchema = z
  .object({
    emailNotifications: z.boolean().optional(),
    theme: z.enum(['light', 'dark', 'system'], {
      errorMap: () => ({ message: 'Theme must be one of: light, dark, system.' }),
    }).optional(),
    language: z
      .string()
      .min(2, 'Language must be a valid language code.')
      .max(10, 'Language code must not exceed 10 characters.')
      .optional(),
  })
  .strict();

const deactivateAccountSchema = z
  .object({
    password: z.string().optional(),
  })
  .strict();

const deleteAccountSchema = z
  .object({
    password: z.string().optional(),
  })
  .strict();

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/**
 * GET /api/profile
 * Returns the authenticated user's profile.
 */
router.get('/', requireAuth, async (req: AuthenticatedRequest, res: Response): Promise<void> => {
  try {
    const profile = await getProfile(req.userId!);
    res.status(200).json(profile);
  } catch (err) {
    if (err instanceof Error && err.message === 'USER_NOT_FOUND') {
      res.status(404).json({ error: 'User not found.' });
      return;
    }
    throw err;
  }
});

/**
 * PATCH /api/profile
 * Updates the authenticated user's name, phone number, or requests an email change.
 */
router.patch(
  '/',
  requireAuth,
  validate(updateProfileSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const result = await updateProfile(req.userId!, req.body as {
        name?: string | null;
        phoneNumber?: string | null;
        email?: string;
      });

      const message = result.emailChangeRequested
        ? 'Profile updated. A verification email has been sent to your new email address.'
        : 'Profile updated successfully.';

      res.status(200).json({ message });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'USER_NOT_FOUND') {
          res.status(404).json({ error: 'User not found.' });
          return;
        }
        if (err.message === 'EMAIL_TAKEN') {
          res.status(409).json({ error: 'Email address is already in use.' });
          return;
        }
        if (err.message === 'PHONE_NUMBER_TAKEN') {
          res.status(409).json({ error: 'Phone number is already in use.' });
          return;
        }
      }
      throw err;
    }
  },
);

/**
 * POST /api/profile/email/confirm-change
 * Confirms an email change using the token sent to the new address.
 */
router.post(
  '/email/confirm-change',
  validate(confirmEmailChangeSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      await confirmEmailChange(req.body.token as string);
      res.status(200).json({ message: 'Email address updated successfully.' });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'INVALID_TOKEN') {
          res.status(400).json({ error: 'Invalid or expired email change token.' });
          return;
        }
        if (err.message === 'EMAIL_TAKEN') {
          res.status(409).json({ error: 'Email address is already in use.' });
          return;
        }
      }
      throw err;
    }
  },
);

/**
 * GET /api/profile/preferences
 * Returns the authenticated user's preferences.
 */
router.get(
  '/preferences',
  requireAuth,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const prefs = await getPreferences(req.userId!);
    res.status(200).json(prefs);
  },
);

/**
 * PATCH /api/profile/preferences
 * Updates the authenticated user's preferences.
 */
router.patch(
  '/preferences',
  requireAuth,
  validate(updatePreferencesSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    const prefs = await updatePreferences(req.userId!, req.body as {
      emailNotifications?: boolean;
      theme?: string;
      language?: string;
    });
    res.status(200).json(prefs);
  },
);

/**
 * POST /api/profile/deactivate
 * Soft-deactivates the authenticated user's account.
 * Sets deactivatedAt and revokes all active sessions.
 * For password-based accounts, the current password must be supplied.
 * Warning: this action will prevent future logins until an administrator
 * re-activates the account.
 */
router.post(
  '/deactivate',
  requireAuth,
  validate(deactivateAccountSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      await deactivateAccount(req.userId!, req.body.password as string | undefined);
      res.status(200).json({
        message: 'Your account has been deactivated. All active sessions have been terminated.',
      });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'USER_NOT_FOUND') {
          res.status(404).json({ error: 'User not found.' });
          return;
        }
        if (err.message === 'ACCOUNT_ALREADY_DEACTIVATED') {
          res.status(409).json({ error: 'Account is already deactivated.' });
          return;
        }
        if (err.message === 'INVALID_CREDENTIALS') {
          res.status(401).json({ error: 'Incorrect password.' });
          return;
        }
      }
      throw err;
    }
  },
);

/**
 * DELETE /api/profile
 * Permanently deletes the authenticated user's account and all associated data.
 * This action is irreversible. For password-based accounts, the current password
 * must be supplied as confirmation.
 */
router.delete(
  '/',
  requireAuth,
  validate(deleteAccountSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      await deleteAccount(req.userId!, req.body.password as string | undefined);
      res.status(200).json({
        message: 'Your account and all associated data have been permanently deleted.',
      });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'USER_NOT_FOUND') {
          res.status(404).json({ error: 'User not found.' });
          return;
        }
        if (err.message === 'INVALID_CREDENTIALS') {
          res.status(401).json({ error: 'Incorrect password.' });
          return;
        }
      }
      throw err;
    }
  },
);

/**
 * GET /api/profile/export
 * Returns the authenticated user's personal data as a JSON object,
 * suitable for download in compliance with data privacy regulations.
 */
router.get(
  '/export',
  requireAuth,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const data = await exportData(req.userId!);
      res
        .status(200)
        .setHeader('Content-Disposition', 'attachment; filename="my-data.json"')
        .json(data);
    } catch (err) {
      if (err instanceof Error && err.message === 'USER_NOT_FOUND') {
        res.status(404).json({ error: 'User not found.' });
        return;
      }
      throw err;
    }
  },
);

export default router;
