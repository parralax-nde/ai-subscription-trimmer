import { Router, Request, Response } from 'express';
import { authRateLimiter } from '../middleware/rateLimiter';
import { validate } from '../middleware/validate';
import {
  registerSchema,
  loginSchema,
  verifyEmailSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  refreshTokenSchema,
  logoutSchema,
  mfaVerifySetupSchema,
  mfaDisableSchema,
  mfaVerifyLoginSchema,
  mfaRegenerateBackupCodesSchema,
  magicLinkSendSchema,
  magicLinkVerifySchema,
  biometricRegisterSchema,
  biometricChallengeSchema,
  biometricVerifySchema,
} from './authSchemas';
import {
  registerUser,
  verifyEmail,
  loginUser,
  refreshTokens,
  logoutUser,
  forgotPassword,
  resetPassword,
} from '../services/authService';
import {
  setupTotp,
  verifyAndEnableTotp,
  disableMfa,
  verifyMfaLogin,
  regenerateBackupCodes,
} from '../services/mfaService';
import { sendMagicLink, verifyMagicLink } from '../services/magicLinkService';
import {
  registerBiometric,
  generateChallenge,
  verifyBiometric,
  listCredentials,
  removeCredential,
} from '../services/biometricService';
import { requireAuth, AuthenticatedRequest } from '../middleware/auth';

const router = Router();

// Apply strict rate limiting to all auth routes
router.use(authRateLimiter);

/**
 * POST /api/auth/register
 * Register a new user with email and password.
 * Sends a verification email. Response is always generic to prevent
 * user enumeration.
 */
router.post('/register', validate(registerSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    await registerUser(req.body.email, req.body.password);
    res.status(202).json({
      message: 'If that email is not already registered, you will receive a verification email shortly.',
    });
  } catch (err) {
    console.error('[auth] register error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * POST /api/auth/verify-email
 * Verify a user's email address using the token from the verification email.
 */
router.post('/verify-email', validate(verifyEmailSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    await verifyEmail(req.body.token);
    res.status(200).json({ message: 'Email verified successfully. You can now log in.' });
  } catch (err) {
    if (err instanceof Error && err.message === 'INVALID_TOKEN') {
      res.status(400).json({ error: 'Invalid or expired verification token.' });
      return;
    }
    console.error('[auth] verify-email error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * POST /api/auth/login
 * Authenticate a user with email and password.
 * Returns JWT access and refresh tokens, or an MFA challenge token if MFA is enabled.
 */
router.post('/login', validate(loginSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    const result = await loginUser(req.body.email, req.body.password);
    if ('mfaRequired' in result) {
      res.status(200).json({ mfaRequired: true, mfaToken: result.mfaToken });
    } else {
      res.status(200).json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
    }
  } catch (err) {
    if (err instanceof Error) {
      if (err.message === 'INVALID_CREDENTIALS') {
        res.status(401).json({ error: 'Invalid email or password.' });
        return;
      }
      if (err.message === 'ACCOUNT_DEACTIVATED') {
        res.status(403).json({ error: 'This account has been deactivated.' });
        return;
      }
      if (err.message === 'EMAIL_NOT_VERIFIED') {
        res.status(403).json({ error: 'Please verify your email address before logging in.' });
        return;
      }
    }
    console.error('[auth] login error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * POST /api/auth/refresh
 * Exchange a valid refresh token for new access and refresh tokens.
 */
router.post('/refresh', validate(refreshTokenSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    const result = await refreshTokens(req.body.refreshToken);
    res.status(200).json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (err) {
    if (err instanceof Error && err.message === 'INVALID_TOKEN') {
      res.status(401).json({ error: 'Invalid or expired refresh token.' });
      return;
    }
    console.error('[auth] refresh error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * POST /api/auth/logout
 * Revoke the provided refresh token.
 */
router.post('/logout', validate(logoutSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    await logoutUser(req.body.refreshToken);
    res.status(200).json({ message: 'Logged out successfully.' });
  } catch (err) {
    console.error('[auth] logout error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * POST /api/auth/forgot-password
 * Initiate password reset. Always returns a generic response.
 */
router.post('/forgot-password', validate(forgotPasswordSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    await forgotPassword(req.body.email);
    res.status(202).json({
      message: 'If that email is registered, you will receive a password reset email shortly.',
    });
  } catch (err) {
    console.error('[auth] forgot-password error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * POST /api/auth/reset-password
 * Reset a user's password using a valid reset token.
 */
router.post('/reset-password', validate(resetPasswordSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    await resetPassword(req.body.token, req.body.password);
    res.status(200).json({ message: 'Password reset successfully. You can now log in with your new password.' });
  } catch (err) {
    if (err instanceof Error && err.message === 'INVALID_TOKEN') {
      res.status(400).json({ error: 'Invalid or expired password reset token.' });
      return;
    }
    console.error('[auth] reset-password error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

// ---------------------------------------------------------------------------
// MFA — TOTP setup (requires authenticated user)
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/mfa/totp/setup
 * Initiate TOTP MFA setup. Returns the TOTP secret and a QR code data URL.
 * The user must scan the QR code and confirm with a valid code to enable MFA.
 */
router.post(
  '/mfa/totp/setup',
  requireAuth,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const result = await setupTotp(req.userId!);
      res.status(200).json(result);
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'MFA_ALREADY_ENABLED') {
          res.status(409).json({ error: 'MFA is already enabled for this account.' });
          return;
        }
        if (err.message === 'USER_NOT_FOUND') {
          res.status(404).json({ error: 'User not found.' });
          return;
        }
      }
      console.error('[auth] mfa/totp/setup error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * POST /api/auth/mfa/totp/enable
 * Verify the TOTP code from the authenticator app and enable MFA.
 * Returns one-time backup codes for account recovery.
 */
router.post(
  '/mfa/totp/enable',
  requireAuth,
  validate(mfaVerifySetupSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const backupCodes = await verifyAndEnableTotp(req.userId!, req.body.totpCode);
      res.status(200).json({
        message: 'MFA enabled successfully.',
        backupCodes,
      });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'INVALID_TOTP_CODE') {
          res.status(400).json({ error: 'Invalid TOTP code. Please try again.' });
          return;
        }
        if (err.message === 'MFA_ALREADY_ENABLED') {
          res.status(409).json({ error: 'MFA is already enabled for this account.' });
          return;
        }
        if (err.message === 'MFA_SETUP_NOT_INITIATED') {
          res.status(400).json({ error: 'MFA setup has not been initiated. Call /mfa/totp/setup first.' });
          return;
        }
      }
      console.error('[auth] mfa/totp/enable error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * POST /api/auth/mfa/disable
 * Disable MFA for the authenticated user.
 * Requires a valid TOTP code or backup code for confirmation.
 */
router.post(
  '/mfa/disable',
  requireAuth,
  validate(mfaDisableSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      await disableMfa(req.userId!, req.body.code);
      res.status(200).json({ message: 'MFA disabled successfully.' });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'INVALID_MFA_CODE') {
          res.status(400).json({ error: 'Invalid MFA code.' });
          return;
        }
        if (err.message === 'MFA_NOT_ENABLED') {
          res.status(409).json({ error: 'MFA is not enabled for this account.' });
          return;
        }
      }
      console.error('[auth] mfa/disable error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * POST /api/auth/mfa/backup-codes/regenerate
 * Regenerate backup codes. Existing backup codes are invalidated.
 * Requires a valid TOTP code for confirmation.
 */
router.post(
  '/mfa/backup-codes/regenerate',
  requireAuth,
  validate(mfaRegenerateBackupCodesSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const backupCodes = await regenerateBackupCodes(req.userId!, req.body.totpCode);
      res.status(200).json({
        message: 'Backup codes regenerated successfully.',
        backupCodes,
      });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'INVALID_TOTP_CODE') {
          res.status(400).json({ error: 'Invalid TOTP code. Please try again.' });
          return;
        }
        if (err.message === 'MFA_NOT_ENABLED') {
          res.status(409).json({ error: 'MFA is not enabled for this account.' });
          return;
        }
      }
      console.error('[auth] mfa/backup-codes/regenerate error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

// ---------------------------------------------------------------------------
// MFA — Login verification (uses challenge token, no auth middleware needed)
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/mfa/verify
 * Complete a login when MFA is enabled.
 * Provide the mfaToken from the login response and the current TOTP code or a backup code.
 * Returns access and refresh tokens on success.
 */
router.post(
  '/mfa/verify',
  validate(mfaVerifyLoginSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const result = await verifyMfaLogin(req.body.mfaToken, req.body.code);
      res.status(200).json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'INVALID_MFA_TOKEN') {
          res.status(401).json({ error: 'Invalid or expired MFA token.' });
          return;
        }
        if (err.message === 'INVALID_MFA_CODE') {
          res.status(401).json({ error: 'Invalid MFA code.' });
          return;
        }
      }
      console.error('[auth] mfa/verify error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

// ---------------------------------------------------------------------------
// Magic Link — Passwordless authentication
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/magic-link/send
 * Send a magic link to the user's email for passwordless login.
 * Response is always generic to prevent user enumeration.
 */
router.post(
  '/magic-link/send',
  validate(magicLinkSendSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      await sendMagicLink(req.body.email);
      res.status(202).json({
        message: 'If that email is registered or valid, you will receive a sign-in link shortly.',
      });
    } catch (err) {
      console.error('[auth] magic-link/send error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * POST /api/auth/magic-link/verify
 * Verify a magic link token and authenticate the user.
 * Returns JWT access and refresh tokens, or an MFA challenge token if MFA is enabled.
 */
router.post(
  '/magic-link/verify',
  validate(magicLinkVerifySchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const result = await verifyMagicLink(req.body.token);
      if ('mfaRequired' in result) {
        res.status(200).json({ mfaRequired: true, mfaToken: result.mfaToken });
      } else {
        res.status(200).json({
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
        });
      }
    } catch (err) {
      if (err instanceof Error && err.message === 'INVALID_TOKEN') {
        res.status(400).json({ error: 'Invalid or expired magic link token.' });
        return;
      }
      console.error('[auth] magic-link/verify error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

// ---------------------------------------------------------------------------
// Biometric Authentication
// ---------------------------------------------------------------------------

/**
 * POST /api/auth/biometric/register
 * Register a biometric credential for the authenticated user.
 * The client provides the public key from its biometric-protected key pair.
 */
router.post(
  '/biometric/register',
  requireAuth,
  validate(biometricRegisterSchema),
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const result = await registerBiometric(
        req.userId!,
        req.body.publicKey,
        req.body.deviceId,
        req.body.deviceName,
      );
      res.status(201).json({
        message: 'Biometric credential registered successfully.',
        credentialId: result.credentialId,
      });
    } catch (err) {
      if (err instanceof Error && err.message === 'USER_NOT_FOUND') {
        res.status(404).json({ error: 'User not found.' });
        return;
      }
      console.error('[auth] biometric/register error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * POST /api/auth/biometric/challenge
 * Generate a challenge for biometric authentication.
 * The client must sign this challenge with the biometric-protected private key.
 */
router.post(
  '/biometric/challenge',
  validate(biometricChallengeSchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const result = await generateChallenge(req.body.credentialId);
      res.status(200).json({ challenge: result.challenge });
    } catch (err) {
      if (err instanceof Error && err.message === 'CREDENTIAL_NOT_FOUND') {
        res.status(404).json({ error: 'Biometric credential not found.' });
        return;
      }
      console.error('[auth] biometric/challenge error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * POST /api/auth/biometric/verify
 * Verify a biometric authentication attempt.
 * The client signs the challenge with their biometric-protected private key.
 * Returns JWT access and refresh tokens on success.
 */
router.post(
  '/biometric/verify',
  validate(biometricVerifySchema),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const result = await verifyBiometric(
        req.body.credentialId,
        req.body.signature,
      );
      res.status(200).json({
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
      });
    } catch (err) {
      if (err instanceof Error) {
        if (err.message === 'CREDENTIAL_NOT_FOUND') {
          res.status(404).json({ error: 'Biometric credential not found.' });
          return;
        }
        if (err.message === 'CHALLENGE_EXPIRED') {
          res.status(401).json({ error: 'Challenge expired or not found. Request a new challenge.' });
          return;
        }
        if (err.message === 'INVALID_SIGNATURE') {
          res.status(401).json({ error: 'Invalid biometric signature.' });
          return;
        }
      }
      console.error('[auth] biometric/verify error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * GET /api/auth/biometric/credentials
 * List all biometric credentials for the authenticated user.
 */
router.get(
  '/biometric/credentials',
  requireAuth,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const credentials = await listCredentials(req.userId!);
      res.status(200).json({ credentials });
    } catch (err) {
      console.error('[auth] biometric/credentials error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

/**
 * DELETE /api/auth/biometric/:credentialId
 * Remove a biometric credential for the authenticated user.
 */
router.delete(
  '/biometric/:credentialId',
  requireAuth,
  async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
      const credentialId = req.params.credentialId as string;
      await removeCredential(req.userId!, credentialId);
      res.status(200).json({ message: 'Biometric credential removed successfully.' });
    } catch (err) {
      if (err instanceof Error && err.message === 'CREDENTIAL_NOT_FOUND') {
        res.status(404).json({ error: 'Biometric credential not found.' });
        return;
      }
      console.error('[auth] biometric/remove error:', err);
      res.status(500).json({ error: 'An unexpected error occurred.' });
    }
  },
);

export default router;
