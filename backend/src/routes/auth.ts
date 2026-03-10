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
 * Returns JWT access and refresh tokens.
 */
router.post('/login', validate(loginSchema), async (req: Request, res: Response): Promise<void> => {
  try {
    const result = await loginUser(req.body.email, req.body.password);
    res.status(200).json({
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    });
  } catch (err) {
    if (err instanceof Error) {
      if (err.message === 'INVALID_CREDENTIALS') {
        res.status(401).json({ error: 'Invalid email or password.' });
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

export default router;
