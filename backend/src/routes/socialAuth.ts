/**
 * Routes for Google OAuth 2.0 and Apple Sign-In.
 *
 * Flow (browser / SPA):
 *   1. Client calls GET /api/auth/google (or /api/auth/apple) to receive the
 *      provider authorization URL including an anti-CSRF state token.
 *   2. Client redirects the user to that URL.
 *   3. Provider redirects back to the callback endpoint.
 *   4. The callback handler verifies the state, exchanges the code,
 *      finds-or-creates the local user, and redirects the browser to the
 *      frontend with the application tokens embedded in the URL hash fragment.
 *
 * Apple-specific note: Apple sends the callback as an HTTP POST (not GET),
 * hence the asymmetry between /apple/callback (POST) and /google/callback (GET).
 */

import { Router, Request, Response } from 'express';
import { authRateLimiter } from '../middleware/rateLimiter';
import { config } from '../config';
import {
  generateOAuthState,
  verifyOAuthState,
  getGoogleAuthUrl,
  handleGoogleCallback,
  getAppleAuthUrl,
  handleAppleCallback,
} from '../services/socialAuthService';

const router = Router();

// Apply the same strict rate limiting used by all auth routes
router.use(authRateLimiter);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Redirect the browser to the frontend with tokens in the URL hash fragment. */
function redirectWithTokens(
  res: Response,
  accessToken: string,
  refreshToken: string,
): void {
  const fragment = new URLSearchParams({ accessToken, refreshToken }).toString();
  res.redirect(`${config.urls.frontend}/auth/callback#${fragment}`);
}

/** Redirect the browser to the frontend with an error code. */
function redirectWithError(res: Response, error: string): void {
  const params = new URLSearchParams({ error });
  res.redirect(`${config.urls.frontend}/auth/callback?${params.toString()}`);
}

// ---------------------------------------------------------------------------
// Google OAuth
// ---------------------------------------------------------------------------

/**
 * GET /api/auth/google
 * Returns the Google OAuth authorization URL that the client should redirect
 * the user to.  The response includes a state token for CSRF protection.
 */
router.get('/google', (_req: Request, res: Response): void => {
  try {
    const state = generateOAuthState();
    const url = getGoogleAuthUrl(state);
    res.status(200).json({ url });
  } catch (err) {
    console.error('[socialAuth] google init error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * GET /api/auth/google/callback
 * Google redirects the user here after they grant (or deny) access.
 * Exchanges the authorization code, finds or creates the local user account,
 * and redirects the browser to the frontend application with tokens.
 */
router.get('/google/callback', async (req: Request, res: Response): Promise<void> => {
  const { code, state, error } = req.query as Record<string, string | undefined>;

  // User denied access or an OAuth error occurred
  if (error || !code) {
    redirectWithError(res, error ?? 'access_denied');
    return;
  }

  try {
    verifyOAuthState(state);
  } catch {
    redirectWithError(res, 'invalid_state');
    return;
  }

  try {
    const tokens = await handleGoogleCallback(code);
    redirectWithTokens(res, tokens.accessToken, tokens.refreshToken);
  } catch (err) {
    console.error('[socialAuth] google callback error:', err);
    redirectWithError(res, 'server_error');
  }
});

// ---------------------------------------------------------------------------
// Apple Sign-In
// ---------------------------------------------------------------------------

/**
 * GET /api/auth/apple
 * Returns the Apple Sign-In authorization URL that the client should redirect
 * the user to.
 */
router.get('/apple', (_req: Request, res: Response): void => {
  try {
    const state = generateOAuthState();
    const url = getAppleAuthUrl(state);
    res.status(200).json({ url });
  } catch (err) {
    console.error('[socialAuth] apple init error:', err);
    res.status(500).json({ error: 'An unexpected error occurred.' });
  }
});

/**
 * POST /api/auth/apple/callback
 * Apple uses HTTP POST (form_post response mode) for its callback rather than
 * GET.  Verifies the state, verifies the identity token against Apple's JWKS,
 * finds or creates the local user, and redirects to the frontend.
 */
router.post('/apple/callback', async (req: Request, res: Response): Promise<void> => {
  const { code, id_token: idToken, state, error } = req.body as Record<string, string | undefined>;

  if (error || !code || !idToken) {
    redirectWithError(res, error ?? 'access_denied');
    return;
  }

  try {
    verifyOAuthState(state);
  } catch {
    redirectWithError(res, 'invalid_state');
    return;
  }

  try {
    const tokens = await handleAppleCallback(code, idToken);
    redirectWithTokens(res, tokens.accessToken, tokens.refreshToken);
  } catch (err) {
    console.error('[socialAuth] apple callback error:', err);
    redirectWithError(res, 'server_error');
  }
});

export default router;
