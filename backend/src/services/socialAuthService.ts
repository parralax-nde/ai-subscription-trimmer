/**
 * Social authentication service.
 *
 * Implements Google OAuth 2.0 and Apple Sign-In flows, handling:
 * - OAuth state generation and CSRF verification
 * - Authorization URL construction for each provider
 * - Authorization code exchange and user-info fetching
 * - Apple identity-token verification via JWKS
 * - Account creation and linking (social ID ↔ existing email account)
 * - Issuing the application's own access/refresh token pair
 */

import crypto, { webcrypto } from 'crypto';
import jwt from 'jsonwebtoken';
import prisma from '../config/database';
import { config } from '../config';
import { generateSecureToken } from '../utils/crypto';
import { generateAccessToken, generateRefreshToken, parseDurationMs } from '../utils/tokens';
import { httpPost, httpGet } from '../utils/httpClient';
import type { LoginResultSuccess } from './authService';

// ---------------------------------------------------------------------------
// OAuth state — CSRF protection
// ---------------------------------------------------------------------------

/**
 * Generate a short-lived signed state token to protect the OAuth round-trip
 * from CSRF attacks.  The token is a JWT so it carries its own expiry.
 */
export function generateOAuthState(): string {
  const nonce = generateSecureToken();
  return jwt.sign({ nonce }, config.jwt.accessSecret, { expiresIn: '10m' });
}

/**
 * Verify a state token that was returned by the OAuth provider.
 * Throws if the token is missing, tampered with, or expired.
 */
export function verifyOAuthState(state: string | undefined): void {
  if (!state) throw new Error('MISSING_OAUTH_STATE');
  try {
    jwt.verify(state, config.jwt.accessSecret);
  } catch {
    throw new Error('INVALID_OAUTH_STATE');
  }
}

// ---------------------------------------------------------------------------
// Google OAuth
// ---------------------------------------------------------------------------

/** Build the Google authorization URL and embed the state token. */
export function getGoogleAuthUrl(state: string): string {
  const params = new URLSearchParams({
    client_id: config.oauth.google.clientId,
    redirect_uri: config.oauth.google.redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    access_type: 'offline',
    prompt: 'select_account',
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
}

interface GoogleTokenResponse {
  access_token: string;
  id_token: string;
}

interface GoogleUserInfo {
  sub: string;
  email: string;
  email_verified: boolean;
}

async function exchangeGoogleCode(code: string): Promise<GoogleTokenResponse> {
  const body = new URLSearchParams({
    code,
    client_id: config.oauth.google.clientId,
    client_secret: config.oauth.google.clientSecret,
    redirect_uri: config.oauth.google.redirectUri,
    grant_type: 'authorization_code',
  }).toString();

  const response = await httpPost(
    'https://oauth2.googleapis.com/token',
    body,
    { 'Content-Type': 'application/x-www-form-urlencoded' },
  ) as GoogleTokenResponse;

  if (!response.access_token) {
    throw new Error('GOOGLE_TOKEN_EXCHANGE_FAILED');
  }
  return response;
}

async function getGoogleUserInfo(accessToken: string): Promise<GoogleUserInfo> {
  const info = await httpGet(
    'https://www.googleapis.com/oauth2/v3/userinfo',
    { Authorization: `Bearer ${accessToken}` },
  ) as GoogleUserInfo;

  if (!info.sub) {
    throw new Error('GOOGLE_USERINFO_FAILED');
  }
  return info;
}

/**
 * Complete the Google OAuth flow after receiving an authorization code.
 * Exchanges the code, fetches user info, finds or creates the local user,
 * and returns the application's own access and refresh tokens.
 */
export async function handleGoogleCallback(code: string): Promise<LoginResultSuccess> {
  const { access_token } = await exchangeGoogleCode(code);
  const userInfo = await getGoogleUserInfo(access_token);

  const userId = await findOrCreateSocialUser({
    provider: 'google',
    providerId: userInfo.sub,
    email: userInfo.email?.toLowerCase().trim() ?? null,
    emailVerified: userInfo.email_verified ?? false,
  });

  return issueTokens(userId);
}

// ---------------------------------------------------------------------------
// Apple Sign-In
// ---------------------------------------------------------------------------

/** Build the Apple Sign-In authorization URL and embed the state token. */
export function getAppleAuthUrl(state: string): string {
  const params = new URLSearchParams({
    client_id: config.oauth.apple.clientId,
    redirect_uri: config.oauth.apple.redirectUri,
    response_type: 'code',
    scope: 'name email',
    state,
    response_mode: 'form_post',
  });
  return `https://appleid.apple.com/auth/authorize?${params.toString()}`;
}

function generateAppleClientSecret(): string {
  return jwt.sign({}, config.oauth.apple.privateKey, {
    algorithm: 'ES256',
    expiresIn: '1h',
    issuer: config.oauth.apple.teamId,
    audience: 'https://appleid.apple.com',
    subject: config.oauth.apple.clientId,
    keyid: config.oauth.apple.keyId,
  });
}

interface AppleTokenResponse {
  id_token: string;
}

async function exchangeAppleCode(code: string): Promise<AppleTokenResponse> {
  const clientSecret = generateAppleClientSecret();

  const body = new URLSearchParams({
    code,
    client_id: config.oauth.apple.clientId,
    client_secret: clientSecret,
    redirect_uri: config.oauth.apple.redirectUri,
    grant_type: 'authorization_code',
  }).toString();

  const response = await httpPost(
    'https://appleid.apple.com/auth/token',
    body,
    { 'Content-Type': 'application/x-www-form-urlencoded' },
  ) as AppleTokenResponse;

  if (!response.id_token) {
    throw new Error('APPLE_TOKEN_EXCHANGE_FAILED');
  }
  return response;
}

/** JWK key shape from Apple's JWKS endpoint (includes `kid` beyond the base spec). */
interface AppleJwk extends webcrypto.JsonWebKey {
  kid?: string;
}

/** How long to cache Apple's JWKS before re-fetching (milliseconds). */
const JWKS_CACHE_TTL_MS = 3_600_000; // 1 hour

// Simple in-memory JWKS cache — refreshed at most once per hour.
interface JwksCache {
  keys: AppleJwk[];
  fetchedAt: number;
}
let appleJwksCache: JwksCache | null = null;

async function getApplePublicKey(kid: string): Promise<crypto.KeyObject> {
  const now = Date.now();
  if (!appleJwksCache || now - appleJwksCache.fetchedAt > JWKS_CACHE_TTL_MS) {
    const jwks = await httpGet('https://appleid.apple.com/auth/keys', {}) as { keys: AppleJwk[] };
    appleJwksCache = { keys: jwks.keys, fetchedAt: now };
  }

  const jwk = appleJwksCache.keys.find((k) => k.kid === kid);
  if (!jwk) throw new Error('APPLE_PUBLIC_KEY_NOT_FOUND');

  return crypto.createPublicKey({ key: jwk, format: 'jwk' });
}

interface AppleIdentityClaims {
  sub: string;
  email?: string;
}

async function verifyAppleIdentityToken(idToken: string): Promise<AppleIdentityClaims> {
  const decoded = jwt.decode(idToken, { complete: true });
  if (!decoded || typeof decoded === 'string' || !decoded.header.kid) {
    throw new Error('INVALID_APPLE_ID_TOKEN');
  }

  const publicKey = await getApplePublicKey(decoded.header.kid as string);

  const payload = jwt.verify(idToken, publicKey, {
    algorithms: ['RS256'],
    issuer: 'https://appleid.apple.com',
    audience: config.oauth.apple.clientId,
  }) as AppleIdentityClaims;

  return { sub: payload.sub, email: payload.email };
}

/**
 * Complete the Apple Sign-In flow.
 *
 * Apple sends both an authorization code and a signed identity token.
 * We verify the identity token using Apple's public JWKS (the token contains
 * all required user claims), then find or create the local user account.
 */
export async function handleAppleCallback(
  code: string,
  idToken: string,
): Promise<LoginResultSuccess> {
  // The identity token is the authoritative source of user identity.
  // We verify it independently so we do not need to exchange the code just
  // to obtain user info — but we still exchange the code so Apple's servers
  // register the sign-in and can issue a refresh token if needed.
  const [claims] = await Promise.all([
    verifyAppleIdentityToken(idToken),
    exchangeAppleCode(code).catch(() => { /* non-fatal; claims are already verified */ }),
  ]);

  const userId = await findOrCreateSocialUser({
    provider: 'apple',
    providerId: claims.sub,
    email: claims.email?.toLowerCase().trim() ?? null,
    emailVerified: true, // Apple always delivers verified emails (incl. relay addresses)
  });

  return issueTokens(userId);
}

// ---------------------------------------------------------------------------
// Account creation / linking
// ---------------------------------------------------------------------------

export interface FindOrCreateSocialUserParams {
  provider: 'google' | 'apple';
  providerId: string;
  email: string | null;
  emailVerified: boolean;
}

/**
 * Resolve the local user ID for a social login, implementing three cases:
 *
 * 1. A user already exists with this provider ID → return their ID.
 * 2. A user exists with the same email (registered via another provider or
 *    email/password) → link the new provider ID and return their ID.
 * 3. No matching user → create a new account and return the new ID.
 */
export async function findOrCreateSocialUser(params: FindOrCreateSocialUserParams): Promise<string> {
  const { provider, providerId, email, emailVerified } = params;
  const idField = provider === 'google' ? 'googleId' : 'appleId';

  // 1. Existing user found by provider ID
  const existingByProvider = await prisma.user.findFirst({
    where: { [idField]: providerId },
  });
  if (existingByProvider) {
    return existingByProvider.id;
  }

  // 2. Existing user found by email — link the social account
  if (email) {
    const existingByEmail = await prisma.user.findUnique({ where: { email } });
    if (existingByEmail) {
      await prisma.user.update({
        where: { id: existingByEmail.id },
        data: {
          [idField]: providerId,
          // Upgrade isEmailVerified if the provider confirms it
          ...(emailVerified && !existingByEmail.isEmailVerified && { isEmailVerified: true }),
        },
      });
      return existingByEmail.id;
    }
  }

  // 3. Create a new user.
  //    Apple may withhold the real email after the first sign-in; when that
  //    happens we generate a placeholder using the `.invalid` TLD (reserved
  //    by RFC 2606 for exactly this kind of non-deliverable placeholder) so
  //    the unique email constraint is satisfied without storing a fake real address.
  const resolvedEmail = email ?? `${provider}.${providerId}@social.invalid`;

  const newUser = await prisma.user.create({
    data: {
      email: resolvedEmail,
      [idField]: providerId,
      isEmailVerified: emailVerified,
      // passwordHash intentionally left null — social-only accounts cannot
      // log in with a password.
    },
  });

  return newUser.id;
}

// ---------------------------------------------------------------------------
// Token issuance helper (mirrors authService.issueTokens)
// ---------------------------------------------------------------------------

async function issueTokens(userId: string): Promise<LoginResultSuccess> {
  const accessToken = generateAccessToken(userId);
  const { token: refreshToken } = generateRefreshToken(userId);

  const expiresAt = new Date(Date.now() + parseDurationMs(config.jwt.refreshExpiresIn));

  await prisma.refreshToken.create({
    data: { token: refreshToken, userId, expiresAt },
  });

  return { accessToken, refreshToken };
}
