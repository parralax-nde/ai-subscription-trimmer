import dotenv from 'dotenv';
dotenv.config();

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

export const config = {
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: parseInt(process.env.PORT ?? '3000', 10),

  jwt: {
    accessSecret: requireEnv('JWT_ACCESS_SECRET'),
    refreshSecret: requireEnv('JWT_REFRESH_SECRET'),
    accessExpiresIn: process.env.JWT_ACCESS_EXPIRES_IN ?? '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN ?? '7d',
  },

  email: {
    host: process.env.SMTP_HOST ?? 'localhost',
    port: parseInt(process.env.SMTP_PORT ?? '1025', 10),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER ?? '',
    pass: process.env.SMTP_PASS ?? '',
    from: process.env.EMAIL_FROM ?? 'noreply@example.com',
  },

  urls: {
    app: process.env.APP_URL ?? 'http://localhost:3000',
    frontend: process.env.FRONTEND_URL ?? 'http://localhost:5173',
  },

  tokens: {
    emailVerificationExpiresMs: parseInt(
      process.env.EMAIL_VERIFICATION_TOKEN_EXPIRES_MS ?? '86400000',
      10,
    ),
    passwordResetExpiresMs: parseInt(
      process.env.PASSWORD_RESET_TOKEN_EXPIRES_MS ?? '3600000',
      10,
    ),
    magicLinkExpiresMs: parseInt(
      process.env.MAGIC_LINK_TOKEN_EXPIRES_MS ?? '600000', // 10 minutes
      10,
    ),
    biometricChallengeExpiresMs: parseInt(
      process.env.BIOMETRIC_CHALLENGE_EXPIRES_MS ?? '300000', // 5 minutes
      10,
    ),
    emailChangeExpiresMs: parseInt(
      process.env.EMAIL_CHANGE_TOKEN_EXPIRES_MS ?? '3600000', // 1 hour
      10,
    ),
  },

  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '900000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS ?? '100', 10),
    authMaxRequests: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS ?? '10', 10),
  },

  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID ?? '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET ?? '',
      redirectUri: process.env.GOOGLE_REDIRECT_URI ?? 'http://localhost:3000/api/auth/google/callback',
    },
    apple: {
      clientId: process.env.APPLE_CLIENT_ID ?? '',
      teamId: process.env.APPLE_TEAM_ID ?? '',
      keyId: process.env.APPLE_KEY_ID ?? '',
      privateKey: (process.env.APPLE_PRIVATE_KEY ?? '').replace(/\\n/g, '\n'),
      redirectUri: process.env.APPLE_REDIRECT_URI ?? 'http://localhost:3000/api/auth/apple/callback',
    },
  },
};
