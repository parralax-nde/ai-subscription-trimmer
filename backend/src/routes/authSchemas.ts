import { z } from 'zod';

const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters.')
  .max(128, 'Password must not exceed 128 characters.')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter.')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter.')
  .regex(/[0-9]/, 'Password must contain at least one number.')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character.');

export const registerSchema = z.object({
  email: z.string().email('Invalid email address.').max(254),
  password: passwordSchema,
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email address.'),
  password: z.string().min(1, 'Password is required.'),
});

export const verifyEmailSchema = z.object({
  token: z.string().min(1, 'Token is required.'),
});

export const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address.'),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token is required.'),
  password: passwordSchema,
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required.'),
});

export const logoutSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required.'),
});
