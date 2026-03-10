import rateLimit from 'express-rate-limit';
import { config } from '../config';

/**
 * General rate limiter for all routes.
 */
export const generalRateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.maxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

/**
 * Strict rate limiter for authentication endpoints.
 * Limits to 10 requests per 15 minutes per IP to mitigate brute-force attacks.
 */
export const authRateLimiter = rateLimit({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.authMaxRequests,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
  skipSuccessfulRequests: false,
});
