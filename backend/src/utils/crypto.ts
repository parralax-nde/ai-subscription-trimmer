import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';

/**
 * Generate a cryptographically secure random token as a hex string.
 */
export function generateSecureToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Generate a UUID.
 */
export function generateId(): string {
  return uuidv4();
}
