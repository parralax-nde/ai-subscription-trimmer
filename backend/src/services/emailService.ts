import transporter from '../config/email';
import { config } from '../config';

export async function sendVerificationEmail(
  to: string,
  token: string,
): Promise<void> {
  const verificationUrl = `${config.urls.frontend}/verify-email?token=${token}`;

  await transporter.sendMail({
    from: config.email.from,
    to,
    subject: 'Verify your email address',
    text: `
Welcome to AI Subscription Trimmer!

Please verify your email address by clicking the link below:

${verificationUrl}

This link expires in 24 hours.

If you did not create an account, you can safely ignore this email.
    `.trim(),
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px;">
  <h1 style="color:#333;">Welcome to AI Subscription Trimmer!</h1>
  <p>Please verify your email address by clicking the button below:</p>
  <a href="${verificationUrl}"
     style="display:inline-block;padding:12px 24px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px;">
    Verify Email Address
  </a>
  <p style="margin-top:16px;color:#666;">This link expires in 24 hours.</p>
  <p style="color:#666;">If you did not create an account, you can safely ignore this email.</p>
</body>
</html>
    `.trim(),
  });
}

export async function sendPasswordResetEmail(
  to: string,
  token: string,
): Promise<void> {
  const resetUrl = `${config.urls.frontend}/reset-password?token=${token}`;

  await transporter.sendMail({
    from: config.email.from,
    to,
    subject: 'Reset your password',
    text: `
You requested a password reset for your AI Subscription Trimmer account.

Click the link below to reset your password:

${resetUrl}

This link expires in 1 hour.

If you did not request a password reset, you can safely ignore this email. Your password will not be changed.
    `.trim(),
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px;">
  <h1 style="color:#333;">Password Reset Request</h1>
  <p>You requested a password reset for your AI Subscription Trimmer account.</p>
  <p>Click the button below to reset your password:</p>
  <a href="${resetUrl}"
     style="display:inline-block;padding:12px 24px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px;">
    Reset Password
  </a>
  <p style="margin-top:16px;color:#666;">This link expires in 1 hour.</p>
  <p style="color:#666;">If you did not request a password reset, you can safely ignore this email. Your password will not be changed.</p>
</body>
</html>
    `.trim(),
  });
}

export async function sendMagicLinkEmail(
  to: string,
  token: string,
): Promise<void> {
  const magicLinkUrl = `${config.urls.frontend}/magic-link?token=${token}`;

  await transporter.sendMail({
    from: config.email.from,
    to,
    subject: 'Sign in to AI Subscription Trimmer',
    text: `
You requested to sign in to your AI Subscription Trimmer account.

Click the link below to sign in:

${magicLinkUrl}

This link expires in 10 minutes and can only be used once.

If you did not request this link, you can safely ignore this email.
    `.trim(),
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px;">
  <h1 style="color:#333;">Sign In Request</h1>
  <p>You requested to sign in to your AI Subscription Trimmer account.</p>
  <p>Click the button below to sign in:</p>
  <a href="${magicLinkUrl}"
     style="display:inline-block;padding:12px 24px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px;">
    Sign In
  </a>
  <p style="margin-top:16px;color:#666;">This link expires in 10 minutes and can only be used once.</p>
  <p style="color:#666;">If you did not request this link, you can safely ignore this email.</p>
</body>
</html>
    `.trim(),
  });
}
