import './config'; // load env vars first
import express, { Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { generalRateLimiter } from './middleware/rateLimiter';
import authRouter from './routes/auth';

export const app = express();

// Security headers
app.use(helmet());

// CORS — restrict to known origins in production
app.use(
  cors({
    origin:
      process.env.NODE_ENV === 'production'
        ? [process.env.FRONTEND_URL ?? '']
        : true,
    credentials: true,
  }),
);

// Body parsing
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// General rate limiter
app.use(generalRateLimiter);

// Health check
app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ status: 'ok' });
});

// API routes
app.use('/api/auth', authRouter);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: 'Not found.' });
});

// Global error handler
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('[server] unhandled error:', err);
  res.status(500).json({ error: 'An unexpected error occurred.' });
});
