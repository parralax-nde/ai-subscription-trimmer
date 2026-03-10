import { app } from './app';
import { config } from './config';
import prisma from './config/database';

async function main() {
  // Ensure DB connection
  await prisma.$connect();

  const server = app.listen(config.port, () => {
    console.log(`Server running on port ${config.port} [${config.nodeEnv}]`);
  });

  const shutdown = async () => {
    console.log('Shutting down gracefully...');
    server.close();
    await prisma.$disconnect();
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
