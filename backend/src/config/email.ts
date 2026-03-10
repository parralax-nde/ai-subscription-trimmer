import nodemailer from 'nodemailer';
import { config } from './index';

const transporter = nodemailer.createTransport({
  host: config.email.host,
  port: config.email.port,
  secure: config.email.secure,
  auth:
    config.email.user && config.email.pass
      ? { user: config.email.user, pass: config.email.pass }
      : undefined,
});

export default transporter;
