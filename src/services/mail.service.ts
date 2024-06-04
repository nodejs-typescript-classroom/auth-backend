import * as nodemailer from 'nodemailer';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private logger: Logger = new Logger(MailService.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      auth: {
        user: this.configService.get<string>('SMTP_USER'),
        pass: this.configService.get<string>('SMTP_SECRET'),
      },
      host: this.configService.get<string>('SMTP_HOST'),
      port: this.configService.get<number>('SMTP_PORT'),
      secure: this.configService.get<boolean>('EMAIL_SECURE'),
    });
  }

  async sendPasswordResetEmail(to: string, token: string) {
    const resetLink = `http://localhost:3000/reset-password?token=${token}`;
    const mailOptions = {
      from: 'no-reply@auth-backend.com',
      sender: 'no-reply@auth-backend.com',
      to: to,
      subject: '[Auth-Backend] Password Reset Request',
      html: `<p>You requested a password reset. Click the link below to reset your password:</p><p><a href=${resetLink}>Reset Password</a></p>`,
    };

    await this.transporter.sendMail(mailOptions);
    this.logger.log({ message: 'message has been sent', to });
  }
}
