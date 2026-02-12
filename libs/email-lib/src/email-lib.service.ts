import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import nodemailer, { Transporter } from 'nodemailer';
import handlebars from 'handlebars';

/**
 * EmailLibService
 * ----------------
 * - Sends emails using SMTP (via Nodemailer).
 * - Supports both HTML template and plain-text fallback.
 */
@Injectable()
export class EmailLibService {
  private readonly logger = new Logger(EmailLibService.name);
  private transporter: Transporter;

  constructor(private readonly config: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.config.get('SMTP_HOST'),
      port: this.config.get<number>('SMTP_PORT'),
      secure: this.config.get<boolean>('SMTP_SECURE'),
      auth: {
        user: this.config.get('SMTP_USER'),
        pass: this.config.get('SMTP_PASS'),
      },
    });
  }

  /**
   * Send an email
   * @param to Recipient email
   * @param subject Subject line
   * @param template HTML template string with placeholders (handlebars)
   * @param context Variables for handlebars template
   * @param plainText Optional plain text fallback
   */
  async sendMail(
    to: string,
    subject: string,
    template: string,
    context: Record<string, any>,
    plainText?: string,
  ) {
    try {
      const compiled = handlebars.compile(template);
      const html = compiled(context);

      const mailOptions = {
        from: this.config.get('EMAIL_FROM'),
        to,
        subject,
        text: plainText ?? subject,
        html,
      };

      const info = await this.transporter.sendMail(mailOptions);
      this.logger.log(`📧 Email sent to ${to}: ${info.messageId}`);
      return info;
    } catch (err) {
      this.logger.error(`❌ Failed to send email to ${to}`, err.stack);
      throw err;
    }
  }
}
