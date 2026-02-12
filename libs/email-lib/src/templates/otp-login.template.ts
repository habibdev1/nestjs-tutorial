/**
 * otpLoginTemplate — Professional, branded OTP email
 * Usage: sendMail(to, subject, otpLoginTemplate, { name, otp, year }, textFallback)
 */
export const otpLoginTemplate = `
<table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,sans-serif;background:#f5f7fb;padding:24px;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 8px 24px rgba(30,42,62,0.08);">
        <tr>
          <td style="background:#0d6efd;color:#ffffff;text-align:center;padding:22px;">
            <div style="font-size:20px;font-weight:600;letter-spacing:0.3px;">DARMIST Lab</div>
            <div style="opacity:0.9;font-size:12px;margin-top:4px;">Secure Login Verification</div>
          </td>
        </tr>
        <tr>
          <td style="padding:32px 28px;text-align:center;">
            <h2 style="margin:0 0 12px;font-size:22px;color:#1f2937;">Hello {{name}},</h2>
            <p style="margin:0 0 18px;font-size:15px;color:#374151;">
              Use the One-Time Password (OTP) below to continue your login.
            </p>
            <div style="display:inline-block;margin:10px 0 18px;padding:12px 22px;border:2px dashed #0d6efd;border-radius:10px;font-size:30px;font-weight:700;color:#0d6efd;letter-spacing:6px;background:#f0f6ff;">
              {{otp}}
            </div>
            <p style="font-size:13px;color:#6b7280;margin:0 0 4px;">This code will expire in <strong>5 minutes</strong>.</p>
            <p style="font-size:12px;color:#9ca3af;margin:0;">If you didn’t request this, you can safely ignore this email.</p>
            <p style="font-size:13px;color:#6b7280;margin: 50px 0 0;border-top: 1px solid #6b728084;padding-top: 10px;">Warm regards,<br>DARMIST Lab Team</p>
          </td>
        </tr>
        <tr>
          <td style="background:#f9fafb;text-align:center;padding:14px;color:#6b7280;font-size:12px;">
            &copy; {{year}} DARMIST Lab — All rights reserved.
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
`;
