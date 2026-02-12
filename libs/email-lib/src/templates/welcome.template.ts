/**
 * welcomeTemplate — Professional, branded welcome email
 * Usage: sendMail(to, subject, welcomeTemplate, { name, email, year }, textFallback)
 */
export const welcomeTemplate = `
<table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,sans-serif;background:#f5f7fb;padding:24px;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 8px 24px rgba(30,42,62,0.08);">
        <tr>
          <td style="background:#0d6efd;color:#ffffff;text-align:center;padding:22px;">
            <div style="font-size:20px;font-weight:600;letter-spacing:0.3px;">DARMIST Lab</div>
            <div style="opacity:0.9;font-size:12px;margin-top:4px;">Welcome to the community</div>
          </td>
        </tr>
        <tr>
          <td style="padding:32px 28px;text-align:center;">
            <h2 style="margin:0 0 12px;font-size:22px;color:#1f2937;">Welcome, {{name}}</h2>
            <p style="margin:0 0 16px;font-size:15px;color:#374151;">
              Hi {{name}}, thanks for signing up with DARMIST Lab. Your account has been created successfully.
            </p>
            <p style="margin:0 0 20px;font-size:15px;color:#374151;">
              You can now log in using your email <strong>{{email}}</strong>.
            </p>
            <p style="font-size:13px;color:#6b7280;margin:0;">
              We’re excited to have you on board. Let’s build something amazing together!
            </p>
            <p style="font-size:13px;color:#6b7280;margin: 50px 0 0;border-top: 1px solid #6b728084;padding-top: 10px;">
              Warm regards,<br>DARMIST Lab Team
            </p>
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
