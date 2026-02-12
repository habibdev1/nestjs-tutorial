export const accountLockedTemplate = `
<table width="100%" cellpadding="0" cellspacing="0" style="font-family:Arial,sans-serif;background:#f5f7fb;padding:24px;">
  <tr>
    <td align="center">
      <table width="600" style="background:#fff;border-radius:12px;box-shadow:0 8px 24px rgba(30,42,62,0.08);overflow:hidden;">
        <tr>
          <td style="background:#ef4444;color:#fff;text-align:center;padding:20px;">
            <h1 style="margin:0;font-size:20px;">Account Locked</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:28px;text-align:center;">
            <h2 style="margin:0 0 12px;">Hello {{name}},</h2>
            <p style="font-size:15px;color:#374151;">
              Too many failed login attempts have locked your DARMIST Lab account.
            </p>
            <p style="margin:20px 0;font-size:14px;">
              Click the button below to unlock your account:
            </p>
            <a href="{{unlockUrl}}" style="display:inline-block;padding:12px 24px;background:#0d6efd;color:#fff;border-radius:6px;text-decoration:none;font-weight:600;">
              Unlock My Account
            </a>
            <p style="margin-top:24px;font-size:13px;color:#6b7280;">
              If you did not try to log in, please change your password once you regain access.
            </p>
            <p style="font-size:13px;color:#6b7280;margin: 50px 0 0;border-top: 1px solid #6b728084;padding-top: 10px;">Warm regards,<br>DARMIST Lab Team</p>
          </td>
        </tr>
        <tr>
          <td style="background:#f9fafb;text-align:center;padding:14px;font-size:12px;color:#6b7280;">
            &copy; {{year}} DARMIST Lab — All rights reserved.
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
`;
