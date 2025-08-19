const AdminActivateUserAccount = (data) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Account Activated</title>
  <style>
    body {
      font-family: Tahoma, Arial, sans-serif;
      background-color: #f8f8f8;
      color: #565a5c;
      margin: 0;
      padding: 20px;
    }
    .email-container {
      max-width: 600px;
      margin: 40px auto;
      background: #ffffff;
      border-radius: 10px;
      padding: 20px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.08);
    }
    p {
      font-size: 16px;
      line-height: 1.5;
      margin: 12px 0;
    }
    .signature {
      margin-top: 24px;
    }
  </style>
</head>
<body>
  <div class="email-container">
    <p>Dear ${data.name},</p>
    <p>
      We are pleased to inform you that your account has been successfully activated 
      by Your Organisation Admin. You can now access all the features and services 
      available in ${data.org_name}.
    </p>
    <p>
      Thank you for choosing Glocal Prayer Network! We look forward to serving you.
    </p>
    <div class="signature">
      <p>Best regards,</p>
      <p><strong>Glocal Prayer Network</strong></p>
    </div>
  </div>
</body>
</html>`;

module.exports = AdminActivateUserAccount;
