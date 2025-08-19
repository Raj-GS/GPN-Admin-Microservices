const VerifyUser = (data) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>User Verification</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #f8f8f8;
      margin: 0;
      padding: 20px;
    }
    .email-container {
      max-width: 600px;
      margin: auto;
      background: #ffffff;
      border-radius: 8px;
      padding: 20px;
      color: #565a5c;
      font-size: 16px;
      line-height: 1.5;
    }
    .email-container p {
      margin: 10px 0;
    }
  </style>
</head>
<body>
  <div class="logo">
    <img src="https://glocalprayer.net/prayer/public/assets/img/glocal-prayer-logo.png" alt="Glocal Prayer Network Logo" />
  </div>
  <div class="email-container">
    <p>Hi ${data.name},</p>
    <p>You are verified by <strong>${data.org_name}</strong>. Kindly login with your credentials.</p>
  </div>
</body>
</html>`;

module.exports = VerifyUser;
