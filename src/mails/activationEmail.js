const getActivationEmailHtml = (data) => `
<!DOCTYPE html>
<html lang="en">
<head>...</head>
<body>
  <div class="container">
    <div class="logo">
      ${data.org_logo ? `<img src="${data.org_logo}" alt="Organization Logo" class="rounded-logo">` : ''}
    </div>
    <h3>Dear ${data.name},</h3>
    <p>Congratulations on joining the ${data.org_name} community! We're excited to have you on board.</p>        
    <p>We appreciate you choosing our platform for your prayer and other spiritual activities...</p>
    <a href="${data.activation_link}" class="button">Activate Account</a>
    ...
    <p>Blessings,</p>
    <div class="signature">
      <p>${data.org_name} Team</p>
    </div>
  </div>
</body>
</html>
`;
