// utils/templates.js
function getOtpEmailTemplate(name, otp) {
  return `
    <p>Dear ${name},</p>
    <p>Your password reset OTP is: <strong>${otp}</strong></p>
    <p>If you did not request this, please ignore.</p>
  `;
}

module.exports = { getOtpEmailTemplate };
