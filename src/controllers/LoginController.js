const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { body, validationResult } = require('express-validator');
const transporter = require('../utils/mailTransport');
const {getOtpEmailTemplate}= require('../mails/otpTemplate');


function convertBigInt(obj) {
  if (typeof obj === 'bigint') {
    return Number(obj); // or use obj.toString() if IDs are too large
  } else if (Array.isArray(obj)) {
    return obj.map(convertBigInt);
  } else if (obj !== null && typeof obj === 'object') {
    const newObj = {};
    for (const key in obj) {
      newObj[key] = convertBigInt(obj[key]);
    }
    return newObj;
  }
  return obj;
}

exports.login = async (req, res) => {

  const { email, password } = req?.body;



  if (!email || !password) {
    return res.status(200).json({
      error: { message: 'Email and password are required.' }
    });
  }

  try {
    const user = await prisma.app_users.findFirst({
      where: { email },
      include: {
        origanisation: true,
        family_details: true
      }
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Login credentials are invalid.' });
    }

    // Fix Laravel bcrypt prefix
    const hashedPassword = user.password.replace(/^\$2y\$/, '$2a$');
    const passwordMatch = await bcrypt.compare(password, hashedPassword);

    if (!passwordMatch) {
      return res.status(400).json({ success: false, message: 'Password is wrong.' });
    }

    const safeUser = {
      id: Number(user.id),
      org_id: Number(user.org_id),
      role: Number(user.role),
    };

    const token = jwt.sign(safeUser, process.env.JWT_SECRET, { expiresIn: '7d' });


    if (user.role === 4n || user.role === 4) {

      return res.status(500).json({
          success: false,
          message: "You do not have permission to access this panel",
        });

    }


 if (user.role != 1n || user.role === 1) {

    // Normal user: check if organization is active
    const orgId = Number(user.org_id);
    const org = await prisma.origanisation.findUnique({
      where: { id: orgId }
    });


    if (!org || org.status !== 'active') {
      return res.status(200).json({
        success: true,
        message: 'Organization Deactivated',
        is_active: false,
        org_is_active: false,
        user: convertBigInt(user)
      });
    }

    // For volunteers/external users
    if (user.role === 4n || user.role === 4) {
      const orgUser = await prisma.organisation_user.findFirst({
        where: { user_id: user.id }
      });

      if (orgUser?.account_status === '0') {
        return res.status(200).json({
          success: true,
          message: 'Account Deactivated',
          is_active: false,
          org_is_active: true,
          user: convertBigInt(user)
        });
      }
    }
  }
    // Default success
    return res.status(200).json({
      success: true,
      user: convertBigInt(user),
      token,
      is_active: true,
      org_is_active: true,
      superadmin: 'no'
    });

  } catch (err) {
    console.error('Login Error:', err);
    return res.status(500).json({ success: false, message: 'Could not create token.' });
  }
};


exports.forgotPassword= async (req, res) => {
  await body('is_set').notEmpty().isInt({ min: 1, max: 3 }).run(req);
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(200).json({ error: errors.array() });

  const { is_set, email, otp, newPassword } = req.body;

  if (is_set == 1) {
    await body('email').isEmail().run(req);
    if (!validationResult(req).isEmpty()) return res.status(200).json({ error: errors.array() });

    return await emailVerifyAndSendOtp(email, res);
  } else if (is_set == 2) {
    await Promise.all([body('email').isEmail().run(req), body('otp').notEmpty().run(req)]);
    if (!validationResult(req).isEmpty()) return res.status(200).json({ error: errors.array() });

    return await otpVerify(email, otp, res);
  } else if (is_set == 3) {
    await Promise.all([body('email').isEmail().run(req), body('newPassword').isLength({ min: 6 }).run(req)]);
    if (!validationResult(req).isEmpty()) return res.status(200).json({ error: errors.array() });

    return await updatePassword(email, newPassword, res);
  } else {
    return res.status(400).json({ success: false, message: 'Invalid is_set value' });
  }
}

async function emailVerifyAndSendOtp(email, res) {
  try {
    const user = await prisma.app_users.findFirst({ where: { email } });
    if (!user) return res.status(404).json({ success: false, message: 'Email not found' });

    const otp = Math.floor(1000 + Math.random() * 9000).toString();



    const existingRecord = await prisma.forgotpasswords.findFirst({
  where: { email: email },
});

if (existingRecord) {
  await prisma.forgotpasswords.update({
    where: { id: existingRecord.id },
    data: { otp },
  });
} else {
  await prisma.forgotpasswords.create({
    data: { email: email, otp },
  });
}



    try {
      await transporter.sendMail({
        from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
        to: email,
        subject: 'Your Password Reset OTP',
        html: getOtpEmailTemplate(`${user.first_name || ''} ${user.last_name || ''}`, otp)
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ success: false, message: 'Unable to send mail' });
    }

    res.json({ success: true, message: 'OTP sent successfully' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Something went wrong' });
  }
}

async function otpVerify(email, otp, res) {
  try {
    const record = await prisma.forgotpasswords.findFirst({ where: { email } });
    if (record && record.otp === otp) {
      res.json({ success: true, message: 'OTP verified successfully' });
    } else {
      res.status(422).json({ success: false, message: 'Invalid OTP' });
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Something went wrong' });
  }
}

async function updatePassword(email, newPassword, res) {
  try {
    const hashed = await bcrypt.hash(newPassword, 10);
    await prisma.app_users.updateMany({
      where: { email },
      data: { password: hashed },
    });
    res.json({ success: true, message: 'Password updated' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: 'Something went wrong' });
  }
}
