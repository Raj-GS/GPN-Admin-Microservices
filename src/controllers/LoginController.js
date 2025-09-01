const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { body, validationResult } = require('express-validator');
const transporter = require('../utils/mailTransport');
const {getOtpEmailTemplate}= require('../mails/otpTemplate');
// controllers/userController.js
import { randomBytes } from "crypto";

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

exports.dbCheck = async (req, res) => {

try {
    await prisma.$queryRaw`SELECT 1`; // lightweight test query
    res.send("✅ Database connected successfully!");
  } catch (err) {
    console.error(err);
    res.status(500).send("❌ Database connection failed!");
  }
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

exports.OrgDetails = async (req, res) => {
 const { id } = req.body;

  try {

    const orgDetails = await prisma.origanisation.findFirst({
      where: { short_code: id},
      select :{
        id :true,
        org_name :true,
        logo:true
      },

    });

    if (!orgDetails) {
      return res.status(404).json({ success: false, message: 'Organization not found' });
    }

    return res.status(200).json({
      success: true,
      pagename: 'Org Details',
      data:convertBigInt(orgDetails),
    });

  } catch (error) {
    console.error('Error editing special prayer:', error);
    return res.status(500).json({ success: false, message: 'Server Error' });
  }

}





exports.addNewUsers = async (req, res) => {
  try {
    const {
      existed,
      existedUserId,
      first_name,
      last_name,
      email,
      phone_number,
      gender,
      orgainisation,
      password,
      baptized,
      date_of_birth,
      marital_status,
      address,
      country_code,
      address_country,
      dial_code,
      child,
      childCount,
      short_code,

      father_name,
      fdate_of_birth,
      father_number,
      fbaptized,
      mother_name,
      mdate_of_birth,
      mother_number,
      mbaptized,

      spouse_name,
      sdate_of_birth,
      spouse_number,
      sbaptized,
      // child_* fields handled below
    } = req.body;

    // approval settings
    const approvalSettings = await prisma.approval_settings.findFirst({
      where: {
        module_name: "backgroundVerification",
        org_id: orgainisation,
      },
    });

    let isVerified = 0;
    if (approvalSettings && approvalSettings.approval === "no") {
      isVerified = 1;
    }

    const activation_link = randomBytes(32).toString("hex");

    let userId;

    if (existed === "no") {
      // Create new user
      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await prisma.appuser.create({
        data: {
          first_name,
          last_name,
          email,
          phone: phone_number.replace(/\s/g, ""),
          gender,
          role: "4",
          org_id: orgainisation,
          password: hashedPassword,
          baptized,
          date_of_birth: new Date(date_of_birth),
          marital_status,
          address,
          country: country_code,
          country_code: address_country,
          dial_code,
          child,
        },
      });
      userId = user.id;

      // OrganisationUser link
      await prisma.organisationUser.create({
        data: {
          user_id: userId,
          org_id: orgainisation,
          isVerified,
          activation_link,
          account_status: "0",
          role: "4",
        },
      });

      // Family Details
      if (marital_status === "Unmarried") {
        await prisma.familyDetails.createMany({
          data: [
            {
              user_id: userId,
              type: "1",
              person_name: father_name,
              date_of_birth: fdate_of_birth ? new Date(fdate_of_birth) : null,
              phone_number: father_number,
              baptized: fbaptized,
            },
            {
              user_id: userId,
              type: "2",
              person_name: mother_name,
              date_of_birth: mdate_of_birth ? new Date(mdate_of_birth) : null,
              phone_number: mother_number,
              baptized: mbaptized,
            },
          ],
        });
      } else {
        await prisma.familyDetails.create({
          data: {
            user_id: userId,
            type: "3",
            person_name: spouse_name,
            date_of_birth: sdate_of_birth ? new Date(sdate_of_birth) : null,
            phone_number: spouse_number,
            baptized: sbaptized,
          },
        });

        if (child === "yes" && childCount) {
          const childrenData = [];
          for (let i = 1; i <= Number(childCount); i++) {
            const name = req.body[`child_name${i}`];
            if (name) {
              childrenData.push({
                user_id: userId,
                type: "4",
                person_name: name,
                date_of_birth: req.body[`cdate_of_birth${i}`]
                  ? new Date(req.body[`cdate_of_birth${i}`])
                  : null,
                phone_number: req.body[`child_number${i}`],
                baptized: req.body[`cbaptized${i}`],
                gender: req.body[`cgender${i}`],
              });
            }
          }
          if (childrenData.length) {
            await prisma.familyDetails.createMany({ data: childrenData });
          }
        }
      }

      // Profile pic upload (assuming Multer middleware handles req.file)
      if (req.file) {
        const imagePath = `/uploads/organizations/${orgainisation}/images/${req.file.filename}`;
        await prisma.appuser.update({
          where: { id: userId },
          data: { profile_pic: imagePath },
        });
      }
    } else {
      // Existed user flow
      userId = existedUserId;

      await prisma.organisationUser.create({
        data: {
          user_id: userId,
          org_id: orgainisation,
          isVerified,
          activation_link,
          account_status: "0",
        },
      });
    }

    // Org details
    const orgDetails = await prisma.origanisation.findUnique({
      where: { id: orgainisation },
    });

    // Email content
    const mailData = {
      name: `${first_name} ${last_name}`,
      email,
      org_name: orgDetails.org_name,
      org_email: orgDetails.email,
      org_logo: orgDetails.logo,
      activation_link: `${process.env.APP_URL}/activate/${activation_link}`,
      from_request: "web",
    };

    // Save notification
    await prisma.notification.create({
      data: {
        is_admin: 1,
        title: "User Register",
        time: new Date().toLocaleTimeString(),
        content: `${first_name} ${last_name} Registered`,
        user_id: userId,
        org_id: orgainisation,
        is_admin_read: "false",
        module_id: userId,
        role: "Admin",
      },
    });

    // Send email (using nodemailer example)
    const transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: process.env.MAIL_PORT,
      auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: process.env.MAIL_FROM_ADDRESS,
      to: email,
      subject: "Activate your account",
      html: `<p>Hello ${first_name},</p>
             <p>Please activate your account: 
             <a href="${mailData.activation_link}">Activate</a></p>`,
    });

    return res.json({
      message:
        "You have been successfully registered! Please check your email for further instructions.",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Something went wrong" });
  }
};
