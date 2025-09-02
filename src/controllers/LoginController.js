const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const { body, validationResult } = require('express-validator');
const transporter = require('../utils/mailTransport');
const {getOtpEmailTemplate}= require('../mails/otpTemplate');
// controllers/userController.js
const {randomBytes} = require('crypto');
const path = require('path');
const fs = require('fs');

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
      firstName,
      lastName,
      email,
      phone,
      gender,
      orgId,
      password,
      baptized,
      date_of_birth,
      maritalStatus,
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
        org_id: orgId,
      },
    });

    let isVerified = 0;
    if (approvalSettings && approvalSettings.approval === "no") {
      isVerified = 1;
    }

    const activation_link = randomBytes(32).toString("hex");

    let userId;

    if (existed === "") {
      // Create new user
      const hashedPassword = await bcrypt.hash(password, 10);

      const user = await prisma.app_users.create({
        data: {
          first_name:firstName,
          last_name:lastName,
          email,
          phone: phone.replace(/\s/g, ""),
          gender,
          role: "4",
          org_id: orgId,
          password: hashedPassword,
          baptized,
          date_of_birth: new Date(date_of_birth),
          marital_status:maritalStatus,
          address,
          country: 'India',
      //    country_code: address_country,
          dial_code:'+91',
          child,
          verified_status:"Verified",
          status:"Active"
        },
      });
      userId = user.id;

      // OrganisationUser link
      await prisma.organisation_user.create({
        data: {
          user_id: userId,
          org_id: orgId,
          isVerified,
          activation_link,
          account_status: "Pending",
          active_request:'Accepted'
        },
      });

      // Family Details
      // if (maritalStatus === "Unmarried") {
      //   await prisma.family_details.createMany({
      //     data: [
      //       {
      //         user_id: userId,
      //         type: "1",
      //         person_name: father_name,
      //         date_of_birth: fdate_of_birth ? new Date(fdate_of_birth) : null,
      //         phone_number: father_number,
      //         baptized: fbaptized,
      //       },
      //       {
      //         user_id: userId,
      //         type: "2",
      //         person_name: mother_name,
      //         date_of_birth: mdate_of_birth ? new Date(mdate_of_birth) : null,
      //         phone_number: mother_number,
      //         baptized: mbaptized,
      //       },
      //     ],
      //   });
      // } else {
      //   await prisma.family_details.create({
      //     data: {
      //       user_id: userId,
      //       type: "3",
      //       person_name: spouse_name,
      //       date_of_birth: sdate_of_birth ? new Date(sdate_of_birth) : null,
      //       phone_number: spouse_number,
      //       baptized: sbaptized,
      //     },
      //   });

      //   if (child === "yes" && childCount) {
      //     const childrenData = [];
      //     for (let i = 1; i <= Number(childCount); i++) {
      //       const name = req.body[`child_name${i}`];
      //       if (name) {
      //         childrenData.push({
      //           user_id: userId,
      //           type: "4",
      //           person_name: name,
      //           date_of_birth: req.body[`cdate_of_birth${i}`]
      //             ? new Date(req.body[`cdate_of_birth${i}`])
      //             : null,
      //           phone_number: req.body[`child_number${i}`],
      //           baptized: req.body[`cbaptized${i}`],
      //           gender: req.body[`cgender${i}`],
      //         });
      //       }
      //     }
      //     if (childrenData.length) {
      //       await prisma.family_details.createMany({ data: childrenData });
      //     }
      //   }
      // }

      // Profile pic upload (assuming Multer middleware handles req.file)

           if (req.file) {
                const uploadDir = path.join(__dirname, `../public/organizations/${orgId}/images`);
                const oldFilePath = user.profile_pic
                  ? path.join(__dirname, `../public/${new URL(user.profile_pic).pathname}`)
                  : null;
          
                // Delete old file
                if (oldFilePath && fs.existsSync(oldFilePath)) {
                  fs.unlinkSync(oldFilePath);
                }
          
                // Move new file
                const newFileName = `${firstName}_${Date.now()}${path.extname(req.file.originalname)}`;
                const newFilePath = path.join(uploadDir, newFileName);
          
                // Ensure directory exists
                fs.mkdirSync(uploadDir, { recursive: true });
                fs.writeFileSync(newFilePath, req.file.buffer);
          
                // Generate public URL
                profilePicUrl = `${req.protocol}://${req.get('host')}/public/organizations/${orgId}/images/${newFileName}`;

        await prisma.app_users.update({
          where: { id: userId },
          data: { profile_pic: profilePicUrl },
        });
              }


      
      
    } else {
      // Existed user flow
      userId = existedUserId;

      await prisma.organisation_user.create({
        data: {
          user_id: userId,
          org_id: orgId,
          isVerified,
          activation_link,
          account_status: "Pending",
          active_request:'Accepted'
        },
      });
    }

    // Org details
    const orgDetails = await prisma.origanisation.findUnique({
      where: { id: orgId },
    });

    // Email content
    const mailData = {
      name: `${firstName} ${lastName}`,
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
        content: `${firstName} ${lastName} Registered`,
        user_id: userId,
        org_id: orgId,
        is_admin_read: "false",
        module_id: userId,
        role: "Admin",
      },
    });





await transporter.sendMail({
  from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
  to: email,
  subject: "Activate your account",
  html: `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome to Glocal Prayer Network</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      line-height: 1.6;
      color: #333333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
    }
    .container {
      background-color: #ffffff;
      border-radius: 10px;
      padding: 30px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    }
    .logo {
      text-align: center;
      margin-bottom: 20px;
    }
    .logo img {
      max-width: 200px;
      height: auto;
    }
    h1, h3 {
      color: #4a4a4a;
      margin-bottom: 20px;
    }
    p {
      margin-bottom: 15px;
    }
    .signature {
      margin-top: 20px;
      font-style: italic;
    }
    .button {
      display: inline-block;
      padding: 10px 20px;
      background-color: #3490dc;
      color: #fff !important;
      text-decoration: none;
      border-radius: 5px;
      margin: 20px auto;
    }
    .border-top {
      margin-top: 20px;
      padding-top: 15px;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      ${mailData.org_logo ? `<img src="${mailData.org_logo}" alt="Organization Logo" class="rounded-logo">` : ""}
    </div>
    
    <h3>Dear ${firstName},</h3>
    
    <p>Congratulations on joining the ${mailData.org_name} community! We're excited to have you on board.</p>        
    <p>We appreciate you choosing our platform for your prayer and other spiritual activities. Our goal is to provide a meaningful and enriching experience for all our members.</p>
    
    <p>To complete your registration and activate your account, please click the button below:</p>
    <div style="text-align:center;">
      <a href="${mailData.activation_link}" class="button">Activate Account</a>
    </div>
    
    <p>Once your account is activated, you'll be able to access all the great resources and benefits that come.</p>
    <p>If you have any questions or need assistance, please don't hesitate to reach out to our membership team at ${mailData.org_email}.</p>
    
    <p>We hope you'll find our platform valuable and consider recommending it to others in your community.</p>
    
    <p>Welcome to ${mailData.org_name}! We look forward to your participation and contributions.</p>

    <hr>

    <div class="border-top">
      <p>If you're having trouble clicking the "Activate Account" button, copy and paste the URL below into your web browser:</p>
      <p>${mailData.activation_link}</p>
    </div>

    <p>Blessings,</p>
    <div class="signature">
      <p>${mailData.org_name} Team</p>
    </div>
  </div>
</body>
</html>
  `
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




exports.checkAppUserExistOrNot = async (req, res) => {
  try {
    const { email, org_id } = req.body;

    // 1. Check if user exists by email
    const userDetails = await prisma.app_users.findFirst({
      where: { email: email },
    });

    if (userDetails) {
      // 2. Check if user belongs to the given organization
      const currentOrgDetails = await prisma.organisation_user.findFirst({
        where: {
          user_id: userDetails.id,
          org_id: org_id,
        },
      });

      if (currentOrgDetails) {
        return res.json({
          success: true,
          current_org: true,
          message: "This User Already Existed!",
        });
      }

      return res.json({
        success: true,
        current_org: false,
        message: "This User Already Existed!",
        data: convertBigInt(userDetails),
      });
    } else {
      return res.json({
        success: false,
        message: "This User not Existed!",
      });
    }
  } catch (error) {
    console.error("Error checking user existence:", error);
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};
