const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const transporter = require('../utils/mailTransport');
const axios = require('axios');
const nodemailer = require('nodemailer');
const { subMonths, startOfMonth } = require("date-fns");


function convertBigInt(obj) {
  if (typeof obj === 'bigint') {
    return obj.toString(); // or Number(obj), but toString is safer for large IDs
  } else if (obj instanceof Date) {
    return obj.toISOString(); // convert Date to string
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

exports.profile = async (req, res) => {
  try {
    const userId = req.user?.id;
    const orgId = req.user ?. org_id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Unauthorized',
      });
    }

    const userDetails = await prisma.app_users.findFirst({
      where: { id: userId },
      select: {
        id: true,
        first_name: true,
        last_name: true,
        email:true,
        phone:true,
        profile_pic:true,
        origanisation: {
          select: {
            id: true,
            org_name: true,
            logo: true,
            short_code: true,
            address:true,
            phone:true,
            contact_person_name:true,
            website:true,
            email:true,
            update_request:true,

          },
        },
        languages: {
          select: {
            id: true,
            language: true,
          },
        },
        family_details: true,
      },
    });

    if (!userDetails) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    const editOrgDetails = await prisma.edit_org_table.findMany({
      where : {
        org_id : orgId
      },
  select: {
    org_name: true,
    logo: true,
    address: true,
    phone: true,
    contact_person_name: true,
    website: true,
    email: true,
  },
});

const response = { ...userDetails, edit_org_table: editOrgDetails };


    const weblink = `${req.protocol}://${req.get('host')}/appuserregistration/${userDetails.origanisation.short_code}`;

    return res.status(200).json({
      success: true,
      message: 'user profile',
      data: convertBigInt(response),
      weblink,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong',
    });
  }
};

exports.profileupdate = async (req, res) => {
  try {
    const userId = req.user?.id;
    const orgId = req.user?.org_id;
    const {
      first_name,
      last_name,
    } = req.body;

    // Basic validation
    if (!first_name || !last_name) {
      return res.status(200).json({
        error: {
          first_name: !first_name ? 'First name is required' : undefined,
          last_name: !last_name ? 'Last name is required' : undefined,
        },
      });
    }

    // Fetch existing user
    const user = await prisma.app_users.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
      });
    }

    let profilePicUrl = user.profile_pic;

    // Handle profile picture upload
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
      const newFileName = `${first_name}_${Date.now()}${path.extname(req.file.originalname)}`;
      const newFilePath = path.join(uploadDir, newFileName);

      // Ensure directory exists
      fs.mkdirSync(uploadDir, { recursive: true });
      fs.writeFileSync(newFilePath, req.file.buffer);

      // Generate public URL
      profilePicUrl = `${req.protocol}://${req.get('host')}/public/organizations/${orgId}/images/${newFileName}`;
    }

    // Handle invalid date format

    // Update user profile
    await prisma.app_users.update({
      where: { id: userId },
      data: {
        first_name: first_name,
        last_name: last_name,
        profile_pic: profilePicUrl,
      },
    });


     const userDetails = await prisma.app_users.findFirst({
      where: { id: userId },
      select: {
        id: true,
        first_name: true,
        last_name: true,
        email:true,
        phone:true,
        profile_pic:true,
        origanisation: {
          select: {
            id: true,
            org_name: true,
            logo: true,
            short_code: true,
            address:true,
            phone:true,
            contact_person_name:true,
            website:true,
            email:true

          },
        },
        languages: {
          select: {
            id: true,
            language: true,
          },
        },
        family_details: true,
      },
    });

    return res.status(200).json({
      success: true,
      message: 'Profile updated',
      data: convertBigInt(userDetails),
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong',
    });
  }
};

exports.updateOrganization = async (req, res) => {
  const user = req.user; // assuming user is attached to req via auth middleware

  try {
    const orgDetails = await prisma.origanisation.findUnique({
      where: { id: user.org_id }
    });

    if (!orgDetails) {
      return res.status(404).json({ error: 'Organization not found' });
    }

        let logo = user.logo;

    // Handle profile picture upload
    if (req.file) {
      const uploadDir = path.join(__dirname, `../public/organizations/${user.org_id}/images`);
      const oldFilePath = user.logo
        ? path.join(__dirname, `../public/${new URL(user.logo).pathname}`)
        : null;

      // Delete old file
      if (oldFilePath && fs.existsSync(oldFilePath)) {
        fs.unlinkSync(oldFilePath);
      }

      // Move new file
      const newFileName = `${req.body.org_name}_${Date.now()}${path.extname(req.file.originalname)}`;
      const newFilePath = path.join(uploadDir, newFileName);

      // Ensure directory exists
      fs.mkdirSync(uploadDir, { recursive: true });
      fs.writeFileSync(newFilePath, req.file.buffer);

      // Generate public URL
      profilePicUrl = `${req.protocol}://${req.get('host')}/public/organizations/${user.org_id}/images/${newFileName}`;
    }

    const dataToInsert = {
      org_id: user.org_id,
      org_name: req.body.org_name || orgDetails.org_name,
      contact_person_name: req.body.contact_person_name || orgDetails.contact_person_name,
      email: req.body.email || orgDetails.email,
      phone: orgDetails.phone,
      logo: orgDetails.logo,
      country: req.body.country || orgDetails.country,
      country_code: orgDetails.country_code,
      dial_code: orgDetails.dial_code,
      website: req.body.website || orgDetails.website,
      address: req.body.address || orgDetails.address,
      created_at: new Date(),
      updated_at: new Date()
    };

    // Insert into edit_org_table
    const inserted = await prisma.edit_org_table.create({
      data: dataToInsert
    });

    // Update organisation update_request flag
    await prisma.origanisation.update({
      where: { id: user.org_id },
      data: { update_request: 'Requested' }
    });


  



    try {

        await transporter.sendMail({
        from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
        to: 'inakotisanthoshi@gmail.com',
        subject: 'Edit Organization Request',
        text: `Edit request submitted for organization ${dataToInsert.org_name}`
      });
      console.log('Email sent successfully');
    } catch (err) {
      console.error('Email could not be sent. Error:', err);
    }

    return res.json({ success: true, organization:orgDetails });
  } catch (err) {
    console.error('Error updating organization:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
};



exports.updatePassword = async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  try {
    // Get logged-in user ID from auth middleware
    const userId = req.user.id;

    // Fetch the user
    const user = await prisma.app_users.findUnique({
      where: { id: userId },
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found',
        statusCode: 404,
      });
    }

    // Check old password
    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: 'Old password you entered is wrong',
        statusCode: 401,
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password
    await prisma.app_users.update({
      where: { id: userId },
      data: { password: hashedPassword },
    });

    return res.status(200).json({
      success: true,
      message: 'Password changed successfully',
      statusCode: 200,
    });

  } catch (error) {
    console.error('Password update error:', error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong',
      statusCode: 500,
    });
  }
};

exports.DashboardCounts = async (req, res) => {
  try {
    const role = req.user.role;
    const orgId = req.user.org_id;

    let counts = {};
    let recent = {};

    if (role === 1) {
      // Super Admin: global stats
      counts = {
        totalOrganizations: await prisma.origanisation.count(),
        totalUsers: await prisma.app_users.count(),
        totalPrayers: await prisma.pray_requests.count(),
        approvedPrayers: await prisma.pray_requests.count({
          where: { is_approved: '1' },
        }),
        pendingPrayers: await prisma.pray_requests.count({
          where: { is_approved: '0' },
        }),
      };

      recent = {
        recentPrayers: await prisma.pray_requests.findMany({
          orderBy: { created_at: 'desc' },
          take: 2,
          select: {
            id: true,
            title: true,
            created_at: true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true
              }
            }
          }
        }),
        recentTestimonies: await prisma.testimonies.findMany({
          orderBy: { created_at: 'desc' },
          take: 2,
          select: {
            id: true,
            title: true,
            created_at: true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true
              }
            }
          }
        }),
        recentSpecialPrayerSubscriptions: await prisma.special_prayers_subscribs.findMany({
          orderBy: { created_at: 'desc' },
          take: 2,
          select: {
            id: true,
            created_at: true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true
              }
            },
            session_prayers : {
              select: {
              id: true,
              title : true,
              created_at :true
            }
            }

          }
        }),
      };
    } else if (role === 2) {
      // Org Admin: stats for their organization
      counts = {
        totalUsers: await prisma.app_users.count({
          where: { org_id: orgId },
        }),
        totalPrayers: await prisma.pray_requests.count({
          where: { org_id: orgId },
        }),
        approvedPrayers: await prisma.pray_requests.count({
          where: {
            org_id: orgId,
            is_approved: '1',
          },
        }),
        pendingPrayers: await prisma.pray_requests.count({
  where: {
    org_id: orgId,
    OR: [
      { is_approved: null },
      { is_approved: '0' }
    ],
  },
}),
      };

      recent = {
        recentPrayers: await prisma.pray_requests.findMany({
          where: { org_id: orgId },
          orderBy: { created_at: 'desc' },
          take: 2,
          select: {
            id: true,
            title: true,
            created_at: true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true
              }
            }
          }

        }),
        recentTestimonies: await prisma.testimonies.findMany({
          where: { org_id: orgId },
          orderBy: { created_at: 'desc' },
          take: 2,
          select: {
            id: true,
            title: true,
            created_at: true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true
              }
            }
          }
        }),
        recentSpecialPrayerSubscriptions: await prisma.special_prayers_subscribs.findMany({
          where: { org_id: orgId },
          orderBy: { created_at: 'desc' },
          take: 2,
          select: {
            id: true,
            created_at: true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true
              }
            },
            session_prayers : {
              select: {
              id: true,
              title : true,
              created_at :true
            }
          }
          }
        }),
      };
    } else {
      return res.status(403).json({ success: false, message: "Unauthorized access" });
    }



    var orgShortcode=await prisma.origanisation.findFirst({
          where:{id: orgId},
          select :{
            org_name:true,
            short_code:true,
          }
    })

    // Common base condition
    const baseCondition = {
      deleted_at: null,
    };

    let whereCondition = {};

    if (role === 1) {
      // Superadmin: see all categories
      whereCondition = baseCondition;
    } else {
      // Other roles: only see org-specific or public categories
      whereCondition = {
        ...baseCondition,
        OR: [
          { org_id: null },
          { org_id: orgId },
        ],
      };
    }

 const categories = await prisma.categories.findMany({
      where: whereCondition,
      select: {
        id:true,
        name:true
      },
      orderBy: { id: 'desc' },
    });



    const today = new Date();
    const fiveMonthsAgo = subMonths(today, 4);

    const result = {};
    for (let i = 4; i >= 0; i--) {
      const date = subMonths(today, i);
      const month = date.toLocaleString("default", { month: "short" });
      result[month] = { organizations: 0, users: 0 };
    }

    if (role === 1) {
      // Organizations only
      const organizations = await prisma.origanisation.findMany({
        where: {
          created_at: {
            gte: startOfMonth(fiveMonthsAgo),
          },
        },
        select: { created_at: true },
      });

      organizations.forEach((o) => {
        const month = new Date(o.created_at).toLocaleString("default", { month: "short" });
        if (result[month]) result[month].organizations += 1;
      });

    } else {
      // Users only
      const users = await prisma.app_users.findMany({
        where: {
          created_at: {
            gte: startOfMonth(fiveMonthsAgo),
          },
          org_id: orgId
        },
        select: { created_at: true },
      });

      users.forEach((u) => {
        const month = new Date(u.created_at).toLocaleString("default", { month: "short" });
        if (result[month]) result[month].users += 1;
      });
    }





    res.json({
      success: true,
      data: {
        counts:convertBigInt(counts),
        recent:convertBigInt(recent),
        categories:convertBigInt(categories),
        report:convertBigInt(result),
        orgDetails:orgShortcode
      }
    });
  } catch (error) {
    console.error("DashboardCounts error:", error);
    res.status(500).json({ success: false, message: "Server error", error: error.message });
  }
};

exports.Languages = async (req, res) => {
  try {
    const languages = await prisma.languages.findMany({
      orderBy: { created_at: 'desc' },
       where: { deleted_at: null },
    });

    res.json({
      success: true,
      data: convertBigInt(languages) // optional: only if BigInt conversion is needed
    });

  } catch (error) {
    console.error("Languages error:", error);
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message
    });
  }
};

// POST /api/language
exports.AddLanguage = async (req, res) => {
  try {
    const { language, short_code } = req.body;
    console.log('Post data',req.body)

    // Simple validation
    if (!language || !short_code) {
      return res.status(400).json({
        success: false,
        message: 'Language and Short Code are required'
      });
    }

    // Check for uniqueness
    const existing = await prisma.languages.findFirst({
      where: {
        OR: [
          { language: language },
          { short_code: short_code }
        ]
      }
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'Language or Short Code already exists'
      });
    }

    // Create new language
    const newLanguage = await prisma.languages.create({
      data: {
        language,
        short_code
      }
    });

    res.status(201).json({
      success: true,
      message: 'New language inserted successfully!',
      data: newLanguage
    });

  } catch (error) {
    console.error('insertLanguage error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};




exports.UpdateLanguage = async (req, res) => {
  try {
    const { languageId, language, short_code } = req.body;

    // Validate input
    if (!languageId || !language || !short_code) {
      return res.status(400).json({ success: false, message: "All fields are required." });
    }

    // Check if another language with the same name exists (excluding the current one)
    const existingLang = await prisma.languages.findFirst({
      where: {
        AND: [
          {
            OR: [
              { language },
              { short_code },
            ]
          },
          { NOT: { id: Number(languageId) } }
        ]
      }
    });

    if (existingLang) {
      return res.status(400).json({ success: false, message: "Language or Short Code already exists." });
    }

    // Update the language
    const updated = await prisma.languages.update({
      where: { id: Number(languageId) },
      data: {
        language,
        short_code
      }
    });

    return res.json({ success: true, message: "Language updated successfully!", data: updated });

  } catch (error) {
    console.error("Error updating language:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};


// In your controller (e.g., ProfileController.js)


exports.DeleteLanguage = async (req, res) => {
  try {
    const encryptedId = req.body.languageId;

    // Assuming decrypt is a custom function that mimics Laravel's decrypt()
  //  const id = decrypt(encryptedId); // implement this as needed

    const updated = await prisma.languages.update({
      where: { id: Number(encryptedId) },
      data: {
        deleted_at: new Date()  // sets current timestamp
      }
    });

    return res.json({ success: true, message: 'Language Deleted' });

  } catch (error) {
    console.error('Error deleting language:', error);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};



exports.Roles = async (req, res) => {
  try {
    const roles = await prisma.roles.findMany({
      orderBy: { created_at: 'desc' },
       where: { deleted_at: null },
    });

    res.json({
      success: true,
      data: convertBigInt(roles) // optional: only if BigInt conversion is needed
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message
    });
  }
};

// POST /api/language
exports.AddRole = async (req, res) => {
  try {
    const { role} = req.body;

    // Simple validation
    if (!role) {
      return res.status(400).json({
        success: false,
        message: 'Role is required'
      });
    }

    // Check for uniqueness
    const existing = await prisma.roles.findFirst({
      where: {
        OR: [
          { role: role },
        ]
      }
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: 'Role already exists'
      });
    }

    // Create new language
    const newRole = await prisma.roles.create({
      data: {
        role
      }
    });

    res.status(201).json({
      success: true,
      message: 'New Role inserted successfully!',
      data: convertBigInt(newRole)
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};




exports.UpdateRole = async (req, res) => {
  try {
    const { roleId, role } = req.body;

    // Validate input
    if (!roleId || !role) {
      return res.status(400).json({ success: false, message: "All fields are required." });
    }

    // Check if another language with the same name exists (excluding the current one)
    const existingRole = await prisma.roles.findFirst({
      where: {
        AND: [
          {
            OR: [
              { role }
            ]
          },
          { NOT: { id: Number(roleId) } }
        ]
      }
    });

    if (existingRole) {
      return res.status(400).json({ success: false, message: "Role already exists." });
    }

    // Update the language
    const updated = await prisma.roles.update({
      where: { id: Number(roleId) },
      data: {
        role
      }
    });

    return res.json({ success: true, message: "Role updated successfully!", data: convertBigInt(updated) });

  } catch (error) {
    console.log('error', error)
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};


// In your controller (e.g., ProfileController.js)


exports.DeleteRole = async (req, res) => {
  try {
    const encryptedId = req.body.roleId;

    // Assuming decrypt is a custom function that mimics Laravel's decrypt()
  //  const id = decrypt(encryptedId); // implement this as needed

    const updated = await prisma.roles.update({
      where: { id: Number(encryptedId) },
      data: {
        deleted_at: new Date()  // sets current timestamp
      }
    });

    return res.json({ success: true, message: 'Role Deleted' });

  } catch (error) {
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
};


exports.RolesAndPermission = async (req, res) => {
  try {
   const roles = await prisma.roles.findMany({
  where: {
    deleted_at: null,
    role: {
      not: 'Super Admin'
    }
  },
  orderBy: {
    created_at: 'desc'
  }
});


     const permissions = await prisma.gpn_modules.findMany({
      orderBy: { id: 'asc' },
    });

    res.json({
      success: true,
      roles:convertBigInt(roles),
      permissions:convertBigInt(permissions)
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message
    });
  }
};

// Controller function
exports.getUserPermissions = async (req, res) => {
  const roleId = req.body.id; // or req.params.id, depending on how you're passing it

  try {
    const userPermissions = await prisma.user_permissions.findMany({
      where: { role_id: roleId }
    });

    return res.json({
      success: true,
      data: convertBigInt(userPermissions)
    });
  } catch (error) {
    console.error('Error fetching user permissions:', error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong while fetching permissions'
    });
  }
};



exports.SaveRolePermissions = async (req, res) => {

 const { role_id, permissions } = req.body;

  if (!role_id || !Array.isArray(permissions)) {
    return res.status(400).json({ success: false, message: 'Invalid input' });
  }

  try {
    for (const perm of permissions) {
      const {
        permission_id,
        mview = 'no',
        madd = 'no',
        medit = 'no',
        mdelete = 'no',
        module=null,
      } = perm;


      const existingPermission = await prisma.user_permissions.findFirst({
        where: {
          role_id: parseInt(role_id),
          module_id: parseInt(permission_id),
        },
      });

      if (existingPermission) {
        await prisma.user_permissions.updateMany({
          where: {
            role_id: parseInt(role_id),
            module_id: parseInt(permission_id),
          },
          data: {
            mview,
            madd,
            medit,
            mdelete,
            module,
          },
        });
      } else {
        await prisma.user_permissions.create({
          data: {
            role_id: parseInt(role_id),
            module_id: parseInt(permission_id),
            mview,
            madd,
            medit,
            mdelete,
            module,
          },
        });
      }
    }

    return res.json({ success: true, message: 'Permissions updated successfully' });
  } catch (error) {
    console.error('Error updating permissions:', error);
    return res.status(500).json({ success: false, message: 'Server Error' });
  }
}
