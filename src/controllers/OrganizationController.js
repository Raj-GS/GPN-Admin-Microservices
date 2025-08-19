const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const transporter = require('../utils/mailTransport');
const nodemailer = require('nodemailer');
const ejs = require('ejs');
const crypto = require('crypto'); // for activation link
const getActivationEmailHtml = require("../mails/activationEmail");
const VerifyUser = require('../mails/verifyuser.js');
const AdminActivateUserAccount = require('../mails/adminactivateaccount.js');

function convertBigInt(obj, parentKey = '') {
  if (typeof obj === 'bigint') {
    return obj.toString();
  } else if (obj instanceof Date) {
    // Only date for specific keys like 'dob'
    if (['dob', 'date_of_birth', 'birth_date'].includes(parentKey)) {
      return obj.toISOString().split('T')[0];
    } else {
      return obj.toISOString(); // full datetime for created_at, updated_at etc.
    }
  } else if (Array.isArray(obj)) {
    return obj.map(item => convertBigInt(item));
  } else if (obj !== null && typeof obj === 'object') {
    const newObj = {};
    for (const key in obj) {
      newObj[key] = convertBigInt(obj[key], key);
    }
    return newObj;
  }

  return obj;
}


exports.OrganizationList = async (req, res) => {
  const { search, page = 1, status } = req.body;
  const { role, org_id } = req.user;

  const limit = 10;
  const offset = (parseInt(page) - 1) * limit;

  try {
    let whereCondition = {};

    // Only add status if it's a valid enum value
    if (status && status !== '' && status !== 'All Status') {
      whereCondition.status = status; // Make sure this matches your Prisma enum values
    }

    if (search && search.trim() !== '') {

      whereCondition.org_name = {
        contains: search.trim(),
     //   mode: 'insensitive'  // Optional: only works if Prisma + DB support it
      };
    }

    if (role !== 1) {
      whereCondition.id = org_id;
    }

    const [organisations, totalCount] = await Promise.all([
      prisma.origanisation.findMany({
        where: whereCondition,
        skip: offset,
        take: limit,
        orderBy: { id: 'desc' },
        include: {
          app_users: true,
        },
      }),
      prisma.origanisation.count({
        where: whereCondition,
      }),
    ]);

    const formattedOrgs = organisations.map(org => ({
      ...org,
      total_users: org.app_users?.length || 0,
    }));

    return res.json({
      success: true,
      pagename: 'orgs',
      totalCount,
      totalPages: Math.ceil(totalCount / limit),
      currentPage: parseInt(page),
      organisations: convertBigInt(formattedOrgs),
    });

  } catch (error) {
    console.error('Error fetching organisations:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};




exports.verifyOrgStatus = async (req, res) => {
  const { id, status } = req.body;

  try {
    // 1. Update organization status
    await prisma.origanisation.update({
      where: { id: parseInt(id) },
      data: {
        status: status,
        updated_at: new Date(),
      },
    });

    // 2. Update users of that organization
    // await prisma.user.updateMany({
    //   where: { org_id: parseInt(id) },
    //   data: {
    //     status: parseInt(status),
    //     updated_at: new Date(),
    //   },
    // });

    // 3. Send email if status is verified
    if (status === 'active') {
      const org = await prisma.origanisation.findUnique({
        where: { id: parseInt(id) },
      });

      const data = {
        org_name: org.org_name,
        short_code: org.short_code,
      };

      const templatePath = path.join(__dirname, '../mails/verify-org.ejs');
      const templateHtml = fs.readFileSync(templatePath, 'utf-8');
      const htmlContent = ejs.render(templateHtml, { data });




      await transporter.sendMail({
       from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
        to: org.email,
        cc: 'inakotisanthoshi@gmail.com',
        subject: 'Welcome on board to the Glocal Prayer Network',
        html: htmlContent,
      });
    }

    return res.json({ success: true, message: 'Status updated successfully' });

  } catch (error) {
    console.error('Error verifying organization:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
};




exports.updateOrganisation = async (req, res) => {
  const {
    id,
    org_name,
    contact_person_name,
    email,
    phone,
    website,
    address,
  } = req.body;



  try {
    let logoUrl = null;

    if (req.file) {
      // File path is already handled by multer

        const path = require('path');
const fs = require('fs');

const uploadDir = path.join(__dirname, `../public/organizations/${id}/images`);

// Delete old file if exists
// if (user.profile_pic) {
//   const oldFilePath = path.join(__dirname, `../public`, new URL(user.profile_pic).pathname);

//   if (fs.existsSync(oldFilePath)) {
//     fs.unlinkSync(oldFilePath);
//   }
// }

// Generate new file name
const fileExt = path.extname(req.file.originalname); // e.g., '.jpg'
const newFileName = `${org_name}_${Date.now()}${fileExt}`;
const newFilePath = path.join(uploadDir, newFileName);

// Ensure the directory exists
fs.mkdirSync(uploadDir, { recursive: true });

// Save the file
fs.writeFileSync(newFilePath, req.file.buffer);

// Generate the public URL to store in DB
const logoUrl = `${req.protocol}://${req.get('host')}/public/organizations/${id}/images/${newFileName}`;
const logourldata = {
    logo : logoUrl
}

   await prisma.origanisation.update({
        where: { id: parseInt(id) },
        data: logourldata,
      });

    }

      // Super Admin: update org directly
      const updateData = {
        org_name: org_name,
        contact_person_name: contact_person_name,
        email,
        phone,
        website,
        address
      };

      await prisma.origanisation.update({
        where: { id: parseInt(id) },
        data: updateData,
      });

      return res.json({ success: true, message: 'Organization updated successfully!' });

  
  } catch (error) {
    console.error('Error updating organization:', error);
    return res.status(500).json({ success: false, message: 'Server Error' });
  }
};




exports.filterUsers = async (req, res) => {
  try {
    const {
      status,
      role,
      organization,
      emailStatus,
      search,
      page = 1,
      limit = 10,
    } = req.body;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const take = parseInt(limit);

    const user = req.user; // From middleware auth
    const userRole = user.role;
    const userOrgId = user.org_id;

    const rolesAry = userRole === 1 ? [2, 3, 4] : [3, 4];

    // Build filters
    const whereClause = {
      role: {
        in: rolesAry,
      },
      deleted_at: null,
    };

    if (userRole !== 1) {
      whereClause.org_id = userOrgId;
    }

    if (organization) {
      const orgId = parseInt(organization); // If encrypted, decrypt here
      whereClause.org_id = orgId;
    }

    if (role!='All Roles') {
      whereClause.role = parseInt(role);
    }

    if (status !== 'All Status') {
      whereClause.account_status = status;
    }

    // if (emailStatus !== undefined) {
    //   if (emailStatus === '0' || emailStatus === 0) {
    //     whereClause.account_status = 0;
    //   } else if (emailStatus === '1' || emailStatus === 1) {
    //     whereClause.account_status = 1;
    //   } else if (emailStatus === '2' || emailStatus === 2) {
    //     whereClause.account_status = 2;
    //   } else {
    //     whereClause.deleted_at = { not: null }; // deleted users
    //   }
    // }

    // Search conditions
    const searchClause = search
      ? {
          OR: [
            { app_users: { first_name: { contains: search } } },
            { app_users: { last_name: { contains: search } } },
            { app_users: { email: { contains: search } } },
            { origanisation: { org_name: { contains: search } } },
          ],
        }
      : {};

    // Fetch with pagination
    const [users, total] = await Promise.all([
      prisma.organisation_user.findMany({
        where: {
          ...whereClause,
          ...searchClause,
        },
        include: {
          app_users: {
            select: {
              first_name: true,
              last_name: true,
              email: true,
              phone: true,
              profile_pic:true,
              gender:true,
              baptized:true,
              marital_status:true,
              date_of_birth:true,
              address:true

            },
          },
          origanisation: {
            select: {
              org_name: true,
              id: true,
            },
          },
          roles : {
            select : {
                role:true
            }
          }
        },
        orderBy: {
          id: 'desc', // Latest user first
        },
        skip,
        take,
      }),

      prisma.organisation_user.count({
        where: {
          ...whereClause,
          ...searchClause,
        },
      }),
    ]);

    return res.json({
      users:convertBigInt(users),
      total,
      page: parseInt(page),
      limit: parseInt(limit),
      totalPages: Math.ceil(total / limit),
    });
  } catch (error) {
    console.error('Filter Users Error:', error);
    return res.status(500).json({ error: 'Server Error' });
  }
};

exports.RolesAndOrganizations = async (req, res) => {
  try {

     const user = req.user;
    const org_id = user.org_id;
    const role = user.role;

    const [roles, organizations] = await Promise.all([
      prisma.roles.findMany({
        where: {
          deleted_at: null,
          role: {
            not: 'Super Admin',
          },
        },
        orderBy: {
          created_at: 'desc',
        },
      }),
      prisma.origanisation.findMany({
        where: {
          deleted_at: null,
          status: 'active',
        },
        orderBy: {
          id: 'asc',
        },
      }),
    ]);

const currentDate = new Date();

// Initialize filter object
let wherePrayerCondition = {};
if (role !== 1) {
  wherePrayerCondition.org_id = org_id;
}

// 1. All Events Count
const allEventsCount = await prisma.events.count({
  where: {
    ...wherePrayerCondition,
  },
});

// 2. Upcoming Events Count (start_date > now, not deleted)
const upcomingEventsCount = await prisma.events.count({
  where: {
    ...wherePrayerCondition,
    start_date: {
      gt: currentDate,
    },
    deleted_at: null,
  },
});

// 3. This Month's Events Count (start_date in current month, not deleted)
const startOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth(), 1);
const endOfMonth = new Date(currentDate.getFullYear(), currentDate.getMonth() + 1, 0, 23, 59, 59);

const thisMonthEventsCount = await prisma.events.count({
  where: {
    ...wherePrayerCondition,
    start_date: {
      gte: startOfMonth,
      lte: endOfMonth,
    },
    deleted_at: null,
  },
});

// 4. Completed Events Count (start_date < now, not deleted)
const completedEventsCount = await prisma.events.count({
  where: {
    ...wherePrayerCondition,
    start_date: {
      lt: currentDate,
    },
    deleted_at: null,
  },
});


const allDriversCount = await prisma.ride_giver_details.count({
  where: {
    ...wherePrayerCondition,
  },
});

// 2. Upcoming Events Count (start_date > now, not deleted)
const activeDriversCount = await prisma.ride_giver_details.count({
  where: {
    ...wherePrayerCondition,
    approve_status:"Approve",
  },
});


const pendingDriversCount = await prisma.ride_giver_details.count({
  where: {
    ...wherePrayerCondition,
    approve_status:"Pending",
  },
});

// 2. Upcoming Events Count (start_date > now, not deleted)
const declineDriversCount = await prisma.ride_giver_details.count({
  where: {
    ...wherePrayerCondition,
   approve_status:"Decline",
  },
});

// 1. All feedback count
const allRating = await prisma.feedback.count({
  where: wherePrayerCondition,
});

// 2. Average rating
const avgData = await prisma.feedback.aggregate({
  where: wherePrayerCondition,
  _avg: {
    rating: true,
  },
});
const avgRating = avgData._avg.rating ? parseFloat(avgData._avg.rating.toFixed(1)) : 0;



const thismonthRating = await prisma.feedback.count({
  where: {
    ...wherePrayerCondition,
    created_at: {
      gte: startOfMonth,
      lt: endOfMonth,
    },
  },
});


    res.json({
      success: true,
      roles: convertBigInt(roles),
      organizations: convertBigInt(organizations),
      allEventsCount:allEventsCount,
      upcomingEventsCount:upcomingEventsCount,
      thisMonthEventsCount:thisMonthEventsCount,
      completedEventsCount:completedEventsCount,
      activeDriversCount:activeDriversCount,
      pendingDriversCount:pendingDriversCount,
      declineDriversCount:declineDriversCount,
      allDriversCount:allDriversCount,
      allRating:allRating,
      thismonthRating:thismonthRating,
      avgRating:avgRating,


    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message,
    });
  }
};

exports.UpdateUser= async(req,res) => {

      const userId = req.user?.id;
    const orgId = req.user?.org_id;
  try {
    const {
      first_name,
      last_name,
      gender,
      phone,
      baptized,
      date_of_birth,
      marital_status,
      address,
      id
    } = req.body;


    // Update user fields
    await prisma.app_users.update({
      where: { id: parseInt(id) },
      data: {
        first_name,
        last_name,
        gender,
        phone: phone,
        baptized,
        date_of_birth: new Date(date_of_birth),
        marital_status,
        address
      }
    });

    // Handle image upload
    if (req.file) {

              const uploadDir = path.join(__dirname, `../public/organizations/${orgId}/images`);
            //   const oldFilePath = user.profile_pic
            //     ? path.join(__dirname, `../public/${new URL(user.profile_pic).pathname}`)
            //     : null;
        
            //   // Delete old file
            //   if (oldFilePath && fs.existsSync(oldFilePath)) {
            //     fs.unlinkSync(oldFilePath);
            //   }
        
              // Move new file
              const newFileName = `${first_name}_${Date.now()}${path.extname(req.file.originalname)}`;
              const newFilePath = path.join(uploadDir, newFileName);
        
              // Ensure directory exists
              fs.mkdirSync(uploadDir, { recursive: true });
              fs.writeFileSync(newFilePath, req.file.buffer);
        
              // Generate public URL
              profilePicUrl = `${req.protocol}://${req.get('host')}/public/organizations/${orgId}/images/${newFileName}`;


      await prisma.app_users.update({
        where: { id: parseInt(id) },
        data: { profile_pic: profilePicUrl }
      });
    }

    return res.json({ message: 'User Details Updated successfully!' });
  } catch (error) {
    console.error('Update Error:', error);
    return res.status(500).json({ message: 'Something went wrong', error });
  }
}






exports.activateUserAccount = async (req, res) => {
  try {
    const { status, id, user_id } = req.body;

    if (status == 4) {
      // Reactivate user
      await prisma.organisation_user.update({
        where: { id: parseInt(id) },
        data: {
          deleted_at: null,
          active_request: false,
          account_status: '1',
          delete_reason: '',
          updated_at: new Date()
        }
      });

      const userDetails = await prisma.app_users.findUnique({
        where: { id: parseInt(user_id) },
        include: { orginisation: true }
      });

      const data = {
        name: `${userDetails.first_name} ${userDetails.last_name}`,
        email: userDetails.email,
        org_name: userDetails.orginisation.org_name
      };

      await sendMail(userDetails.email, 'Account Activated', AdminActivateAccountTemplate(data));
    }

    else if (status == 5) {
      // Deactivate user
      await prisma.organisation_user.update({
        where: { id: parseInt(id) },
        data: {
          account_status: '2',
          active_request: false,
          delete_reason: '',
          updated_at: new Date()
        }
      });
    }

    else if (status == 6) {
      // Send activation link
      const activation_link = crypto.randomBytes(32).toString('hex');

      const userDetails = await prisma.app_users.findUnique({
        where: { id: parseInt(user_id) },
        include: { orginisation: true }
      });

      await prisma.organisation_user.update({
        where: { id: parseInt(id) },
        data: {
          activation_link
        }
      });

      const data = {
        name: `${userDetails.first_name} ${userDetails.last_name}`,
        email: userDetails.email,
        org_name: userDetails.orginisation.org_name,
        org_email: userDetails.orginisation.email,
        org_logo: userDetails.orginisation.logo,
        activation_link: `${process.env.FRONTEND_URL}/activate/${activation_link}`,
        from_request: 'web'
      };


    // 3. Send welcome email
    const htmlContent = getActivationEmailHtml(data);

        await transporter.sendMail({
       from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
        to: userDetails.email,
        cc: 'inakotisanthoshi@gmail.com',
        subject: 'Welcome on board to the Glocal Prayer Network',
        html: htmlContent,
      });

   //   await transporter(userDetails.email, 'Activate Your Account', ActivateUserAccountTemplate(data));
    }

    else {
      // Default activation
      await prisma.organisation_user.update({
        where: { id: parseInt(id) },
        data: {
          deleted_at: null,
          account_status: status,
          active_request: 'Accepted',
          delete_reason: '',
          updated_at: new Date()
        }
      });
    }

    return res.json({
      success: true,
      message: 'User Account Activated Successfully'
    });

  } catch (error) {
    console.error('Activate user error:', error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong',
      error: error.message
    });
  }
};




// GET /api/categories
exports.getCategories = async (req, res) => {
try {
  const { search, status, page = 1, organization } = req.body;

  const userRole = req.user.role;
  const userOrgId = req.user.org_id;

  const statusFilter = status !== '' ? status : 'active';

  const limit = 10;
  const skip = (page - 1) * limit;

  let whereCondition = {};

if (status === 'deleted') {
  whereCondition.deleted_at = {
    not: null,
  };
} else {
  whereCondition.deleted_at = null;
}


  // Start building an array of AND filters
  const andFilters = [];

  // If searching by name
if (search) {
  andFilters.push({
    name: {
      contains: search.toLowerCase(),
    },
  });
}


if (status !== undefined && status !== 'deleted') {
  andFilters.push({
    status: statusFilter,
  });
}

 if (organization) {
  andFilters.push({
    org_id: parseInt(organization, 10),
  });
}

  if (userRole === 1) {
    // Superadmin can search across all organizations
    whereCondition = {
      ...whereCondition,
      ...(andFilters.length > 0 ? { AND: andFilters } : {}),
    };
  } else {
    // Other users restricted by org_id
    whereCondition = {
      ...whereCondition,
      AND: [
        {
          OR: [
            { org_id: null },
            { org_id: userOrgId },
          ],
        },
        ...(andFilters.length > 0 ? andFilters : []),
      ],
    };
  }

    // Count total matching records
    const totalCategories = await prisma.categories.count({
      where: whereCondition
    });

    // Fetch paginated records
const categories = await prisma.categories.findMany({
  where: whereCondition,
  include: {
    origanisation: true,
    _count: {
      select: {
        pray_requests: true // Assuming the relation is called `pray_requests`
      }
    }
  },
  orderBy: { id: 'desc' },
  skip,
  take: limit
});


    const organisations = await prisma.origanisation.findMany({
      where: {
          deleted_at: null,
          status: 'active',
        }});

    res.json({
      success: true,
      data: {
        categories: convertBigInt(categories),
        organisations: convertBigInt(organisations),
        totalCategories,
        totalPages: Math.ceil(totalCategories / limit),
        currentPage: parseInt(page),
        status: statusFilter,
        pagename: 'categ'
      }
    });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({
      success: false,
      message: 'Server Error',
      error: error.message
    });
  }
};

// controllers/categoryController.js
exports.UpdatePrayerCategory = async (req, res) => {
  try {
    const { id, name } = req.body;

    if (!id || !name) {
      return res.status(400).json({
        success: false,
        message: 'Both id and category are required.',
      });
    }

    const updatedCategory = await prisma.categories.update({
      where: { id: parseInt(id) },
      data: { name: name },
    });

    return res.json({
      success: true,
      message: 'Category updated successfully!',
      data: convertBigInt(updatedCategory),
    });

  } catch (error) {
    console.error('Error updating category:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message,
    });
  }
};

exports.DeletePrayerCategory = async (req, res) => {


  const { id, status } = req.body;
  console.log('post', req.body)

  try {
    let updateData = {};

    if (status === 3) {
      // Soft delete: set deleted_at timestamp
      updateData.deleted_at = new Date();
    } else {
      // Update status
      updateData.status = status;
    }

    await prisma.categories.update({
      where: { id: parseInt(id, 10) },
      data: updateData,
    });

    return res.status(200).json({
      success: true,
      statusCode: 200,
    });
  } catch (error) {
    console.error('Error updating category:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while updating category status.',
    });
  }
};
exports.createCategory = async (req, res) => {
  try {
    const { name } = req.body;
    console.log('category',name)

    const userRole = req.user.role;
    const sessionOrgId = req.user.org_id;

    // Determine actual org_id to save
    const org_id = userRole === 1 ? null : sessionOrgId;

    // Check if category already exists (case-insensitive match within same org)
const existingCategory = await prisma.categories.findFirst({
 where: {
  AND: [
    {
      name: {
        equals: name.trim().toLowerCase(),
      },
    },
    {
      org_id: org_id ?? null,
    },
  ],
}
});



    if (existingCategory) {
      return res.status(400).json({
        success: false,
        message: 'Category already exists for this organization.'
      });
    }

    // Create the category
    const newCategory = await prisma.categories.create({
      data: {
        name: name.trim(),
        org_id: org_id
      }
    });

    res.status(201).json({
      success: true,
      message: 'New category created successfully!',
      data: convertBigInt(newCategory)
    });

  } catch (error) {
    console.error('Error creating category:', error);
    res.status(500).json({
      success: false,
      message: 'Server Error',
      error: error.message
    });
  }
};


exports.updateBulkUsers = async (req, res) => {
  try {
    const { users, status } = req.body;

    for (let i = 0; i < users.length; i++) {
      const userId = parseInt(users[i]);

      if (status === 1 || status === 2) {
        await prisma.organisation_user.update({
          where: { id: userId },
          data: {
            isVerified: status,
            updated_at: new Date()
          }
        });
      } else if (status === 4) {
        await prisma.organisation_user.update({
          where: { id: userId },
          data: {
            deleted_at: null,
            account_status: "Accepted",
            active_request: "Accepted",
            delete_reason: "",
            updated_at: new Date()
          }
        });
      } else {
        await prisma.organisation_user.update({
          where: { id: userId },
          data: {
            deleted_at: new Date(),
            account_status: "Declined",
            active_request: "Accepted",
            delete_reason: "",
            updated_at: new Date()
          }
        });
      }

      // Send Emails for specific statuses
      if (status === 1 || status === 4) {
        const userDetails = await prisma.organisation_user.findUnique({
          where: { id: userId },
          include: {
            app_users: true,
            origanisation: true
          }
        });
console.log('userDetails',userDetails)
        if (userDetails && userDetails.app_users && userDetails.origanisation) {
          const data = {
            name: `${userDetails.app_users.first_name} ${userDetails.app_users.last_name}`,
            email: userDetails.app_users.email,
            org_name: userDetails.origanisation.org_name
          };

          console.log('data',data)

          if (status === 1) {

        const htmlContent = VerifyUser(data);

        await transporter.sendMail({
       from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
        to: userDetails.app_users.email,
      //  cc: 'inakotisanthoshi@gmail.com',
        subject: 'User Verification Confirmation',
        html: htmlContent,
      });
          }
          if (status === 4) {

        const htmlContent = AdminActivateUserAccount(data);

        await transporter.sendMail({
       from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
        to: userDetails.app_users.email,
     //   cc: 'inakotisanthoshi@gmail.com',
        subject: 'Glocal Prayer Account Activated',
        html: htmlContent,
      });


          }
        }
      }
    }

    return res.json({
      success: true,
      statusCode: 200
    });
  } catch (error) {
    console.error("Error updating bulk users:", error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong",
      error: error.message
    });
  }
};






exports.updateBulkOrgs = async (req, res) => {
  try {
    const { organizations, status } = req.body;

    if (!organizations || organizations.length === 0) {
      return res.status(400).json({ success: false, message: "No IDs provided" });
    }


    for (const orgId of organizations) {
      // Update organisation
      await prisma.origanisation.update({
        where: { id: Number(orgId) },
        data: {
          status: status==1 ? 'active' : 'inactive',
          updated_at: new Date(),
        },
      });

      // Update users under this organisation
      await prisma.app_users.updateMany({
        where: { org_id: Number(orgId) },
        data: {
          status: status==1 ? 'Active' : 'Inactive', // Assuming 1 is active and 2 is inactive
          updated_at: new Date(),
        },
      });

      // If status == 1, send email
      if (Number(status) === 1) {
        const orgDetails = await prisma.origanisation.findUnique({
          where: { id: Number(orgId) },
        });

        if (orgDetails) {
        


      const data = {
        org_name: orgDetails.org_name,
        short_code: orgDetails.short_code,
      };

      const templatePath = path.join(__dirname, '../mails/verify-org.ejs');
      const templateHtml = fs.readFileSync(templatePath, 'utf-8');
      const htmlContent = ejs.render(templateHtml, { data });



      await transporter.sendMail({
       from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM}>`,
        to: orgDetails.email,
        cc: 'inakotisanthoshi@gmail.com',
        subject: 'Welcome on board to the Glocal Prayer Network',
        html: htmlContent,
      });


        }
      }
    }

    return res.status(201).json({
      success: true,
      message: "Status updated successfully",
    });
  } catch (error) {
    console.error("Error updating orgs:", error);
    return res.status(500).json({
      success: false,
      message: "Server error",
      error: error.message,
    });
  }
};
