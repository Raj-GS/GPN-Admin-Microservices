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

exports.getAllCategories = async (req, res) => {
  try {
    const userRole = req.user.role;
    const userOrgId = req.user.org_id;
    const userId=req.user.id;

    const {
      type
    } = req.query;

    // Common base condition
    const baseCondition = {
      deleted_at: null,
    };

    let whereCondition = {};

    if (userRole === 1) {
      // Superadmin: see all categories
      whereCondition = baseCondition;
    } else {
      // Other roles: only see org-specific or public categories
      whereCondition = {
        ...baseCondition,
        OR: [
          { org_id: null },
          { org_id: userOrgId },
        ],
      };
    }

   let whereprayerCondition = {};
   let checked=0;

   if(type=='public'){
      checked=0;
   }
   if(type=='private'){
      checked=1
   }

    if (userRole === 1) {
      // Superadmin: see all categories
      whereprayerCondition = baseCondition;
    } else {
      // Other roles: only see org-specific or public categories
      whereprayerCondition = {
        ...baseCondition,
        OR: [
          { org_id: userOrgId },
        ],
      };
    }


    // Fetch categories
    const categories = await prisma.categories.findMany({
      where: whereCondition,
      select: {
        id:true,
        name:true
      },
      orderBy: { id: 'desc' },
    });

  const activeprayerscount = await prisma.pray_requests.count({
  where: {
    ...whereprayerCondition,
    is_answerd: 0,
    checked:checked,
    is_approved: "1",
    deleted_at: null,
  },
});

const pendingprayerscount = await prisma.pray_requests.count({
  where: {
    ...whereprayerCondition,
    is_answerd: 0,
    checked:checked,
    is_approved: null,
    deleted_at: null,
  },
});

const rejectedprayerscount = await prisma.pray_requests.count({
  where: {
    ...whereprayerCondition,
    is_answerd: 0,
    checked:checked,
    is_approved: "2",
    deleted_at: null,
  },
});

const answeredprayerscount = await prisma.pray_requests.count({
  where: {
    ...whereprayerCondition,
    is_answerd: 1,
    checked:checked,
    is_approved: "1",
    deleted_at: null,
  },
});






const activetestimoniescount = await prisma.testimonies.count({
  where: {
    ...whereprayerCondition,
    status: 1,
    deleted_at: null,
  },
});

const pendingtestimoniescount = await prisma.testimonies.count({
  where: {
    ...whereprayerCondition,
    status: 0,
    deleted_at: null,
  },
});

const rejectedtestimoniescount = await prisma.testimonies.count({
  where: {
    ...whereprayerCondition,
    status: 2,
    deleted_at: null,
  },
});


  const prayerlist = await prisma.pray_requests.findMany({
  where: {
    user_id:userId,
    is_answerd: 0,
    is_approved: "1",
    deleted_at: null,
  },
  select : {
    id:true,
    title:true,
    description:true,
    category_id:true
  }
});

    // Fetch all organisations (if needed)
    const organisations = await prisma.origanisation.findMany({
      select : {
        id:true,
        org_name:true,
        logo:true
      }
    });

    res.json({
      success: true,
      data: {
        categories: convertBigInt(categories),
        organisations: convertBigInt(organisations),
        activeprayerscount:activeprayerscount,
        pendingprayerscount:pendingprayerscount,
        rejectedprayerscount:rejectedprayerscount,
        answeredprayerscount:answeredprayerscount,
        activetestimoniescount:activetestimoniescount,
        pendingtestimoniescount:pendingtestimoniescount,
        rejectedtestimoniescount:rejectedtestimoniescount,
        prayerlist:convertBigInt(prayerlist)
      },
    });
  } catch (error) {
    console.error("Error fetching categories:", error);
    res.status(500).json({
      success: false,
      message: 'Server Error',
      error: error.message,
    });
  }
};


// controllers/prayerController.js



exports.prayersList = async (req, res) => {
  try {
    const {
      organization,
      category,
      status,
    //   fromDate,
    //   toDate,
      page = 1, // default to page 1
    } = req.body;

    const perPage = 10;
    const skip = (page - 1) * perPage;

    const userRole = req.user.role;
    const userOrgId = req.user.org_id;

    const whereClause = {
      checked: 0,
      ...(category ? { category_id: Number(category) } : {}),
      ...(organization && organization != 0 ? { org_id: Number(organization) } : 
        (userRole !== 1 ? { org_id: userOrgId } : {})),
    };

    // Status logic
    if (status) {
      switch (Number(status)) {
         case 0:
          Object.assign(whereClause, { is_answerd: 0, is_approved: null, deleted_at: null });
          break;
        case 1:
          Object.assign(whereClause, { is_answerd: 0, is_approved: "1", deleted_at: null });
          break;
       
        case 2:
          Object.assign(whereClause, { is_answerd: 0, is_approved: "2", deleted_at: null });
          break;
        case 3:
          Object.assign(whereClause, { is_answerd: 1, is_approved: "1", deleted_at: null });
          break;
        case 4:
          Object.assign(whereClause, { NOT: { deleted_at: null } });
          break;
      }
    } else {
      whereClause.deleted_at = null;
    }

    // Date filters
    // if (fromDate || toDate) {
    //   whereClause.created_at = {};
    //   if (fromDate) {
    //     whereClause.created_at.gte = new Date(fromDate);
    //   }
    //   if (toDate) {
    //     whereClause.created_at.lte = new Date(toDate);
    //   }
    // }

    // Fetch total count
    const totalCount = await prisma.pray_requests.count({
      where: whereClause,
    });

    // Fetch paginated prayers
    const prayers = await prisma.pray_requests.findMany({
      where: whereClause,
      select: {
            id: true,
            title: true,
            description:true,
            created_at: true,
            deleted_at:true,
            is_approved:true,
            is_answerd:true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true,
                profile_pic:true
              }
            },
            categories: {
              select: {
                id:true,
              name:true
              }
            },
            origanisation : {
              select: {
              id:true,
              org_name:true
              }
            }
          },
      orderBy: { id: 'desc' },
      skip,
      take: perPage,
    });

    res.json({
      success: true,
      data: convertBigInt(prayers),
      pagination: {
        total: totalCount,
        perPage,
        currentPage: Number(page),
        totalPages: Math.ceil(totalCount / perPage),
      },
    });
  } catch (error) {
    console.error("Error fetching prayer requests:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
      error: error.message,
    });
  }
};

exports.PrivatePrayersList = async (req, res) => {
  try {
    const {
      organization,
      category,
      status,
    //   fromDate,
    //   toDate,
      page = 1, // default to page 1
    } = req.body;

    const perPage = 10;
    const skip = (page - 1) * perPage;

    const userRole = req.user.role;
    const userOrgId = req.user.org_id;

    const whereClause = {
      checked: 1,
      ...(category ? { category_id: Number(category) } : {}),
      ...(organization && organization != 0 ? { org_id: Number(organization) } : 
        (userRole !== 1 ? { org_id: userOrgId } : {})),
    };

    // Status logic
    if (status) {
      switch (Number(status)) {
         case 0:
          Object.assign(whereClause, { is_answerd: 0, is_approved: null, deleted_at: null });
          break;
        case 1:
          Object.assign(whereClause, { is_answerd: 0, is_approved: "1", deleted_at: null });
          break;
       
        case 2:
          Object.assign(whereClause, { is_answerd: 0, is_approved: "2", deleted_at: null });
          break;
        case 3:
          Object.assign(whereClause, { is_answerd: 1, is_approved: "1", deleted_at: null });
          break;
        case 4:
          Object.assign(whereClause, { NOT: { deleted_at: null } });
          break;
      }
    } else {
      whereClause.deleted_at = null;
    }

    // Date filters
    // if (fromDate || toDate) {
    //   whereClause.created_at = {};
    //   if (fromDate) {
    //     whereClause.created_at.gte = new Date(fromDate);
    //   }
    //   if (toDate) {
    //     whereClause.created_at.lte = new Date(toDate);
    //   }
    // }

    // Fetch total count
    const totalCount = await prisma.pray_requests.count({
      where: whereClause,
    });

    // Fetch paginated prayers
    const prayers = await prisma.pray_requests.findMany({
      where: whereClause,
      select: {
            id: true,
            title: true,
            description:true,
            created_at: true,
            deleted_at:true,
            is_approved:true,
            is_answerd:true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true,
                profile_pic:true
              }
            },
            categories: {
              select: {
                id:true,
              name:true
              }
            },
            origanisation : {
              select: {
              id:true,
              org_name:true
              }
            }
          },
      orderBy: { id: 'desc' },
      skip,
      take: perPage,
    });

    res.json({
      success: true,
      data: convertBigInt(prayers),
      pagination: {
        total: totalCount,
        perPage,
        currentPage: Number(page),
        totalPages: Math.ceil(totalCount / perPage),
      },
    });
  } catch (error) {
    console.error("Error fetching prayer requests:", error);
    res.status(500).json({
      success: false,
      message: "Server Error",
      error: error.message,
    });
  }
};


// controllers/prayerController.js

const moment = require("moment");

exports.prayerStatusChange = async (req, res) => {
  try {
    const { id, status } = req.body;

    const getUser = await prisma.pray_requests.findFirst({
      where: { id: Number(id) },
      select: {
        id: true,
        user_id: true,
        title: true,
        org_id: true,
        edit_request: true,
      },
    });

    if (!getUser) {
      return res.status(404).json({ success: false, message: "Prayer request not found" });
    }

    // If status is Approved and not edit_request
    if (status === 1 && getUser.edit_request !== "yes") {
      const notifyUser = await prisma.app_users.findUnique({
        where: { id: getUser.user_id },
        select: {
          first_name: true,
          last_name: true,
        },
      });

      const now = moment().format("HH:mm:ss");

      // Notification to all
      await prisma.notification.create({
        data: {
          is_admin: 0,
          title: "Prayer",
          time: now,
          content: `A prayer request has been added by ${notifyUser.first_name} ${notifyUser.last_name}`,
          user_id: getUser.user_id,
          org_id: getUser.org_id,
          is_admin_read: "false",
          module_id: getUser.id,
          role: "All",
          created_at: new Date()
        },
      });

      // Notification to user
      await prisma.notification.create({
        data: {
          is_admin: 0,
          title: "Prayer",
          time: now,
          content: "Your prayer request has been approved",
          user_id: getUser.user_id,
          org_id: getUser.org_id,
          is_admin_read: "false",
          module_id: getUser.id,
          role: "User",
          created_at: new Date()
        },
      });
    }

    // If status Approved and edit_request == yes
    if (status === 1 && getUser.edit_request === "yes") {
      const checkEditPray = await prisma.edit_prayer.findFirst({
        where: { prayer_id: Number(id) },
      });

      if (checkEditPray) {
        await prisma.pray_requests.update({
          where: { id: Number(id) },
          data: {
            title: checkEditPray.title,
            description: checkEditPray.description,
            is_approved: status,
            edit_request: null,
          },
        });
      }
    } else {
      // Otherwise, just update approval status
      await prisma.pray_requests.update({
        where: { id: Number(id) },
        data: {
          is_approved: status,
        },
      });
    }

    return res.json({ success: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success: false });
  }
};




exports.AddPublicPrayer = async (req, res) => {
  try {
    const {
      category,
      title,
      description,
      origanisation,
      priority, // Default to 1 if not provided
    } = req.body;

    const userId = req.user?.id;
    const orgId = req.user?.org_id;

    if (!userId || !orgId) {
      return res.status(401).json({ error: 'Unauthorized: User not found' });
    }

    // Create prayer request
    const createdPrayer = await prisma.pray_requests.create({
      data: {
        category_id: parseInt(category),
        title: title,
        description,
        is_approved: "1",
        org_id: parseInt(orgId),
        user_id: userId,
        importance: priority,
        created_at: new Date()
      },
    });

    // Get organization details
    const organisation = await prisma.origanisation.findUnique({
      where: { id: orgId },
    });

    if (!organisation) {
      return res.status(404).json({ error: 'Organisation not found' });
    }

    // Create notification
    await prisma.notification.create({
      data: {
        is_admin: 1,
        title: 'prayer',
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        content: `New prayer request by ${organisation.org_name}`,
        user_id: userId,
        org_id: orgId,
        is_admin_read: false,
        module_id: Number(createdPrayer.id),
        created_at: new Date()
      },
    });

    return res.status(200).json({ message: 'Prayer posted successfully!' });
  } catch (error) {
    console.error('Error creating prayer:', error);
    return res.status(500).json({ error: 'Something went wrong' });
  }
};



// GET /api/testimonies?page=1&status=approved&category=healing&fromDate=2025-01-01&toDate=2025-12-31
exports.getTestimonies = async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 10;
  const offset = (page - 1) * limit;

  const {
    status,        // e.g., 'approved', 'pending'
    category,      // e.g., 'healing', 'deliverance'
    fromDate,      // e.g., '2025-01-01'
    toDate         // e.g., '2025-12-31'
  } = req.body;

  const filters = {};

  // Apply optional filters
  if (status) {
    filters.status = Number(status);
  }

  if (category) {
    filters.category_id = category;
  }

  if (fromDate || toDate) {
    filters.created_at = {};
    if (fromDate) filters.created_at.gte = new Date(fromDate);
    if (toDate) filters.created_at.lte = new Date(toDate);
  }

  try {
    const [testimonies, total] = await Promise.all([
      prisma.testimonies.findMany({
        where: filters,

        select: {
            id: true,
            title: true,
            description:true,
            status:true,
            created_at: true,
            deleted_at:true,
            prayer_id:true,
            app_users: {
              select: {
                id: true,
                first_name: true,
                last_name: true,
                profile_pic:true
              }
            },
            categories: {
              select: {
                id:true,
              name:true
              }
            },
            origanisation : {
              select: {
              id:true,
              org_name:true
              }
            }
          },

        skip: offset,
        take: limit,
        orderBy: {
          created_at: 'desc',
        },
      }),
      prisma.testimonies.count({
        where: filters,
      }),
    ]);

    return res.json({
      success: true,
      data: convertBigInt(testimonies),
      pagination: {
        total,
        page,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('Error fetching testimonies:', error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong while fetching testimonies.',
    });
  }
};




exports.TestimonyStatusChange = async (req, res) => {
  try {
    const { id, status } = req.body;

    const testimony = await prisma.testimonies.findFirst({
      where: { id: parseInt(id) },
      select: {
        id: true,
        user_id: true,
        title: true,
        org_id: true,
        edit_request: true,
      },
    });

    if (!testimony) {
      return res.status(404).json({ message: 'Testimony not found' });
    }

    // If approved and not an edit request
    if (status === 1 && testimony.edit_request !== 'yes') {
      const notifyUser = await prisma.app_users.findUnique({
        where: { id: testimony.user_id },
        select: {
          first_name: true,
          last_name: true,
        },
      });

      const timeNow = new Date().toLocaleTimeString('en-GB', { hour12: false });

      // Notification 1: To all
      await prisma.notification.create({
        data: {
          is_admin: 1,
          title: 'Testimony',
          time: timeNow,
          content: `New Testimony added by ${notifyUser?.first_name} ${notifyUser?.last_name}`,
          user_id: testimony.user_id,
          org_id: Number(testimony.org_id),
          is_admin_read: 'false',
          module_id: testimony.id,
          role: 'All',
          created_at: new Date()
        },
      });

      // Notification 2: To user
      await prisma.notification.create({
        data: {
          is_admin: 1,
          title: 'Testimony',
          time: timeNow,
          content: 'Your Testimony has been approved',
          user_id: testimony.user_id,
          org_id:Number(testimony.org_id),
          is_admin_read: 'false',
          module_id: testimony.id,
          role: 'User',
          created_at: new Date()
        },
      });
    }

    // Update status
    await prisma.testimonies.update({
      where: { id: testimony.id },
      data: { status },
    });

    // If status is 3 (deleted), update deleted_at timestamp
    if (status === 3) {
      await prisma.testimonies.update({
        where: { id: testimony.id },
        data: { deleted_at: new Date() },
      });
    }

    return res.status(200).json({ message: 'Testimony status updated successfully' });
  } catch (error) {
    console.error('Error updating testimony status:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
};


// POST /api/testimonies/add

exports.AddTestimony = async (req, res) => {
  try {
    const { PrayerId, title, description } = req.body;
    const userId = req.user.id;
    const orgId = req.user.org_id;

    // 1. Fetch prayer request data
    const prayRequest = await prisma.pray_requests.findUnique({
      where: { id: parseInt(PrayerId) },
    });

    if (!prayRequest) {
      return res.status(404).json({ message: "Prayer request not found" });
    }

    // 2. Create testimony
    const newTestimony = await prisma.testimonies.create({
      data: {
        prayer_id: parseInt(PrayerId),
        category_id: prayRequest.category_id,
        title,
        description,
        user_id: userId,
        org_id: orgId,
        status: 1,
      },
    });

    await prisma.pray_requests.update({
          where: { id: Number(PrayerId) },
          data: {
            is_answerd: 1,
          },
        });

    // 3. Get organisation name
    const organisation = await prisma.origanisation.findUnique({
      where: { id: prayRequest.org_id },
    });

    // 4. Create notification
    await prisma.notification.create({
      data: {
        is_admin: 1,
        title: "Testimony",
        time: new Date().toLocaleTimeString('en-US', { hour12: false }),
        content: `New Testimony added by ${organisation.org_name}`,
        user_id: userId,
        org_id: Number(prayRequest.org_id),
        is_admin_read: "false",
        module_id: newTestimony.id,
        role: "All",
        created_at: new Date()
      },
    });

    // 5. Respond with success
    return res.status(200).json({ message: "Testimony added successfully!" });

  } catch (error) {
    console.error("Error adding testimony:", error);
    return res.status(500).json({ message: "Server error" });
  }
};




exports.updateTestimony = async (req, res) => {
  try {
    const { id, title, description } = req.body;

    const existingTestimony = await prisma.testimonies.findUnique({
      where: { id: parseInt(id) },
    });

    if (!existingTestimony) {
      return res.status(404).json({ message: 'Testimony Not Found!' });
    }

    const updatedTestimony = await prisma.testimonies.update({
      where: { id: parseInt(id) },
      data: {
        title,
        description,
      },
    });

    return res.status(200).json({
      message: 'Testimony updated successfully!',
      data: updatedTestimony,
    });

  } catch (error) {
    console.error('Error updating testimony:', error);
    return res.status(500).json({ message: 'Oops! Something went wrong', error: error.message });
  }
};
