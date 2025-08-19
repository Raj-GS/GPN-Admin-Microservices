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
const dayjs = require('dayjs');


function convertBigInt(obj, parentKey = '') {
  if (typeof obj === 'bigint') {
    return obj.toString();
  } else if (obj instanceof Date) {
    // Only date for specific keys like 'dob'
    if (['dob', 'date_of_birth', 'birth_date','from_date','to_date'].includes(parentKey)) {
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


exports.getSpecialCategories = async (req, res) => {
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
    const totalCategories = await prisma.session_prayer_category.count({
      where: whereCondition
    });

    // Fetch paginated records
const categories = await prisma.session_prayer_category.findMany({
  where: whereCondition,
  include: {
    origanisation: true,
    _count: {
      select: {
        session_prayers: true // Assuming the relation is called `pray_requests`
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

exports.createSpecialPrayerCategory = async (req, res) => {
  try {
    const { name } = req.body;
    console.log('category',name)

    const userRole = req.user.role;
    const sessionOrgId = req.user.org_id;

    // Determine actual org_id to save
    const org_id = userRole === 1 ? null : sessionOrgId;

    // Check if category already exists (case-insensitive match within same org)
const existingCategory = await prisma.session_prayer_category.findFirst({
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
    const newCategory = await prisma.session_prayer_category.create({
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


exports.UpdateSpecialPrayerCategory = async (req, res) => {
  try {
    const { id, name } = req.body;

    if (!id || !name) {
      return res.status(400).json({
        success: false,
        message: 'Both id and category are required.',
      });
    }

    const updatedCategory = await prisma.session_prayer_category.update({
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


exports.DeleteSpecialPrayerCategory = async (req, res) => {


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

    await prisma.session_prayer_category.update({
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

// controllers/prayerController.js



exports.createSpecialPrayer = async (req, res) => {
  try {
    const {
      title,
      description,
      prayerFrequency,
      prayerType,
      category,
      fromDate,
      toDate,
      fromTime,
      toTime,
      daysOfWeek,
      prayerPlan,
      selectedTemplateId,
      numberOfDays,
      prayerPoints,
      slotDuration,
      scriptures
    } = req.body;



    const user = req.user; // assuming auth middleware sets req.user
    const org_id = user.role === 1 ? null : user.org_id;

    const dayOfWeekString = Array.isArray(daysOfWeek) ? daysOfWeek.join(',') : '';

    // Create SessionPrayer
    const createdPrayer = await prisma.session_prayers.create({
      data: {
        title,
        category,
        description,
        from_date:new Date(fromDate).toISOString(),
        to_date:new Date(toDate).toISOString(),
        from_time:fromTime,
        to_time:toTime,
        slots: parseInt(slotDuration),
        prayer_type: prayerType,
        pray_for:prayerFrequency,
        day_of_week: dayOfWeekString,
        org_id,
        flow_type:prayerPlan,
        image: selectedTemplateId,
        number_of_days: numberOfDays ? parseInt(numberOfDays) : null,
      },
    });

    const prayerId = createdPrayer.id;

    // Add scriptures
    if (scriptures.length >= 1) {
      const scriptureData = [];
      for (let i = 1; i <= scriptures.length; i++) {
        const scripture = req.body[`scripture${i}`];
        if (scripture) {
          scriptureData.push({
            scripture,
            prayerId,
          });
        }
      }
      if (scriptureData.length) {
        await prisma.session_scriptures.createMany({ data: scriptureData });
      }
    }

    // Add prayer points
    if (user.role === 1) {
      const gppcCount = parseInt(gppc || 0);
      if (gppcCount >= 1 && Array.isArray(prayer_point)) {
        const pointsData = [];
        for (let i = 0; i < prayer_point.length; i++) {
          if (req.body[`approvedstatus${i}`] === 'yes') {
            const point = prayer_point[i];
            const tePoint = te_prayer_point?.[i] || null;
            if (point) {
              pointsData.push({
                prayer_point: point,
                te_prayer_point: tePoint,
                prayerId,
              });
            }
          }
        }
        if (pointsData.length) {
          await prisma.session_prayer_points.createMany({ data: pointsData });
        }
      }
    } else {
    //  const pc = parseInt(pointscount || 0);
      if (prayerPoints.length >= 1) {
  const pointsData = [];
  for (let i = 0; i < prayerPoints.length; i++) {
    const point = prayerPoints[i]['english'];
    const tePoint = prayerPoints[i]['telugu'];
    const category = prayerPoints[i]['title'];

    if (point) {
      pointsData.push({
        prayer_point: point,
        te_prayer_point: tePoint,
        category,
        prayerId,
      });
    }
  }

  if (pointsData.length) {
    await prisma.session_prayer_points.createMany({ data: pointsData });
  }
}

    }

    // Generate time slots
    const fromTime1 = dayjs(fromTime, 'HH:mm');
    const toTime1 = dayjs(toTime, 'HH:mm');
    const slotDuration1 = parseInt(slotDuration);
    const timeSlots = [];

    let current = fromTime1;
    while (current.isBefore(toTime1)) {
      const endSlot = current.add(slotDuration1, 'minute');
      if (endSlot.isAfter(toTime1)) break;

      timeSlots.push({
        from_slot: current.format('HH:mm'),
        to_slot: endSlot.format('HH:mm'),
        prayerId,
      });

      current = endSlot;
    }

    if (timeSlots.length) {
      await prisma.time_slots.createMany({ data: timeSlots });
    }

    return res.json({
      message: 'New Prayer added successfully!',
      prayerId,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
};




exports.SpecialPrayerList = async (req, res) => {
  try {
    const {
      organization,
      search,
      category,
      prayerStatus,
      fromDate,
      toDate,
      page = 1
    } = req.body;

    const orgId = req.user.org_id;
    const role = req.user.role;

    const take = 10;
    const skip = (parseInt(page) - 1) * take;

    const where = {
      status: 'active',
    };

    // Search filter
    if (search) {
      const terms = search.trim().split(/\s+/);
      where.OR = [
        { title: { contains: search } },
        {
          AND: terms.map(term => ({
            title: { contains: term },
          })),
        },
      ];
    }

    // Category filter
    if (category) {
      where.category = category;
    }

    // Status filter
    // if (prayerStatus) {
    //   where.status = parseInt(prayerStatus);
    // }

    // Date filters
    if (fromDate) {
      where.from_date = { gte: new Date(fromDate) };
    }
    if (toDate) {
      where.to_date = {
        ...where.to_date,
        lte: new Date(toDate),
      };
    }

    // Org filter
    if (organization && parseInt(organization) !== 0) {
      try {
        const decryptedOrgId = decrypt(organization); // Implement your decrypt function
        where.org_id = decryptedOrgId;
      } catch (err) {
        return res.status(400).json({ error: 'Invalid organization ID' });
      }
    } else if (role !== 1) {
      where.org_id = orgId;
    }

    // Fetch data with pagination
    const [data, total] = await Promise.all([
      prisma.session_prayers.findMany({
        where,
        include: {
          session_prayer_category: true,
          origanisation: true,
        },
        orderBy: {
          created_at: 'desc',
        },
        skip,
        take,
      }),
      prisma.session_prayers.count({ where }),
    ]);

    return res.json({
      data:convertBigInt(data),
      total,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / take),
    });
  } catch (error) {
    console.error('Error fetching session prayers:', error);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
};




exports.deleteSessionPrayer = async (req, res) => {
  const { id } = req.body;

  if (!id) {
    return res.status(200).json({ error: { prayer_id: ['The prayer_id field is required.'] } });
  }

  try {
    const existingPrayer = await prisma.session_prayers.findUnique({
      where: { id: parseInt(id) },
    });

    if (!existingPrayer) {
      return res.status(200).json({
        success: false,
        message: 'Prayer not Found',
      });
    }

    await prisma.session_prayers.update({
      where: { id: parseInt(id) },
      data: { status: 'inactive' }, // soft delete
    });

    return res.status(200).json({
      success: true,
      message: 'Successfully deleted',
    });

  } catch (error) {
    console.error('Delete error:', error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong',
    });
  }
};




exports.SpecialPrayerDetails = async (req, res) => {
 const { id } = req.body;

  try {

    const specialPrayer = await prisma.session_prayers.findUnique({
      where: { id: Number(id) },
      include: {
        session_scriptures: true,
        session_prayer_points: true,
      },
    });

    if (!specialPrayer) {
      return res.status(404).json({ success: false, message: 'Special prayer not found' });
    }

    return res.status(200).json({
      success: true,
      pagename: 'specialprayers',
      data:convertBigInt(specialPrayer),
    });

  } catch (error) {
    console.error('Error editing special prayer:', error);
    return res.status(500).json({ success: false, message: 'Server Error' });
  }
};



exports.updateSessionPrayer = async (req, res) => {
  try {
    const {
      title,
      description,
      prayerFrequency,
      prayerType,
      category,
      fromDate,
      toDate,
      fromTime,
      toTime,
      daysOfWeek,
      prayerPlan,
      selectedTemplateId,
      numberOfDays,
      prayerPoints,
      slotDuration,
      scriptures,
      id
    } = req.body;



    const user = req.user; // assuming auth middleware sets req.user
    const org_id = user.role === 1 ? null : user.org_id;

    const dayOfWeekString = Array.isArray(daysOfWeek) ? daysOfWeek.join(',') : '';

    // Create SessionPrayer
    const createdPrayer = await prisma.session_prayers.update({
      where:{id:Number(id)},
      data: {
        title,
        category,
        description,
        from_date:new Date(fromDate).toISOString(),
        to_date:new Date(toDate).toISOString(),
        from_time:fromTime,
        to_time:toTime,
        slots: parseInt(slotDuration),
        prayer_type: prayerType,
        pray_for:prayerFrequency,
        day_of_week: dayOfWeekString,
        org_id,
        flow_type:prayerPlan,
        image: selectedTemplateId,
        number_of_days: numberOfDays ? parseInt(numberOfDays) : null,
      },
    });


    // Add scriptures
    if (scriptures.length >= 1) {
      const scriptureData = [];
      for (let i = 1; i <= scriptures.length; i++) {
        const scripture = req.body[`scripture${i}`];
        if (scripture) {
          scriptureData.push({
            scripture,
            prayerId:Number(id),
          });
        }
      }
      if (scriptureData.length) {
        await prisma.session_scriptures.createMany({ data: scriptureData });
      }
    }

    // Add prayer points
    if (user.role === 1) {
      const gppcCount = parseInt(gppc || 0);
      if (gppcCount >= 1 && Array.isArray(prayer_point)) {
        const pointsData = [];
        for (let i = 0; i < prayer_point.length; i++) {
          if (req.body[`approvedstatus${i}`] === 'yes') {
            const point = prayer_point[i];
            const tePoint = te_prayer_point?.[i] || null;
            if (point) {
              pointsData.push({
                prayer_point: point,
                te_prayer_point: tePoint,
                prayerId:Number(id),
              });
            }
          }
        }
        if (pointsData.length) {
          await prisma.session_prayer_points.createMany({ data: pointsData });
        }
      }
    } else {
    //  const pc = parseInt(pointscount || 0);
      if (prayerPoints.length >= 1) {
  const pointsData = [];
  for (let i = 0; i < prayerPoints.length; i++) {

    const prayerId=prayerPoints[i]['id'];
    const point = prayerPoints[i]['english'];
    const tePoint = prayerPoints[i]['telugu'];
    const category = prayerPoints[i]['title'];

    if(id){

    }else {

    if (point) {
      pointsData.push({
        prayer_point: point,
        te_prayer_point: tePoint,
        category,
        prayerId:Number(id),
      });
    }
  }

  if (pointsData.length) {
    await prisma.session_prayer_points.createMany({ data: pointsData });
  }

}
}

    }

    // Generate time slots
    const fromTime1 = dayjs(fromTime, 'HH:mm');
    const toTime1 = dayjs(toTime, 'HH:mm');
    const slotDuration1 = parseInt(slotDuration);
    const timeSlots = [];

    let current = fromTime1;
    while (current.isBefore(toTime1)) {
      const endSlot = current.add(slotDuration1, 'minute');
      if (endSlot.isAfter(toTime1)) break;

      timeSlots.push({
        from_slot: current.format('HH:mm'),
        to_slot: endSlot.format('HH:mm'),
        prayerId:Number(id),
      });

      current = endSlot;
    }

    if (timeSlots.length) {
      await prisma.time_slots.createMany({ data: timeSlots });
    }

    return res.json({
      message: 'Prayer updated successfully!',
      prayerId:Number(id),
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Server error' });
  }
};





exports.subscriptionsdetails = async (req, res) => {
  try {
    const org_id = req.body.organization;
    const search = req.body.search;
    const page = parseInt(req.body.page) || 1;
    const limit = 10;
    const skip = (page - 1) * limit;

    const whereClause = {};

    // Organization filter
    if (org_id && org_id != 0) {
      try {
        whereClause.org_id = org_id; // decrypt like Laravel if needed
      } catch (err) {
        return res.status(400).json({ error: 'Invalid organization ID' });
      }
    } else {
      if (req.user.role !== 1) {
        whereClause.org_id = req.user.org_id;
      }
    }

    // Search filter
    if (search && search.trim() !== '') {
      const searchTerms = search.trim().split(/\s+/);

      whereClause.OR = [
        // Full phrase match
        {
          session_prayers: {
            title: { contains: search, mode: 'insensitive' }
          }
        },
        {
          app_users: {
            OR: [
              { first_name: { contains: search, mode: 'insensitive' } },
              { last_name: { contains: search, mode: 'insensitive' } }
            ]
          }
        },
        // Match all terms (AND logic)
        {
          AND: searchTerms.map(term => ({
            OR: [
              { session_prayers: { title: { contains: term, mode: 'insensitive' } } },
              { app_users: { first_name: { contains: term, mode: 'insensitive' } } },
              { app_users: { last_name: { contains: term, mode: 'insensitive' } } }
            ]
          }))
        }
      ];
    }

    // Get total count for pagination
    const totalCount = await prisma.special_prayers_subscribs.count({
      where: whereClause
    });

    const totalPages = Math.ceil(totalCount / limit);

    // Fetch paginated data
    const data = await prisma.special_prayers_subscribs.findMany({
      where: whereClause,
      include: {
        origanisation: true,
        time_slots: true,
        session_prayers: true,
        app_users: true
      },
      orderBy: { id: 'desc' },
      skip,
      take: limit
    });

    return res.json({
      data: convertBigInt(data),
      currentPage: page,
      totalPages,
      totalCount
    });
  } catch (error) {
    console.error('Error fetching subscriptions:', error);
    return res.status(500).json({ error: 'Server error' });
  }
};

