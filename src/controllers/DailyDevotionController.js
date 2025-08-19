// Assuming Express.js
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

function convertBigInt(obj, parentKey = '') {
  if (typeof obj === 'bigint') {
    return obj.toString();
  } else if (obj instanceof Date) {
    // Format only date for specific keys
    if (['dob', 'date_of_birth', 'birth_date','post_date'].includes(parentKey)) {
      return obj.toISOString().split('T')[0]; // YYYY-MM-DD
    } else if (['start_date', 'end_date', 'event_date'].includes(parentKey)) {
      return obj.toISOString().slice(0, 16); // YYYY-MM-DDTHH:mm
    } else {
      return obj.toISOString(); // full ISO for created_at, updated_at, etc.
    }
  } else if (Array.isArray(obj)) {
    return obj.map(item => convertBigInt(item, parentKey)); // pass parentKey
  } else if (obj !== null && typeof obj === 'object') {
    const newObj = {};
    for (const key in obj) {
      newObj[key] = convertBigInt(obj[key], key); // pass current key
    }
    return newObj;
  }

  return obj;
}

exports.getDailyDevotions= async (req, res) => {
  try {
    const { fromDate, toDate, organization, page,search } = req.body;

    // Determine pagination
    const currentPage = parseInt(page) > 0 ? parseInt(page) : 1;
    const perPage = 10;
    const skip = (currentPage - 1) * perPage;

    // Base query filters
const where = {};

if (fromDate) {
  where.post_date = {
    gte: new Date(fromDate + 'T00:00:00'),
  };
}

if (toDate) {
  where.post_date = where.post_date
    ? { ...where.post_date, lte: new Date(toDate + 'T23:59:59') }
    : { lte: new Date(toDate + 'T23:59:59') };
}

 if (search) {
    where.title = {
      contains: search.toLowerCase(),
  //    mode: 'insensitive',
    };
  }


    // Role-based adjustments
    let settings;
    if (req.user.role === 1) {
      // Super admin
      if (organization) {
        where.org_id = parseInt(organization);
      }

      settings = await prisma.settings.findMany({
        include: { origanisation: true },
        orderBy: { id: "desc" },
      });
    } else {
      // Organisation admin
      settings = await prisma.settings.findFirst({
        where: { org_id: req.user.org_id },
        orderBy: { id: "desc" },
      });

      if (settings?.hdailydevotiondefault === "yes") {
        where.org_id = null;
      } else {
        where.org_id = req.user.org_id;
      }
    }


    // Fetch paginated data and total count in one transaction
    const [devotions, totalCount] = await prisma.$transaction([
      prisma.daily_devotions.findMany({
        where,
       // include: { orginisation: true },
        orderBy: { post_date: "desc" },
        skip,
        take: perPage,
      }),
      prisma.daily_devotions.count({
        where,
      }),
    ]);

    // Fetch all organisations
    const organisations = await prisma.origanisation.findMany();

    res.json({
      pagename: "dailydevotion",
      devotions:convertBigInt(devotions),
      settings:convertBigInt(settings),
      organisations:convertBigInt(organisations),
      organisationId: 0,
      fromdate: fromDate || "",
      todate: toDate || "",
      organization: organization || "",
      pagination: {
        total: totalCount,
        perPage,
        currentPage,
        totalPages: Math.ceil(totalCount / perPage),
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
}


exports.updateDailyDevotion = async (req, res) => {
  try {
    const {
      id,
      post_date,
      title,
      post_content,
      quote,
      author
    } = req.body;

    // Update the record
    const updatedDevotion = await prisma.daily_devotions.update({
      where: { id: Number(id) },
      data: {
        post_date: new Date(post_date),
        title,
        post_content,
        quote,
        author,
      },
    });

    return res.json({
      success: true,
      message: 'Daily Devotion updated successfully',
      data: updatedDevotion,
    });

  } catch (error) {
    console.error('Error updating daily devotion:', error);
    return res.status(500).json({
      success: false,
      message: 'Failed to update daily devotion',
      error: error.message,
    });
  }
};



exports.createDailyDevotion = async (req, res) => {
  try {
    const {
      post_date,
      title,
      post_content, // post_content
      quote,
      author
    } = req.body;

    const org_id = req.user?.org_id; // Assuming authentication middleware adds user to req

    // Check if a devotion already exists for the same post_date and org_id
    const existingDevotion = await prisma.daily_devotions.findFirst({
      where: {
        post_date: new Date(post_date),
        org_id: org_id,
      },
    });

    if (existingDevotion) {
      return res.status(400).json({
        success: false,
        message: 'Devotion for this post date already exists.',
      });
    }

    // Create the new devotion
    const newDevotion = await prisma.daily_devotions.create({
      data: {
        org_id: org_id,
        post_date: new Date(post_date),
        title: title,
        post_content: post_content,
        quote: quote,
        author: author,
      },
    });

    return res.status(201).json({
      success: true,
      message: 'Daily Devotion created successfully',
      data: convertBigInt(newDevotion),
    });

  } catch (error) {
    console.error('Error creating daily devotion:', error);
    return res.status(500).json({
      success: false,
      message: 'Something went wrong',
      error: error.message,
    });
  }
};



exports.updateDevotionSetting = async (req, res) => {
  const { devotionType } = req.body;
  const org_id = req.user?.org_id; // Assuming org_id is available from authenticated user

  try {
    // Find the setting by org_id
    const setting = await prisma.settings.findFirst({
      where: { org_id: org_id },
    });


    if(devotionType==true){
      var hdailydevotiondefault ='yes'
    }
    if(devotionType==false){
      var hdailydevotiondefault ='no'
    }

    // If setting not found
    if (!setting) {
      return res.status(404).json({
        success: false,
        statusCode: 404,
        message: 'Setting not found for this organization',
      });
    }

    // Update the setting
    await prisma.settings.update({
      where: { id: setting.id },
      data: {
        hdailydevotiondefault: hdailydevotiondefault,
      },
    });

    return res.status(200).json({
      success: true,
      statusCode: 200,
      message: 'Home page settings updated successfully',
    });

  } catch (error) {
    console.error('Error updating setting:', error);
    return res.status(500).json({
      success: false,
      statusCode: 500,
      message: 'Failed to update settings: ' + error.message,
    });
  }
};


// DELETE /api/daily-devotions/:id

exports.deleteDailyDevotion = async (req, res) => {
  const { id } = req.body;

  try {
    // Find the devotion entry
    const existingDevotion = await prisma.daily_devotions.findUnique({
      where: { id: Number(id) },
    });

    if (!existingDevotion) {
      return res.status(404).json({
        success: false,
        message: 'Daily Devotion not found',
      });
    }

    // Delete the devotion
    await prisma.daily_devotions.delete({
      where: { id: Number(id) },
    });

    return res.status(200).json({
      success: true,
      message: 'Daily Devotion deleted successfully',
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: 'Something went wrong while deleting the devotion',
      error: error.message,
    });
  }
};



///////////////////////////   Driver Details ///////////////////////

exports.getDriversList = async (req, res) => {
  try {
    const role = req.user.role;
    const orgId = req.user.org_id;
    const { status, filter, page = 1, search } = req.body;

    const pageSize = 10;
    const pageNumber = parseInt(page) || 1;
    const skip = (pageNumber - 1) * pageSize;

    const whereConditions = {
      AND: [],
    };

    if (role === 1) {
      if (filter && parseInt(filter) > 0) {
        whereConditions.AND.push({ org_id: parseInt(filter) });
      }
    } else {
      whereConditions.AND.push({ org_id: orgId });
    }

    if (status && status !== 'All Status') {
      whereConditions.AND.push({ approve_status: status });
    }

   if (search && search.trim() !== '') {
  whereConditions.AND.push({
    app_users: {
      OR: [
        { first_name: { contains: search } },
        { last_name: { contains: search } },
      ],
    },
  });
}


    const drivers = await prisma.ride_giver_details.findMany({
      where: whereConditions,
      skip,
      take: pageSize,
      orderBy: {
        id: 'desc',
      },
      select: {
        id: true,
        vehicle_type: true,
        vehicle_number: true,
        license: true,
        seats: true,
        user_id: true,
        org_id: true,
        approve_status: true,
        created_at: true,
        updated_at: true,
        app_users: {
          select: {
            first_name: true,
            last_name: true,
            profile_pic: true,
            email: true,
          },
        },
        origanisation: {
          select: {
            org_name: true,
          },
        },
      },
    });

    const totalCount = await prisma.ride_giver_details.count({
      where: whereConditions,
    });

    res.json({
      success: true,
      data: convertBigInt(drivers),
      pagination: {
        total: totalCount,
        page: pageNumber,
        pageSize,
        totalPages: Math.ceil(totalCount / pageSize),
      },
    });
  } catch (error) {
    console.error('Error fetching drivers:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch drivers.',
    });
  }
};


exports.changeDriverStatus = async (req, res) => {
  try {
    const { id, status } = req.body;

    // 1. Get driver details by ID
    const getGiverDetails = await prisma.ride_giver_details.findUnique({
      where: { id: Number(id) },
    });

    if (!getGiverDetails) {
      return res.status(404).json({
        success: false,
        message: 'Driver not found',
      });
    }

    // 2. Update approve_status
    await prisma.ride_giver_details.update({
      where: { id: Number(id) },
      data: {
        approve_status: status,
      },
    });

    // 3. Create notification if approved
    if (status == 'Approve') {
      await prisma.notification.create({
        data: {
          is_admin: 1,
          title: 'Driver',
          time: new Date().toTimeString().split(' ')[0], // 'HH:MM:SS'
          content: 'Your Giver details has been approved',
          user_id: getGiverDetails.user_id,
          org_id: Number(getGiverDetails.org_id),
          is_admin_read: false,
          module_id: Number(id),
          role: 'User',
        },
      });
    }

    // 4. Send response
    return res.json({
      success: true,
      statusCode: 200,
    });

  } catch (error) {
    console.error('Error changing driver status:', error);
    return res.status(500).json({
      success: false,
      message: 'Server error while changing driver status.',
    });
  }
};




exports.getFeedbackList = async (req, res) => {
  const { page = 1, search = '' } = req.body;
  const limit = 10;
  const offset = (page - 1) * limit;

  try {
    const role = req.user.role;
    const orgId = req.user.org_id;

    const whereConditions = {};

    // If not super admin, restrict by org_id
    if (role !== 1) {
      whereConditions.org_id = orgId;
    }

    // Search by user name or feedback content
if (search.trim() !== '') {
  whereConditions.OR = [
    {
      feedback: {
        contains: search,
     //   mode: 'insensitive',
      },
    },
    {
      app_users: {
        OR: [
          {
            first_name: {
              contains: search,
         //     mode: 'insensitive',
            },
          },
          {
            last_name: {
              contains: search,
          //    mode: 'insensitive',
            },
          },
        ],
      },
    },
  ];
}


//       if (search && search.trim() !== '') {
//   whereConditions.AND.push({
//     app_users: {
//       OR: [
//         { first_name: { contains: search } },
//         { last_name: { contains: search } },
//       ],
//     },
//   });
// }

    // Get feedback with pagination
    const feedbackList = await prisma.feedback.findMany({
      where: whereConditions,
      select : {

        id:true,
        rating:true,
        feedback:true,
        created_at:true,
        org_id:true,
        app_users: {
          select : {
            first_name:true,
            last_name:true,
            profile_pic:true,
            email:true
          }
          
        },
        origanisation: {
            select : {
              org_name :true
            }
          }

      },

      orderBy: {
        id: 'desc',
      },
      skip: offset,
      take: limit,
    });

    // Get total count for pagination
    const totalCount = await prisma.feedback.count({
      where: whereConditions,
    });

    res.status(200).json({
      success: true,
      data: convertBigInt(feedbackList),
      pagination: {
        total: totalCount,
        currentPage: Number(page),
        totalPages: Math.ceil(totalCount / limit),
      },
    });
  } catch (error) {
    console.error('Error fetching feedback:', error);
    res.status(500).json({
      success: false,
      message: 'Internal Server Error',
    });
  }
};
