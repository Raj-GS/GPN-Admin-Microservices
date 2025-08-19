const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const fs = require("fs");
const path = require("path");

function convertBigInt(obj, parentKey = '') {
  if (typeof obj === 'bigint') {
    return obj.toString();
  } else if (obj instanceof Date) {
    // Format only date for specific keys
    if (['dob', 'date_of_birth', 'birth_date'].includes(parentKey)) {
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

exports.EventsList = async (req, res) => {
   try {
    const user = req.user;
    const role = user.role; // 1 = super admin
    const orgFilter = req.body.organization; // org ID
    const status = req.body.status;          // active | completed | deleted
    const search = req.body.search || "";    // search term
    const page = parseInt(req.body.page) || 1;
    const pageSize = 10;
    const skip = (page - 1) * pageSize;

    let organisationId = 0;


    const whereClause = {
     event_name: {
 contains: search.toLowerCase()
},

    };

    const currentDate = new Date();
    if (status === 'active') {
      whereClause.start_date = {
        gt: currentDate,
      };
      whereClause.deleted_at = null;
    } else if (status === 'completed') {
      whereClause.start_date = {
        lt: currentDate,
      };
      whereClause.deleted_at = null;
    } else if (status === 'deleted') {
      whereClause.deleted_at = {
        not: null,
      };
    } else {
      whereClause.deleted_at = null;
    }

    if (role === 1) {
        console.log('I am checking')
      if (orgFilter && orgFilter !== '0') {
        organisationId = parseInt(orgFilter);
        whereClause.org_id = organisationId;
      }
    } else {
      organisationId = user.org_id;
      whereClause.org_id = organisationId;
    }

    // Fetch paginated events
    const events = await prisma.events.findMany({
      where: whereClause,
      select: {
        id: true,
        event_name: true,
        description: true,
        org_id: true,
        start_date:true,
        contact_email: true,
        contact_number: true,
        contact_info: true,
        url: true,
        image: true,
        status: true,
        created_at: true,
        updated_at: true,
        deleted_at:true,

        origanisation: {
            select : {
                id:true,
                org_name:true,
                logo:true
            }
        }
      },
      skip,
      take: pageSize,
      orderBy: {
        id: 'desc',
      },
    });

    // Total count for pagination UI
    const totalEvents = await prisma.events.count({
      where: whereClause,
    });


    res.json({
      pagename: 'events',
      events:convertBigInt(events),
      organisationId,
      pagination: {
        currentPage: page,
        pageSize,
        totalPages: Math.ceil(totalEvents / pageSize),
        totalRecords: totalEvents,
      },
    });
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: 'Something went wrong.' });
  }
};



exports.updateEvent =async (req, res) => {
    const {
      id,
      origanisation,
      event_name,
      description,
      start_date,
      contact_info,
      url,
      contact_email,
      contact_number,
    } = req.body;

    try {
      const event = await prisma.events.findUnique({ where: { id: parseInt(id) } });
      if (!event) return res.status(404).json({ message: "Event not found" });

      // Update base fields
      await prisma.events.update({
        where: { id: parseInt(id) },
        data: {
          org_id: parseInt(origanisation),
          event_name,
          description,
          start_date: new Date(start_date),
          contact_info,
          url,
          contact_email,
          contact_number,
        },
      });

      // If new image is uploaded
      if (req.file) {
  const orgId = origanisation;
  const dir = path.join(__dirname, "..", "public", "organizations", orgId, "images");

  // Ensure directory exists
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const ext = path.extname(req.file.originalname);
  const fileName = `${Date.now()}-${req.file.originalname}`;
  const fullPath = path.join(dir, fileName);

  // Save buffer to disk
  fs.writeFileSync(fullPath, req.file.buffer);

  // Delete old image if it exists
  const oldImagePath = event.image?.replace(`${req.protocol}://${req.get("host")}/public/`, "");
  if (oldImagePath) {
    const oldImageFullPath = path.join(__dirname, "..", "public", oldImagePath);
    if (fs.existsSync(oldImageFullPath)) {
      fs.unlinkSync(oldImageFullPath);
    }
  }

  const newImageUrl = `${req.protocol}://${req.get("host")}/public/organizations/${orgId}/images/${fileName}`;

  await prisma.events.update({
    where: { id: parseInt(id) },
    data: { image: newImageUrl },
  });
}

      return res.status(200).json({ message: "Event updated successfully!" });
    } catch (err) {
      console.error(err);
      return res.status(500).json({ message: "Server error" });
    }
  }



exports.addEvent = async (req, res) => {
  const {
    event_name,
    description,
    start_date,
    contact_info,
    url,
    contact_email,
    contact_number,
  } = req.body;

  try {
    const orgId = req.user.org_id;
    let imageUrl = null;

    // If image uploaded, save it to disk
    if (req.file) {
const dir = path.join(__dirname, "..", "public", "organizations", String(orgId), "images");

      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      const ext = path.extname(req.file.originalname);
      const fileName = `${Date.now()}-${req.file.originalname}`;
      const fullPath = path.join(dir, fileName);

      // Save image buffer to disk
      fs.writeFileSync(fullPath, req.file.buffer);

      imageUrl = `${req.protocol}://${req.get("host")}/public/organizations/${orgId}/images/${fileName}`;
    }

    // Create event with imageUrl if available
    await prisma.events.create({
      data: {
        org_id: orgId,
        event_name,
        description,
        start_date: new Date(start_date),
        contact_info,
        url,
        contact_email,
        contact_number,
        image: imageUrl, // assuming `image` field exists in the DB
        status:"active",
        updated_at: new Date()
      },
    });

    return res.status(200).json({ message: "Event added successfully!" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error" });
  }
};

// controllers/EventController.js

exports.deleteEvent = async (req, res) => {
  const { id } = req.body;

  try {
    await prisma.events.update({
      where: { id: Number(id) }, // Ensure ID is a number if stored as Int
      data: {
        deleted_at: new Date(), // Current timestamp
      },
    });

    return res.status(200).json({
      success: true,
      statusCode: 200,
    });
  } catch (error) {
    console.error("Error deleting event:", error);
    return res.status(500).json({
      success: false,
      message: "Internal Server Error",
    });
  }
};
