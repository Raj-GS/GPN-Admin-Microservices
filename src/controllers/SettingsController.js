const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

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



exports.settings = async (req, res) => {
  try {
    const user = req.user; // Get authenticated user from token/session
    let pagename = 'settings';
    let organization = null;

    if (user.role === 1) { // Super admin
      const organizations = await prisma.origanisation.findMany();

      let settingsWhere = {};
      if (req.query.organization) {
        settingsWhere.org_id = Number(req.query.organization);
        organization = Number(req.query.organization);
      }

      const settings = await prisma.settings.findMany({
        where: settingsWhere,
        include: {
          origanisation: true
        },
        orderBy: { id: 'desc' },
        take: 10, // pagination: fetch 10 per page
        skip: ((Number(req.query.page) || 1) - 1) * 10
      });

      return res.json({
        pagename,
        settings:convertBigInt,
        organizations: convertBigInt(organizations),
        organization: convertBigInt(organization),
      });

    } else { // Organisation admin
      const settings = await prisma.settings.findMany({
        where: { org_id: user.org_id },
        include: { origanisation: true },
        orderBy: { id: 'desc' }
      });

      organization = await prisma.origanisation.findUnique({
        where: { id: user.org_id }
      });

      const users = await prisma.app_users.findMany({
        where: { org_id: user.org_id, role: 4 }
      });

      // approval_settings
      const approvalSettingsRaw = await prisma.approval_settings.findMany({
        where: { org_id: user.org_id }
      });

      const approvalSettings = {};
      approvalSettingsRaw.forEach(item => {
        approvalSettings[item.module_name] = {
          approval: item.approval,
          users: item.users,
          bv_status: item.bv_status
        };
      });

      const sundayWorships = await prisma.sundayworships.findMany({
        where: { org_id: user.org_id },
        orderBy: { id: 'desc' }
      });

      const bibleStudies = await prisma.bible_study.findMany({
        where: { org_id: user.org_id },
        orderBy: { id: 'desc' }
      });

      return res.json({
        pagename,
        approvalSettings:convertBigInt(approvalSettings),
        settings: convertBigInt(settings),
        organization: convertBigInt(organization),
        users: convertBigInt(users),
        sundayWorships: convertBigInt(sundayWorships),
        bibleStudies: convertBigInt(bibleStudies)
      });
    }

  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Something went wrong' });
  }
};




exports.updateAllApprovalSettings = async (req, res) => {
try {
    const approvals = req.body; // directly the object sent from frontend
    const orgId = Number(req.user.org_id); // assuming org_id comes from logged-in user
console.log('Approvals to update:', approvals);
    for (const [moduleId, settings] of Object.entries(approvals)) {

      console.log(`Updating module: ${moduleId}`, settings);
      if (moduleId === 'ride' || moduleId === 'commonPrayers') {
        // Update in settings table
        await prisma.settings.updateMany({
          where: { org_id: orgId },
          data: { [moduleId]: settings.approval }
        });
      } else {
        // Upsert into approval_settings table
      const existing = await prisma.approval_settings.findFirst({
  where: { org_id: orgId, module_name: moduleId }
});

if (existing) {
  await prisma.approval_settings.updateMany({
    where: { org_id: orgId, module_name: moduleId },
    data: {
      approval: settings.approval,
      bv_status: settings.bv_status ?? null
    }
  });
} else {
  await prisma.approval_settings.create({
    data: {
      org_id: orgId,
      module_name: moduleId,
      approval: settings.approval,
      bv_status: settings.bv_status ?? null
    }
  });
}

      }
    }

    return res.status(200).json({ message: 'Approval settings updated successfully!' });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: 'Something went wrong while updating approval settings' });
  }
};




exports.updateAllHomePageSettings = async (req, res) => {
  const { id, default: defaultValue } = req.body;
  const settings = ["hdailydevotion", "hchurchhistory", "hevents", "hworships", "htestimonies"];
  let imagePaths = {};

  try {
    // Fetch setting record
    const setting = await prisma.settings.findUnique({
      where: { id: Number(id) }
    });

    if (!setting) {
      return res.status(404).json({
        success: false,
        statusCode: 404,
        message: "Setting not found"
      });
    }

    let updateData = {};

    // Update default field if provided
    if (defaultValue) {
      updateData.hdailydevotiondefault = defaultValue;
    }

   for (let settingName of settings) {

     let settingData = req.body[settingName];

  // If it's JSON in string form, parse it
  if (typeof settingData === "string") {
    try {
      settingData = JSON.parse(settingData);
    } catch (err) {
      console.error(`Failed to parse ${settingName}:`, err);
      settingData = {};
    }
  }

  console.log(`Processing setting:`, settingData.enabled);
  // const enabledValue = req.body[settingName]?.enabled || "no";
  // console.log(`Processing setting`,req.body[settingName]?.enabled);

  // Yes/No field update
   updateData[settingName] = settingData.enabled === "yes" ? "yes" : "no";

  // console.log(`Updating setting`,updateData);

  // console.log(`Processing setting "${settingName}": enabled = ${enabledValue}`);

  const fileField = `${settingName}img`;
  const selectedImageField = `${settingName}SelectedImage`;

  // Handle file upload
  if (req.files && req.files[fileField]) {
    const imageFile = req.files[fileField][0];
    const imageName = `${Date.now()}_${settingName}${path.extname(imageFile.originalname)}`;
    const directoryPath = path.join(__dirname, `../public/organizations/${setting.org_id}/app`);

    if (!fs.existsSync(directoryPath)) {
      fs.mkdirSync(directoryPath, { recursive: true });
    }

    const fullPath = path.join(directoryPath, imageName);
    fs.renameSync(imageFile.path, fullPath);

    const relativePath = `organizations/${setting.org_id}/app/${imageName}`;
    updateData[`${settingName}img`] = relativePath;
    imagePaths[settingName] = `${req.protocol}://${req.get("host")}/${relativePath}`;
  }
  // Handle selected image path
  else if (settingData.img) {
    const selectedImagePath = settingData.img;
    updateData[`${settingName}img`] = selectedImagePath;
    imagePaths[settingName] = `${req.protocol}://${req.get("host")}/${selectedImagePath}`;
  }
}


    // Save to database
    await prisma.settings.update({
      where: { id: Number(id) },
      data: updateData
    });

    res.json({
      success: true,
      statusCode: 200,
      message: "All home page settings updated successfully",
      imagePaths
    });

  } catch (err) {
    console.error("Error updating home page settings:", err);
    res.status(500).json({
      success: false,
      statusCode: 500,
      message: `Failed to update settings: ${err.message}`
    });
  }
};




exports.updateAllBottomBarSettings= async (req, res) => {
    const { id, events, testimonies, messages, songs } = req.body;

    const bottomBarSettings = ['events', 'testimonies', 'messages', 'songs'];

    try {
        // Fetch existing setting
        const setting = await prisma.settings.findUnique({
            where: { id: Number(id) }
        });

        if (!setting) {
            return res.status(404).json({
                success: false,
                statusCode: 404,
                message: 'Setting not found'
            });
        }

        // Track which are checked
        let checkedSettings = [];
        bottomBarSettings.forEach(barSetting => {
            if (req.body[barSetting] === 'yes') {
                checkedSettings.push(barSetting);
            }
        });

        // If more than 2 are checked, keep only the last two checked
        if (checkedSettings.length > 2) {
            checkedSettings = checkedSettings.slice(-2);
        }

        // Prepare update data
        const updateData = {};
        bottomBarSettings.forEach(barSetting => {
            updateData[barSetting] = checkedSettings.includes(barSetting) ? 'yes' : 'no';
        });

        // Update in database
        const updatedSetting = await prisma.settings.update({
            where: { id: Number(id) },
            data: updateData
        });

        return res.json({
            success: true,
            statusCode: 200,
            message: 'All bottom bar settings updated successfully',
            bottomBarSettings: bottomBarSettings.reduce((acc, barSetting) => {
                acc[barSetting] = updatedSetting[barSetting];
                return acc;
            }, {})
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            statusCode: 500,
            message: `Failed to update bottom bar settings: ${error.message}`
        });
    }
}

// Assuming you have prisma models: Sundayworship, Biblestudy
// And this is inside an Express route/controller

exports.updateMediaSettings = async (req, res) => {
  try {
    const {
      wmoduleId,
      wchannel_name,
      wchannel_id,
      bmoduleId,
      bchannel_name,
      bchannel_id,
      currentOrgId
    } = req.body;

    // Sunday Worship
    if (wmoduleId !== 'New') {
      await prisma.sundayworships.update({
        where: { id: Number(wmoduleId) },
        data: {
          channel_name: wchannel_name,
          channel_id: wchannel_id,
        },
      });
    } else {
      await prisma.sundayworships.create({
        data: {
          org_id: Number(currentOrgId),
          status: 1,
          channel_name: wchannel_name,
          channel_id: wchannel_id,
        },
      });
    }

    // Bible Study
    if (bmoduleId !== 'New') {
      await prisma.bible_study.update({
        where: { id: Number(bmoduleId) },
        data: {
          channel_name: bchannel_name,
          channel_id: bchannel_id,
        },
      });
    } else {
      await prisma.bible_study.create({
        data: {
          org_id: Number(currentOrgId),
          status: 1,
          channel_name: bchannel_name,
          channel_id: bchannel_id,
        },
      });
    }

    return res.json({
      success: true,
      statusCode: 200,
    });

  } catch (error) {
    console.error('Error updating media settings:', error);
    return res.status(500).json({
      success: false,
      statusCode: 500,
      message: 'Failed to update media settings: ' + error.message,
    });
  }
};



exports.updateFaithStatement = async (req, res) => {
  try {
    const { settingId, faith_statement } = req.body;

    await prisma.settings.update({
      where: { id: Number(settingId) },
      data: { faith_statement }
    });

    return res.json({
      success: true,
      statusCode: 200
    });

  } catch (error) {
    console.error('Error updating faith statement:', error);
    return res.status(500).json({
      success: false,
      statusCode: 500,
      message: 'Internal server error'
    });
  }
};

