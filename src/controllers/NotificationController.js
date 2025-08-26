const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

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

exports.Notifications = async (req, res) => {
  try {
    const user = req.user; // comes from auth middleware (decoded JWT)
    let notifications, unreadCount;

    if (user.role !== 1) {
      // Org Admin Notifications
      notifications = await prisma.notification.findMany({
        where: {
          org_id: user.org_id,
          is_admin_read: "false", // if stored as string
          role: "Admin",
        },
        orderBy: {
          created_at: "desc",
        },
        take: 5,
      });

      unreadCount = await prisma.notification.count({
        where: {
          org_id: user.org_id,
          is_admin_read: "false",
          role: "Admin",
        },
      });
    } else {
      // Super Admin Notifications
      notifications = await prisma.notification.findMany({
        where: {
          org_id: null,
          is_admin_read: "false",
          // role: "Super Admin", // uncomment if needed
        },
        orderBy: {
          created_at: "desc",
        },
        take: 5,
      });

      unreadCount = await prisma.notification.count({
        where: {
          org_id: null,
          is_admin_read: "false",
          // role: "Super Admin",
        },
      });
    }

    // Map notifications with custom fields
    const mappedNotifications = notifications.map((n) => {
      let link = "";
      let icon = "";

      switch (n.title) {
        case "Prayer":
          link = `viewprayerdetails/${n.module_id}`;
          icon = "fa-solid fa-hands-praying";
          break;
        case "Testimony":
          link = "testimonies";
          icon = "fas fa-quote-left";
          break;
        case "User Register":
          link = `edituser/${n.module_id}`;
          icon = "fas fa-users";
          break;
        case "Organization Register":
          link = `editoriganisation/${n.module_id}`;
          icon = "fas fa-users";
          break;
        case "Rider":
          link = "drivers";
          icon = "fa fa-car";
          break;
      }

      return {
        id: n.id,
        title: n.title,
        module_id:n.module_id,
        message: n.content?.length > 50 ? n.content.substring(0, 50) + "..." : n.content,
        link,
        icon,
        timestamp: timeAgo(n.created_at),
      };
    });

    return res.json({
      unreadCount,
      notifications: convertBigInt(mappedNotifications),
    });
  } catch (error) {
    console.error("Error fetching notifications:", error);
    return res.status(500).json({ message: "Internal server error" });
  }
};

function timeAgo(mysqlDate) {
  // Both database and this calculation will be in UTC
  const createdAt = new Date(mysqlDate);
  const now = new Date();
  
  let seconds = Math.floor((now.getTime() - createdAt.getTime()) / 1000);
  
  if (seconds <= 0) {
    return 'just now';
  }
  
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);
  
  if (seconds < 60) return `${seconds} seconds ago`;
  if (minutes < 60) return `${minutes} minutes ago`;
  if (hours < 24) return `${hours} hours ago`;
  return `${days} days ago`;
}


exports.markNotificationRead = async (req, res) => {
  try {
    const { id } = req.body; // get notificationId from request body

    // Find and update the notification
    const notification = await prisma.notification.update({
      where: { id: Number(id) }, // assuming id is numeric
      data: { is_admin_read: true },
    });

    return res.json({ success: true});
  } catch (error) {
    console.error("Error updating notification:", error);

    if (error.code === "P2025") {
      // Prisma: record not found
      return res.status(404).json({ success: false, message: "Notification not found" });
    }

    return res.status(500).json({ success: false, message: "Something went wrong" });
  }
};



