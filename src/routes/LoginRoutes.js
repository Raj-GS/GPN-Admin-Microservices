const express = require('express');
const router = express.Router();
const authController = require('../controllers/LoginController');
const profileController = require('../controllers/ProfileController');
const OrganizationController = require('../controllers/OrganizationController');
const PrayerController = require('../controllers/PrayerController');
const EventController = require('../controllers/EventController');
const DailyDevotionController = require('../controllers/DailyDevotionController');
const SpecialPrayerController = require('../controllers/SpecialPrayerController');
const SongsController = require('../controllers/SongsController');
const SettingsController = require('../controllers/SettingsController');
const notificationController=require('../controllers/NotificationController');

const authenticateToken = require('../middleware/auth');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

//////////// Login /////////////////////////////////

router.post('/login', authController.login);
router.get('/db-check', authController.dbCheck);
router.post('/org-details', authController.OrgDetails);

router.post('/forgotpassword', authController.forgotPassword);

//////////// My Profile /////////////////////////////////

router.get('/my-profile', authenticateToken, profileController.profile);
router.post('/update-profile', upload.single('profile_pic'), authenticateToken, profileController.profileupdate);
router.post('/update-organization', upload.single('logo'), authenticateToken, profileController.updateOrganization);
router.post('/change-password', authenticateToken, profileController.updatePassword);

//////////// Dashboard /////////////////////////////////

router.get('/dashboard-counts', authenticateToken, profileController.DashboardCounts);
router.get('/notifications', authenticateToken, notificationController.Notifications);
router.post('/readnotification', authenticateToken, notificationController.markNotificationRead);
//////////// Languages /////////////////////////////////

router.get('/languages', authenticateToken, profileController.Languages);
router.post('/add-language', authenticateToken, profileController.AddLanguage);
router.post('/update-language', authenticateToken, profileController.UpdateLanguage);
router.post('/delete-language', authenticateToken, profileController.DeleteLanguage);

//////////// Roles /////////////////////////////////

router.get('/roles', authenticateToken, profileController.Roles);
router.post('/add-role', authenticateToken, profileController.AddRole);
router.post('/update-role', authenticateToken, profileController.UpdateRole);
router.post('/delete-role', authenticateToken, profileController.DeleteRole);

//////////// Roles & Permissions /////////////////////////////////

router.get('/roles-permissions', authenticateToken, profileController.RolesAndPermission);
router.post('/user-permissions', authenticateToken, profileController.getUserPermissions);
router.post('/save-role-permissions', authenticateToken, profileController.SaveRolePermissions);


//////////// Organization /////////////////////////////////


router.post('/organizations', authenticateToken, OrganizationController.OrganizationList);
router.put('/update-organization-status', authenticateToken, OrganizationController.verifyOrgStatus);
router.put('/sp-update-organization', upload.single('logo'), authenticateToken, OrganizationController.updateOrganisation);
router.post('/bulk-update-organizations', authenticateToken, OrganizationController.updateBulkOrgs);


//////////// Users /////////////////////////////////
router.post('/users-list', authenticateToken, OrganizationController.filterUsers);
router.get('/roles-organizations', authenticateToken, OrganizationController.RolesAndOrganizations);
router.post('/update-user', upload.single('profile_pic'), authenticateToken, OrganizationController.UpdateUser);
router.post('/update-user-status', authenticateToken, OrganizationController.activateUserAccount);
router.post('/bulk-update-users', authenticateToken, OrganizationController.updateBulkUsers);


//////////// Prayer Categories /////////////////////////////////

router.post('/get-prayer-categories', authenticateToken, OrganizationController.getCategories);
router.post('/update-prayer-category', authenticateToken, OrganizationController.UpdatePrayerCategory);
router.post('/delete-prayer-category', authenticateToken, OrganizationController.DeletePrayerCategory);
router.post('/add-prayer-category', authenticateToken, OrganizationController.createCategory);


//////////// Public Prayers /////////////////////////////////


router.get('/all-prayer-categories', authenticateToken, PrayerController.getAllCategories);
router.post('/public-prayer-list', authenticateToken, PrayerController.prayersList);
router.post('/approve-prayer', authenticateToken, PrayerController.prayerStatusChange);
router.post('/add-public-prayer', authenticateToken, PrayerController.AddPublicPrayer);


//////////// Private Prayers /////////////////////////////////

router.post('/private-prayer-list', authenticateToken, PrayerController.PrivatePrayersList);
router.post('/testimony-list', authenticateToken, PrayerController.getTestimonies);
router.post('/approve-testimony', authenticateToken, PrayerController.TestimonyStatusChange);
router.post('/add-testimony', authenticateToken, PrayerController.AddTestimony);
router.post('/update-testimony', authenticateToken, PrayerController.updateTestimony);

//////////// Events /////////////////////////////////

router.post('/event-list', authenticateToken, EventController.EventsList);
router.post('/add-event', upload.single('profile_pic'), authenticateToken, EventController.addEvent);
router.post('/update-event', upload.single('profile_pic'), authenticateToken, EventController.updateEvent);
router.post('/delete-event', authenticateToken, EventController.deleteEvent);


//////////// Devotion /////////////////////////////////


router.post('/devotion-list',  authenticateToken, DailyDevotionController.getDailyDevotions);
router.post('/update-devotion',  authenticateToken, DailyDevotionController.updateDailyDevotion);
router.post('/add-devotion',  authenticateToken, DailyDevotionController.createDailyDevotion);
router.post('/update-devotion-settings',  authenticateToken, DailyDevotionController.updateDevotionSetting);
router.post('/delete-devotion',  authenticateToken, DailyDevotionController.deleteDailyDevotion);

//////////// Driver /////////////////////////////////

router.post('/driver-list',  authenticateToken, DailyDevotionController.getDriversList);
router.post('/update-driver-status',  authenticateToken, DailyDevotionController.changeDriverStatus);


//////////// Feedback /////////////////////////////////

router.post('/feedback-list',  authenticateToken, DailyDevotionController.getFeedbackList);

//////////// Special Prayer Category /////////////////////////////////


router.post('/special-prayer-categories', authenticateToken, SpecialPrayerController.getSpecialCategories);
router.post('/add-special-prayer-category', authenticateToken, SpecialPrayerController.createSpecialPrayerCategory);
router.post('/update-special-prayer-category', authenticateToken, SpecialPrayerController.UpdateSpecialPrayerCategory);
router.post('/delete-special-prayer-category', authenticateToken, SpecialPrayerController.DeleteSpecialPrayerCategory);

router.post('/add-special-prayer', authenticateToken, SpecialPrayerController.createSpecialPrayer);
router.post('/special-prayer-list', authenticateToken, SpecialPrayerController.SpecialPrayerList);
router.post('/delete-special-prayer', authenticateToken, SpecialPrayerController.deleteSessionPrayer);
router.post('/update-special-prayer', authenticateToken, SpecialPrayerController.updateSessionPrayer);
router.post('/special-prayer-details', authenticateToken, SpecialPrayerController.SpecialPrayerDetails);
router.post('/prayer-subscriber-list', authenticateToken, SpecialPrayerController.subscriptionsdetails);
router.post('/praye-for-nation', authenticateToken, SpecialPrayerController.prayForTheNation);
router.post('/update-pray-for-nation', authenticateToken, SpecialPrayerController.updateNationPrayer);



//////////// Songs /////////////////////////////////
router.post('/filter-songs', authenticateToken, SongsController.filterSongs);
router.get('/get-song-number', authenticateToken, SongsController.getSongNumber);
router.post('/add-song', authenticateToken, SongsController.addSong);
router.post('/get-song-details', authenticateToken, SongsController.SongDetails);
router.post('/update-song', authenticateToken, SongsController.updateSong);
router.post('/delete-song', authenticateToken, SongsController.deleteSong);
router.post('/update-songs-settings', authenticateToken, SongsController.updateSongsSettings); // renamed from
router.post('/import-pdf-songs', upload.single('file'),authenticateToken, SongsController.importSongsPdf);
router.get('/songs-pdf-list', authenticateToken, SongsController.getPdfSongs);
router.post('/add-songs-to-organization', authenticateToken, SongsController.addSongsToOrg); // renamed from
//////////// Settings /////////////////////////////////
router.get('/settings', authenticateToken, SettingsController.settings);
router.post('/update-approval-settings', authenticateToken, SettingsController.updateAllApprovalSettings);
router.post(
  '/update-home-settings',
  upload.array('files', 10), // 'files' is the field name, 10 is max count
  authenticateToken,
  SettingsController.updateAllHomePageSettings
);

router.post(
  '/update-bottom-bar-settings',
  authenticateToken,
  SettingsController.updateAllBottomBarSettings
);

router.post('/update-youtube-settings', authenticateToken, SettingsController.updateMediaSettings);
router.post('/update-faithstatement-settings', authenticateToken, SettingsController.updateFaithStatement);


module.exports = router;
