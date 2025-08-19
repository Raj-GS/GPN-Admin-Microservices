const express = require('express');
const cors = require('cors');
const path = require('path');

const specialPrayerRoutes = require('./routes/LoginRoutes');
const app = express();
app.use(cors());
app.use(express.json());
app.use('/public', express.static(path.join(__dirname, 'public')));

app.use('/api/admin', specialPrayerRoutes);

module.exports = app;
