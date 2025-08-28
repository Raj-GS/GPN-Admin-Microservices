const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();

// Allowed origins
const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "https://gpn-admin-panel.onrender.com"
];

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.log(`CORS blocked request from: ${origin}`);
      callback(new Error(`Not allowed by CORS. Origin: ${origin}`));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type", 
    "Authorization", 
    "X-Requested-With",
    "Accept",
    "Origin"
  ],
  credentials: true,
  optionsSuccessStatus: 200
};

// Apply CORS
app.use(cors(corsOptions));
// Handle preflight requests explicitly
// app.options("*", cors(corsOptions));

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use('/public', express.static(path.join(__dirname, 'public')));

// Debug middleware (remove in production)
// app.use((req, res, next) => {
//   console.log(`${req.method} ${req.path} - Origin: ${req.get('origin') || 'No origin'}`);
//   next();
// });

// Routes
const specialPrayerRoutes = require('./routes/LoginRoutes');
app.use('/api/admin', specialPrayerRoutes);

// Error handling middleware
// app.use((error, req, res, next) => {
//   if (error.message.startsWith('Not allowed by CORS')) {
//     return res.status(403).json({ 
//       error: 'CORS Error', 
//       message: 'Origin not allowed',
//       origin: req.get('origin') 
//     });
//   }
  
//   console.error('Server Error:', error);
//   res.status(500).json({ error: 'Internal server error' });
// });

module.exports = app;