const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // Import `path`
const multer = require('multer'); // Import `multer`

const Admin = require('../model/admins'); // Ensure this path is correct
const authenticateToken = require('../middleware/auth'); // Ensure this path is correct




// Configure storage for multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Determine the destination folder dynamically based on the route or other logic
    if (req.originalUrl.includes('/staff')) {
      cb(null, path.join(__dirname, '../public/uploads/staff-profiles')); // Save to /public/uploads/staff-profiles
    } else if (req.originalUrl.includes('/rooms')) {
      cb(null, path.join(__dirname, '../public/uploads/rooms')); // Save to /public/uploads/rooms
    } else if (req.originalUrl.includes('/hotels')) {
      cb(null, path.join(__dirname, '../public/uploads/hotels')); // Save to /public/uploads/hotels
    } else {
      cb(null, path.join(__dirname, '../public/uploads')); // Default uploads folder
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname)); // Unique filename
  },
});



// Create multer instance
const upload = multer({ storage });

  
// --------------------- Home Page Routes ---------------------

// Root Route
router.get('/', (req, res) => {
  res.render('home', { 
    message: 'Welcome to the Homepage!', 
    showSidebar: false // Enable sidebar for homepage
  });
});

// About Page Route
router.get('/about', (req, res) => {
  res.render('about', { 
    message: 'About Page', 
    showSidebar: false // Enable sidebar for about page
  });
});




// --------------------- Login Page Routes ---------------------
// GET: Login Page
router.get('/login', (req, res) => {
  res.render('login', { layout: false, errorMessage: null });
});

// POST: Login Action
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the admin exists in the database
    const admin = await Admin.findOne({ email: email });
    if (!admin) {
      return res.render('login', { layout: false, errorMessage: 'Admin not found' });
    }

    // Validate password
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res.render('login', { layout: false, errorMessage: 'Invalid password' });
    }

    // Issue JWT token
    const payload = {
      admin: {
        id: admin.id
      }
    };

    const jwtSecret =
      process.env.JWT_SECRET ||
      '4715aed3c946f7b0a38e6b534a9583628d84e96d10fbc04700770d572af3dce43625dd';
    jwt.sign(payload, jwtSecret, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { httpOnly: true }); // Set cookie with JWT token
      res.redirect('/dashboard');
    });
  } catch (error) {
    console.error('Error logging in admin:', error);
    res.render('login', { layout: false, errorMessage: 'Server error' });
  }
});



// --------------------- Register Page Routes ---------------------
// GET: Register Page
router.get('/register', (req, res) => {
  res.render('register', { layout: false, errorMessage: null }); // Pass showSidebar: false and handle errorMessage
});

// POST: Register Action
router.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if email already exists in the database
    const existingAdmin = await Admin.findOne({ email: email });
    if (existingAdmin) {
      return res.render('register', { layout: false, errorMessage: 'Email already exists' });
    }

    // Validate the password
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z]).{6,}$/;
    if (!passwordRegex.test(password)) {
      return res.render('register', { layout: false, errorMessage: 'Password must be at least 6 characters long and contain at least one uppercase and one lowercase letter' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new admin document
    const newAdmin = new Admin({
      name: name,
      email: email,
      password: hashedPassword
    });

    // Save the new admin document to the database
    await newAdmin.save();
    console.log('Admin registered successfully');

    // Redirect to a success page or login page
    res.redirect('/login');
  } catch (error) {
    console.error('Error registering admin:', error);
    res.render('register', { layout: false, errorMessage: 'Server error' });
  }
});



// --------------------- Profile Page Routes ---------------------

  router.get('/profile', authenticateToken, async (req, res) => {
    try {
        const admin = await Admin.findById(req.admin.id).select('-password');
        if (!admin) {
            return res.status(404).send('Admin not found');
        }
        res.render('profile', { admin });
    } catch (error) {
        console.error('Error fetching admin:', error);
        res.status(500).send('Server error');
    }
});

// POST route to handle profile updates
router.post('/profile', authenticateToken, upload.single('picture'), async (req, res) => {
    try {
        const { name, bio } = req.body;
        const picture = req.file ? '/images/' + req.file.filename : null; // Construct path to store in database

        // Find the admin by ID and update the fields
        const updatedFields = { name, bio };
        if (picture) {
            updatedFields.picture = picture;
        }

        const admin = await Admin.findByIdAndUpdate(req.admin.id, updatedFields, { new: true });

        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        res.render('profile', { admin, successMessage: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating admin profile:', error);
        res.status(500).send('Server error');
    }
});



// --------------------- Dashboard Page Routes ---------------------

// 📊 GET: Admin Dashboard with Staff on Duty
router.get('/dashboard', async (req, res) => {
    // 📦 Render Dashboard with all data
    res.render('dashboard', {
    });

});



router.get('/logout', (req, res) => {
  res.clearCookie('token'); // Clear the token cookie
  res.redirect('/login'); // Redirect to login page after logout
});





module.exports = router;
