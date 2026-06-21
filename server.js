import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import { rateLimit } from 'express-rate-limit';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==========================================================================
// 1. ENVIRONMENT VARIABLES & STARTUP VALIDATION
// ==========================================================================
if (!process.env.JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET environment variable is not defined.');
  process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
  console.error('FATAL ERROR: JWT_SECRET is too weak. It must be at least 32 characters long.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

const app = express();
const PORT = process.env.PORT || 5000;
const NODE_ENV = process.env.NODE_ENV || 'development';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
app.set('trust proxy', 1);

// Mask and log Mongo URI
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/ss_kirana_store';
const maskedMongoUri = MONGODB_URI.replace(/\/\/([^:]+):([^@]+)@/, '//***:***@');

// Initialize Google OAuth2 Client
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// ==========================================================================
// 2. SECURITY MIDDLEWARES & CONFIGURATIONS
// ==========================================================================

// Use Helmet for secure HTTP headers
app.use(helmet());

// Dynamic CORS configuration
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
const ALLOWED_CLIENT_ORIGINS = CLIENT_ORIGIN.split(',').map(origin => origin.trim()).filter(Boolean);
const isSameHostOrigin = (origin, host) => {
  try {
    return Boolean(origin) && new URL(origin).host === host;
  } catch {
    return false;
  }
};
app.use((req, res, next) => {
  cors({
    origin: (origin, callback) => {
      const isSameHost = isSameHostOrigin(origin, req.get('host'));
      const isConfiguredOrigin = origin && ALLOWED_CLIENT_ORIGINS.includes(origin);
      const isDevLocalhost = origin && NODE_ENV === 'development' && origin.startsWith('http://localhost:');

      // Allow requests with no origin (like mobile apps/curl), same-host app requests, or configured frontend origins.
      if (!origin || isSameHost || isConfiguredOrigin || isDevLocalhost) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true
  })(req, res, next);
});

// Configure strict JSON size limit (2mb maximum to prevent body-parsing DoS)
app.use(express.json({ limit: '2mb' }));

// ==========================================================================
// 3. RATE LIMITING MIDDLEWARES
// ==========================================================================

// General API rate limiter: max 150 requests per 15 minutes per IP
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 150,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again after 15 minutes.' }
});
app.use(globalLimiter);

// Auth routes rate limiter: max 5 requests per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again after 15 minutes.' }
});

// Review submission rate limiter: max 10 reviews per 15 minutes per IP
const reviewLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many reviews submitted. Please try again after 15 minutes.' }
});

// Order creation rate limiter: max 5 checkouts per 15 minutes per IP
const orderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many checkout attempts. Please try again after 15 minutes.' }
});

// ==========================================================================
// 4. DATABASE CONNECTION
// ==========================================================================
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log(`Connected to MongoDB database at ${maskedMongoUri}`);
    seedDefaultProducts();
  })
  .catch(err => {
    console.error('MongoDB database connection error:', err);
  });

// ==========================================================================
// 5. MONGOOSE SCHEMA & MODELS DEFINITIONS
// ==========================================================================
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true, trim: true },
  photo: { type: String, default: null },
  role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

// Hash password before saving to database
userSchema.pre('save', async function() {
  if (!this.isModified('password')) return;
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  name: { type: String, required: true, trim: true },
  category: { type: String, required: true, trim: true },
  price: { type: Number, required: true },
  image: { type: String, required: true, trim: true },
  inStock: { type: Number, required: true, default: 50 },
  description: { type: String, required: true, trim: true },
  reviews: { type: Array, default: [] }
});

const Product = mongoose.model('Product', productSchema);

const orderSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  orderId: { type: String, required: true, unique: true },
  date: { type: String, required: true },
  items: [{
    id: { type: Number, required: true },
    name: { type: String, required: true },
    price: { type: Number, required: true },
    quantity: { type: Number, required: true }
  }],
  shippingDetails: {
    customerName: { type: String, required: true, trim: true },
    customerPhone: { type: String, required: true, trim: true },
    customerAddress: { type: String, required: true, trim: true },
    customerEmail: { type: String, required: true, lowercase: true, trim: true },
    paymentMethod: { type: String, required: true },
    deliveryType: { type: String, default: 'delivery' },
    shippingCost: { type: Number, required: true },
    subtotal: { type: Number, required: true },
    total: { type: Number, required: true }
  },
  status: { type: String, default: 'Processing' }
});

const Order = mongoose.model('Order', orderSchema);

// Seeding Default Products & Bootstrapping Admin User
const INITIAL_PRODUCTS = [
  { id: 1, name: 'Apple', category: 'Produce', price: 90, image: '🍎', inStock: 49, description: 'Fresh premium orchard red apples. Crispy, sweet, juicy, and rich in natural dietary fiber and Vitamin C.', reviews: [{ id: 101, author: 'Amit K.', rating: 5, comment: 'Extremely fresh and crunchy!', date: 'Jun 10, 2026' }] },
  { id: 2, name: 'Carrot', category: 'Produce', price: 60, image: '🥕', inStock: 59, description: 'Crisp organic orange carrots harvested fresh from local fields. Ideal for salads, juices, and cooking.', reviews: [] },
  { id: 3, name: 'Banana', category: 'Produce', price: 40, image: '🍌', inStock: 80, description: 'Perfectly ripe bananas. Packed with potassium, natural sugars, and quick energy. Great for smoothies.', reviews: [] },
  { id: 4, name: 'Avocado', category: 'Produce', price: 150, image: '🥑', inStock: 25, description: 'Smooth and buttery Hass avocados. Excellent source of healthy monounsaturated fats. Ready to eat.', reviews: [] },
  { id: 5, name: 'Milk (1L)', category: 'Dairy', price: 75, image: '🥛', inStock: 40, description: 'Fresh farm-sourced pasteurized whole cream milk. High in calcium, protein, and nutrients.', reviews: [{ id: 102, author: 'Ramesh P.', rating: 5, comment: 'Rich cream content, perfect for my morning chai!', date: 'Jun 14, 2026' }] },
  { id: 6, name: 'Cheddar Cheese', category: 'Dairy', price: 250, image: '🧀', inStock: 15, description: 'Rich, sharp cheddar cheese blocks. Aged to perfection, offering a savory profile for sandwiches and pairings.', reviews: [] },
  { id: 7, name: 'Butter', category: 'Dairy', price: 120, image: '🧈', inStock: 30, description: 'Pure salted creamery table butter. Made from fresh milk, perfect for spreading and baking.', reviews: [] },
  { id: 8, name: 'Bread Loaf', category: 'Bakery', price: 45, image: '🍞', inStock: 50, description: 'Freshly baked soft white sandwich bread. Sliced and ready for toasting, making sandwiches, or French toast.', reviews: [] },
  { id: 9, name: 'Chilled Cola', category: 'Beverages', price: 50, image: '🥤', inStock: 60, description: 'Sparkling refreshing cola drink with natural citrus notes and botanical extracts. Best served chilled.', reviews: [{ id: 103, author: 'Nisha M.', rating: 5, comment: 'Extremely fizzy and refreshing!', date: 'Jun 16, 2026' }] },
  { id: 10, name: 'Classic Potato Chips', category: 'Snacks', price: 40, image: '🍟', inStock: 45, description: 'Crispy salted golden potato chips. Kettle-cooked to guarantee a satisfying crunch in every bite.', reviews: [] },
  { id: 11, name: 'Herbal Toilet Soap', category: 'Pantry', price: 90, image: '🧼', inStock: 20, description: 'Soothing aloe vera and neem oil organic soap bar. Moisturizes dry skin and maintains freshness.', reviews: [] },
  { id: 12, name: 'Liquid Detergent', category: 'Pantry', price: 299, image: '🧴', inStock: 15, description: 'Concentrated eco-friendly liquid laundry detergent. Removes tough stains and preserves fabric colors.', reviews: [] }
];

async function seedDefaultProducts() {
  try {
    const count = await Product.countDocuments();
    if (count === 0) {
      await Product.insertMany(INITIAL_PRODUCTS);
      console.log('Successfully seeded database with initial products catalog.');
    }
    
    // Admin Bootstrapping Flow using Environment Variables
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    const adminName = process.env.ADMIN_NAME;

    if (adminEmail && adminPassword && adminName) {
      // Validate strength of admin bootstrap password
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,64}$/;
      if (!passwordRegex.test(adminPassword)) {
        console.error('BOOTSTRAP WARNING: ADMIN_PASSWORD does not meet strong password requirements. Admin user was NOT seeded.');
        return;
      }
      
      const adminEmailLower = adminEmail.toLowerCase();
      let adminUser = await User.findOne({ email: adminEmailLower });
      if (!adminUser) {
        await User.create({
          email: adminEmailLower,
          password: adminPassword,
          name: adminName,
          role: 'admin'
        });
        console.log(`Successfully bootstrapped admin account for: ${adminEmailLower}`);
      } else {
        // Enforce role consistency
        if (adminUser.role !== 'admin') {
          adminUser.role = 'admin';
          await adminUser.save();
          console.log(`Updated existing user ${adminEmailLower} role to admin`);
        }
      }
    } else {
      console.log('Skipping Admin bootstrapping (ADMIN_EMAIL, ADMIN_PASSWORD, or ADMIN_NAME environment variables missing).');
    }
  } catch (err) {
    console.error('Database seeding/bootstrap error:', err);
  }
}

// ==========================================================================
// 6. INPUT VALIDATION HELPERS
// ==========================================================================
function validateEmail(email) {
  if (typeof email !== 'string' || email.length > 254) return false;
  const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return regex.test(email);
}

function validatePassword(password) {
  if (typeof password !== 'string') return false;
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,64}$/;
  return regex.test(password);
}

function validateName(name) {
  return typeof name === 'string' && name.trim().length >= 1 && name.trim().length <= 50;
}

function validatePhone(phone) {
  if (typeof phone !== 'string') return false;
  const regex = /^\+?[0-9\s-]{10,15}$/;
  return regex.test(phone.trim());
}

function validatePhoto(photo) {
  if (!photo) return true;
  if (typeof photo !== 'string') return false;
  const base64Regex = /^data:image\/(jpeg|png|gif|webp);base64,[A-Za-z0-9+/=]+$/;
  const httpsRegex = /^https:\/\/[^\s$.?#].[^\s]*$/;
  
  if (photo.startsWith('data:')) {
    // Restrict size check (base64 size is approx 4/3 of byte size. 2MB = ~2.7M chars)
    if (photo.length > 2.7 * 1024 * 1024) return false;
    return base64Regex.test(photo);
  }
  return httpsRegex.test(photo) && photo.length <= 1000;
}

// ==========================================================================
// 7. REST API MIDDLEWARES
// ==========================================================================

// Authenticate JWT bearer token and load user state from database
async function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. Token missing.' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token.' });
    }
    
    try {
      // Validate that user still exists in DB
      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(403).json({ error: 'User account not found or has been deleted.' });
      }
      
      // Ensure user role in token matches database
      if (user.role !== decoded.role) {
        return res.status(403).json({ error: 'User privileges changed. Please re-authenticate.' });
      }
      
      req.user = {
        id: user._id,
        email: user.email,
        role: user.role,
        name: user.name
      };
      next();
    } catch (dbErr) {
      console.error('Token validation database error:', dbErr);
      return res.status(500).json({ error: 'Internal server validation error.' });
    }
  });
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Access forbidden. Administrator privileges required.' });
  }
  next();
}

// Optional authentication middleware (retains verified token for guest checkout scenarios)
async function optionalAuthenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return next();
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token.' });
    }
    try {
      const user = await User.findById(decoded.id);
      if (user && user.role === decoded.role) {
        req.user = {
          id: user._id,
          email: user.email,
          role: user.role,
          name: user.name
        };
      }
    } catch {
      // Ignore database errors during optional auth and proceed as guest
    }
    next();
  });
}

// ==========================================================================
// 8. REST API ENDPOINTS
// ==========================================================================

// --- AUTHENTICATION ROUTES ---

// 1. Credentials Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  let { email, password } = req.body;
  
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid email or password format.' });
  }
  
  email = email.trim().toLowerCase();
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const user = await User.findOne({ email });
    if (user && await bcrypt.compare(password, user.password)) {
      const token = jwt.sign(
        { id: user._id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );
      res.json({
        user: {
          email: user.email,
          name: user.name,
          photo: user.photo,
          role: user.role
        },
        token
      });
    } else {
      res.status(401).json({ error: 'Invalid email or password.' });
    }
  } catch (err) {
    console.error('Login database error:', err);
    res.status(500).json({ error: 'Server authentication failed.' });
  }
});

// 2. Credentials Registration
app.post('/api/auth/register', authLimiter, async (req, res) => {
  let { name, email, password } = req.body;
  
  if (typeof name !== 'string' || typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid inputs.' });
  }
  
  name = name.trim();
  email = email.trim().toLowerCase();
  
  if (!validateName(name)) {
    return res.status(400).json({ error: 'Name must be between 1 and 50 characters.' });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Password must be 8-64 characters long, containing uppercase, lowercase, numbers, and symbols.' });
  }

  try {
    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(400).json({ error: 'Email address is already registered.' });
    }
    const newUser = await User.create({
      name,
      email,
      password,
      role: 'user'
    });
    
    const token = jwt.sign(
      { id: newUser._id, email: newUser.email, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      user: {
        email: newUser.email,
        name: newUser.name,
        photo: newUser.photo,
        role: newUser.role
      },
      token
    });
  } catch (err) {
    console.error('Registration database error:', err);
    res.status(500).json({ error: 'Server registration failed.' });
  }
});

// 3. Google OAuth Verification (Backend Verification Flow)
app.post('/api/auth/google', (req, res, next) => {
  console.log('Received POST request on /api/auth/google');
  next();
}, authLimiter, async (req, res) => {
  console.log('Passed rate limiter on /api/auth/google');
  const { credential } = req.body;
  if (!googleClient) {
    return res.status(500).json({ error: 'Google OAuth is not configured on this server.' });
  }
  if (typeof credential !== 'string' || !credential) {
    return res.status(400).json({ error: 'Google ID token credential is required.' });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    if (!payload || !payload.email) {
      return res.status(400).json({ error: 'Invalid Google token payload.' });
    }
    
    const email = payload.email.toLowerCase();
    const name = payload.name || 'Google User';
    const photo = payload.picture || null;

    let user = await User.findOne({ email });
    if (!user) {
      // Create user with secure random password
      const secureRandomPassword = crypto.randomBytes(32).toString('hex') + '!Aa1';
      user = await User.create({
        email,
        name,
        password: secureRandomPassword,
        photo,
        role: 'user'
      });
    } else {
      // Update name or picture if altered
      let changed = false;
      if (name && user.name !== name) {
        user.name = name;
        changed = true;
      }
      if (photo && user.photo !== photo) {
        user.photo = photo;
        changed = true;
      }
      if (changed) {
        await user.save();
      }
    }

    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.json({
      user: {
        email: user.email,
        name: user.name,
        photo: user.photo,
        role: user.role
      },
      token
    });
  } catch (err) {
    console.error('Google token verification failed:', err);
    res.status(401).json({ error: 'Google authentication verification failed.' });
  }
});

// 4. Update Profile Route
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  const { name, photo, password, currentPassword } = req.body;
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User profile not found.' });
    }

    // Role and email fields CANNOT be updated through profile route
    if (name !== undefined) {
      if (!validateName(name)) {
        return res.status(400).json({ error: 'Name must be between 1 and 50 characters.' });
      }
      user.name = name.trim();
    }

    if (photo !== undefined) {
      if (photo !== null && !validatePhoto(photo)) {
        return res.status(400).json({ error: 'Invalid photo format or size (must be a valid image base64 URI or HTTPS URL under 2MB).' });
      }
      user.photo = photo;
    }

    // Password modification flow (requires currentPassword)
    if (password !== undefined && password !== '') {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password is required to change password.' });
      }
      const isMatch = await bcrypt.compare(currentPassword, user.password);
      if (!isMatch) {
        return res.status(400).json({ error: 'Incorrect current password.' });
      }
      if (!validatePassword(password)) {
        return res.status(400).json({ error: 'New password must be 8-64 characters long, containing uppercase, lowercase, numbers, and symbols.' });
      }
      user.password = password;
    }

    await user.save();
    res.json({
      email: user.email,
      name: user.name,
      photo: user.photo,
      role: user.role
    });
  } catch (err) {
    console.error('Profile update database error:', err);
    res.status(500).json({ error: 'Profile save failed.' });
  }
});

// --- PRODUCT CATALOG ROUTES ---

// 1. Fetch catalog
app.get('/api/products', async (req, res) => {
  try {
    const products = await Product.find().sort({ id: -1 });
    res.json(products);
  } catch (err) {
    console.error('Fetch products database error:', err);
    res.status(500).json({ error: 'Fetch products failed.' });
  }
});

// 2. Add product (Admin only)
app.post('/api/products', authenticateToken, requireAdmin, async (req, res) => {
  const { name, category, price, image, inStock, description } = req.body;
  
  if (typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 100) {
    return res.status(400).json({ error: 'Product name must be between 1 and 100 characters.' });
  }
  const ALLOWED_CATEGORIES = ['Produce', 'Dairy', 'Bakery', 'Pantry', 'Beverages', 'Snacks'];
  if (!ALLOWED_CATEGORIES.includes(category)) {
    return res.status(400).json({ error: 'Invalid product category.' });
  }
  const parsedPrice = parseFloat(price);
  if (isNaN(parsedPrice) || parsedPrice <= 0) {
    return res.status(400).json({ error: 'Price must be a positive number.' });
  }
  if (typeof image !== 'string' || image.trim().length < 1 || image.trim().length > 500) {
    return res.status(400).json({ error: 'Product image/icon is required.' });
  }
  const parsedStock = parseInt(inStock);
  if (isNaN(parsedStock) || parsedStock < 0 || !Number.isInteger(parsedStock)) {
    return res.status(400).json({ error: 'Stock must be a non-negative integer.' });
  }
  if (typeof description !== 'string' || description.trim().length < 1 || description.trim().length > 1000) {
    return res.status(400).json({ error: 'Description must be between 1 and 1000 characters.' });
  }

  try {
    const newProduct = await Product.create({
      id: Date.now(),
      name: name.trim(),
      category,
      price: parsedPrice,
      image: image.trim(),
      inStock: parsedStock,
      description: description.trim(),
      reviews: []
    });
    res.json(newProduct);
  } catch (err) {
    console.error('Add product database error:', err);
    res.status(500).json({ error: 'Add product failed.' });
  }
});

// 3. Update product (Admin only)
app.put('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
  const idNum = parseInt(req.params.id);
  if (isNaN(idNum)) {
    return res.status(400).json({ error: 'Invalid product ID.' });
  }
  
  const { name, category, price, image, inStock, description } = req.body;
  const updateFields = {};
  
  if (name !== undefined) {
    if (typeof name !== 'string' || name.trim().length < 1 || name.trim().length > 100) {
      return res.status(400).json({ error: 'Product name must be between 1 and 100 characters.' });
    }
    updateFields.name = name.trim();
  }
  if (category !== undefined) {
    const ALLOWED_CATEGORIES = ['Produce', 'Dairy', 'Bakery', 'Pantry', 'Beverages', 'Snacks'];
    if (!ALLOWED_CATEGORIES.includes(category)) {
      return res.status(400).json({ error: 'Invalid product category.' });
    }
    updateFields.category = category;
  }
  if (price !== undefined) {
    const parsedPrice = parseFloat(price);
    if (isNaN(parsedPrice) || parsedPrice <= 0) {
      return res.status(400).json({ error: 'Price must be a positive number.' });
    }
    updateFields.price = parsedPrice;
  }
  if (image !== undefined) {
    if (typeof image !== 'string' || image.trim().length < 1 || image.trim().length > 500) {
      return res.status(400).json({ error: 'Product image/icon is required.' });
    }
    updateFields.image = image.trim();
  }
  if (inStock !== undefined) {
    const parsedStock = parseInt(inStock);
    if (isNaN(parsedStock) || parsedStock < 0 || !Number.isInteger(parsedStock)) {
      return res.status(400).json({ error: 'Stock must be a non-negative integer.' });
    }
    updateFields.inStock = parsedStock;
  }
  if (description !== undefined) {
    if (typeof description !== 'string' || description.trim().length < 1 || description.trim().length > 1000) {
      return res.status(400).json({ error: 'Description must be between 1 and 1000 characters.' });
    }
    updateFields.description = description.trim();
  }

  try {
    const updated = await Product.findOneAndUpdate(
      { id: idNum },
      { $set: updateFields },
      { new: true }
    );
    if (!updated) {
      return res.status(404).json({ error: 'Product not found.' });
    }
    res.json(updated);
  } catch (err) {
    console.error('Update product database error:', err);
    res.status(500).json({ error: 'Update product failed.' });
  }
});

// 4. Delete product (Admin only)
app.delete('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
  const idNum = parseInt(req.params.id);
  if (isNaN(idNum)) {
    return res.status(400).json({ error: 'Invalid product ID.' });
  }
  try {
    const deleted = await Product.findOneAndDelete({ id: idNum });
    if (!deleted) {
      return res.status(404).json({ error: 'Product not found.' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Delete product database error:', err);
    res.status(500).json({ error: 'Delete product failed.' });
  }
});

// 5. Post review (Authenticated users only)
app.post('/api/products/:id/reviews', authenticateToken, reviewLimiter, async (req, res) => {
  const idNum = parseInt(req.params.id);
  if (isNaN(idNum)) {
    return res.status(400).json({ error: 'Invalid product ID.' });
  }
  
  const { rating, comment } = req.body;
  const parsedRating = parseInt(rating);
  if (isNaN(parsedRating) || parsedRating < 1 || parsedRating > 5 || !Number.isInteger(parsedRating)) {
    return res.status(400).json({ error: 'Rating must be an integer between 1 and 5.' });
  }
  if (typeof comment !== 'string' || comment.trim().length < 1 || comment.trim().length > 500) {
    return res.status(400).json({ error: 'Comment must be between 1 and 500 characters.' });
  }

  try {
    const product = await Product.findOne({ id: idNum });
    if (!product) {
      return res.status(404).json({ error: 'Product not found.' });
    }
    
    const newReview = {
      id: Date.now(),
      author: req.user.name, // Secure reviewer identity from backend session
      rating: parsedRating,
      comment: comment.trim(),
      date: new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    };

    product.reviews.push(newReview);
    product.markModified('reviews');
    await product.save();
    res.json(product);
  } catch (err) {
    console.error('Publish review database error:', err);
    res.status(500).json({ error: 'Review publish failed.' });
  }
});

// --- ORDER ROUTES ---

// 1. Fetch all orders (Admin only)
app.get('/api/orders', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find().sort({ id: -1 });
    res.json(orders);
  } catch (err) {
    console.error('Fetch orders database error:', err);
    res.status(500).json({ error: 'Fetch orders failed.' });
  }
});

// 2. Fetch specific user orders
app.get('/api/orders/user/:email', authenticateToken, async (req, res) => {
  try {
    const requestedEmail = req.params.email.toLowerCase();
    const currentUserEmail = req.user.email.toLowerCase();
    
    if (req.user.role !== 'admin' && currentUserEmail !== requestedEmail) {
      return res.status(403).json({ error: 'Access denied. You can only view your own orders.' });
    }

    const orders = await Order.find({ 'shippingDetails.customerEmail': requestedEmail }).sort({ id: -1 });
    res.json(orders);
  } catch (err) {
    console.error('Fetch user orders database error:', err);
    res.status(500).json({ error: 'Fetch user orders failed.' });
  }
});

// 3. Create order (Secure verification, calculations, and atomic stock check)
app.post('/api/orders', optionalAuthenticateToken, orderLimiter, async (req, res) => {
  const { items, shippingDetails } = req.body;
  
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Order must contain at least one item.' });
  }
  if (!shippingDetails || typeof shippingDetails !== 'object') {
    return res.status(400).json({ error: 'Shipping details are required.' });
  }

  const { customerName, customerPhone, customerAddress, customerEmail, paymentMethod, deliveryType } = shippingDetails;

  if (!validateName(customerName)) {
    return res.status(400).json({ error: 'Customer name is invalid or too long.' });
  }
  if (!validatePhone(customerPhone)) {
    return res.status(400).json({ error: 'Customer phone is invalid (must be 10-15 digits).' });
  }
  if (typeof customerAddress !== 'string' || customerAddress.trim().length < 5 || customerAddress.trim().length > 200) {
    return res.status(400).json({ error: 'Customer address is invalid (5-200 characters).' });
  }
  
  let finalCustomerEmail;
  if (req.user) {
    finalCustomerEmail = req.user.email.toLowerCase();
  } else {
    if (!validateEmail(customerEmail)) {
      return res.status(400).json({ error: 'Customer email is invalid.' });
    }
    finalCustomerEmail = customerEmail.toLowerCase();
  }

  const ALLOWED_PAYMENT_METHODS = ['Cash on Delivery', 'Credit/Debit Card', 'UPI / NetBanking'];
  if (!ALLOWED_PAYMENT_METHODS.includes(paymentMethod)) {
    return res.status(400).json({ error: 'Invalid payment method.' });
  }
  const ALLOWED_DELIVERY_TYPES = ['delivery', 'pickup'];
  const finalDeliveryType = ALLOWED_DELIVERY_TYPES.includes(deliveryType) ? deliveryType : 'delivery';

  try {
    let calculatedSubtotal = 0;
    const validatedItems = [];

    // Fetch and validate quantities & prices from database, calculation done on server
    for (const item of items) {
      if (!item.id || typeof item.quantity !== 'number' || item.quantity <= 0 || !Number.isInteger(item.quantity)) {
        return res.status(400).json({ error: 'Invalid product quantity. Positive integers only.' });
      }
      
      const dbProduct = await Product.findOne({ id: item.id });
      if (!dbProduct) {
        return res.status(404).json({ error: `Product with ID ${item.id} not found.` });
      }
      
      calculatedSubtotal += dbProduct.price * item.quantity;
      validatedItems.push({
        id: dbProduct.id,
        name: dbProduct.name,
        price: dbProduct.price,
        quantity: item.quantity
      });
    }

    // Atomic stock reduction with rollback on failure
    const updatedItems = [];
    try {
      for (const item of validatedItems) {
        const product = await Product.findOneAndUpdate(
          { id: item.id, inStock: { $gte: item.quantity } },
          { $inc: { inStock: -item.quantity } },
          { new: true }
        );
        if (!product) {
          throw new Error(`Insufficient stock for item: ${item.name}`);
        }
        updatedItems.push({ id: item.id, quantity: item.quantity });
      }
    } catch (stockErr) {
      // Rollback stock for successfully updated items
      for (const rolledBack of updatedItems) {
        await Product.findOneAndUpdate(
          { id: rolledBack.id },
          { $inc: { inStock: rolledBack.quantity } }
        );
      }
      return res.status(400).json({ error: stockErr.message });
    }

    const shippingCost = finalDeliveryType === 'delivery' ? (calculatedSubtotal > 500 ? 0 : 50) : 0;
    const total = calculatedSubtotal + shippingCost;

    // Secure generation of Order ID & Date on server
    const generatedOrderId = `#ORD-${Math.floor(100000 + Math.random() * 900000)}`;
    const newOrder = await Order.create({
      id: Date.now(),
      orderId: generatedOrderId,
      date: new Date().toLocaleDateString(undefined, { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric', 
        hour: '2-digit', 
        minute: '2-digit' 
      }),
      items: validatedItems,
      shippingDetails: {
        customerName: customerName.trim(),
        customerPhone: customerPhone.trim(),
        customerAddress: customerAddress.trim(),
        customerEmail: finalCustomerEmail,
        paymentMethod,
        deliveryType: finalDeliveryType,
        shippingCost,
        subtotal: calculatedSubtotal,
        total
      },
      status: 'Processing'
    });

    res.json(newOrder);
  } catch (err) {
    console.error('Order creation error:', err);
    res.status(500).json({ error: 'Server order creation failed.' });
  }
});

// 4. Update order status (Admin only)
app.put('/api/orders/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  const idNum = parseInt(req.params.id);
  if (isNaN(idNum)) {
    return res.status(400).json({ error: 'Invalid order ID.' });
  }
  const { status } = req.body;
  const ALLOWED_STATUSES = ['Processing', 'Shipped', 'Delivered', 'Cancelled'];
  if (!ALLOWED_STATUSES.includes(status)) {
    return res.status(400).json({ error: 'Invalid order status value.' });
  }

  try {
    const updated = await Order.findOneAndUpdate(
      { id: idNum },
      { $set: { status } },
      { new: true }
    );
    if (!updated) {
      return res.status(404).json({ error: 'Order not found.' });
    }
    res.json(updated);
  } catch (err) {
    console.error('Update order status database error:', err);
    res.status(500).json({ error: 'Order status update failed.' });
  }
});

// ==========================================================================
// 9. CENTRALIZED ERROR HANDLING MIDDLEWARE
// ==========================================================================
if (NODE_ENV === 'production') {
  const distPath = path.join(__dirname, '..', 'dist');

  app.use(express.static(distPath));

  app.use('/api', (req, res) => {
    res.status(404).json({ error: 'API route not found.' });
  });

  app.get(/.*/, (req, res) => {
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

app.use((err, req, res, next) => {
  void next;
  console.error('SERVER ERROR:', err.message || err);
  res.status(500).json({ error: 'An internal server error occurred.' });
});

// Start express server
app.listen(PORT, () => {
  console.log(`FreshKart full-stack server running on http://localhost:${PORT}`);
});

export default app;
