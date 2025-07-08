const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Serve uploaded images
app.use('/uploads', express.static('uploads'));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  profilePic: String,
  balance: { type: Number, default: 0 },
  isAdmin: { type: Boolean, default: false }, // ✅
});

const User = mongoose.model('User', userSchema);

// JWT Auth Middleware
const auth = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Invalid token' });
    req.userId = decoded.id;
    next();
  });
};

// Multer Config
const storage = multer.diskStorage({
  destination: 'uploads/',
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  },
});
const upload = multer({ storage });

// ✅ Signup
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = new User({ email, password: hashed });
    await user.save();
    res.json({ message: '✅ User created!' });
  } catch (err) {
    res.status(400).json({ error: 'Email already exists!' });
  }
});

// ✅ Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: 'Wrong password' });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

// ✅ Dashboard — returns ID + isAdmin
app.get('/api/dashboard', auth, async (req, res) => {
  const user = await User.findById(req.userId);
  res.json({
    id: user._id,
    email: user.email,
    profilePic: user.profilePic,
    balance: user.balance,
    isAdmin: user.isAdmin, // ✅
  });
});

// ✅ Profile Picture Upload
app.post('/api/upload', auth, upload.single('profilePic'), async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    user.profilePic = req.file.path;
    await user.save();
    res.json({ profilePic: user.profilePic });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// ✅ Admin-only Balance Update — update ANY user by email
app.post('/api/balance', auth, async (req, res) => {
  const { email, balance } = req.body;

  const currentUser = await User.findById(req.userId);
  if (!currentUser.isAdmin) {
    return res.status(403).json({ error: 'Forbidden: Only admin can update balances' });
  }

  const user = await User.findOneAndUpdate(
    { email },
    { balance },
    { new: true }
  );

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ message: `Balance for ${user.email} updated to $${user.balance}` });
});

// ✅ Root Route
app.get('/', (req, res) => {
  res.send('Your backend is running with MongoDB!');
});

// ✅ Start Server
app.listen(3000, () => {
  console.log('🚀 Server running at http://localhost:3000');
});
