// ============================================================
// ChatLens SaaS — Complete Node.js + Express Backend
// File: server.js
// ============================================================

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const multer = require('multer');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(cors({ origin: process.env.CLIENT_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// File upload config
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.txt', '.zip'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error('Only .txt and .zip files are allowed'));
  }
});

// ─── DATABASE SCHEMAS ─────────────────────────────────────────

// User Schema
const userSchema = new mongoose.Schema({
  name:          { type: String, required: true, trim: true },
  email:         { type: String, required: true, unique: true, lowercase: true },
  password:      { type: String, required: true, minlength: 6 },
  plan:          { type: String, enum: ['standard', 'plus', 'refundable', null], default: null },
  planActivatedAt: { type: Date, default: null },
  planExpiresAt: { type: Date, default: null },
  razorpayCustomerId: { type: String, default: null },
  uploads:       [{ name: String, date: Date, messages: Number, fileId: String }],
  refundRequested: { type: Boolean, default: false },
  isActive:      { type: Boolean, default: true },
  createdAt:     { type: Date, default: Date.now },
  lastLogin:     { type: Date, default: null },
  passwordResetToken: { type: String, default: null },
  passwordResetExpires: { type: Date, default: null },
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Payment Schema
const paymentSchema = new mongoose.Schema({
  userId:          { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  razorpayOrderId: { type: String, required: true, unique: true },
  razorpayPaymentId: { type: String, default: null },
  razorpaySignature: { type: String, default: null },
  plan:            { type: String, required: true },
  amount:          { type: Number, required: true },  // in paise
  currency:        { type: String, default: 'INR' },
  status:          { type: String, enum: ['created', 'paid', 'failed', 'refunded'], default: 'created' },
  createdAt:       { type: Date, default: Date.now },
  verifiedAt:      { type: Date, default: null },
  refundedAt:      { type: Date, default: null },
  refundId:        { type: String, default: null },
});

const Payment = mongoose.model('Payment', paymentSchema);

// ─── RAZORPAY INIT ───────────────────────────────────────────
const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ─── PLAN CONFIG ─────────────────────────────────────────────
const PLANS = {
  standard:   { price: 9900,  name: 'Standard Plan',   durationDays: 30 },
  plus:       { price: 24900, name: 'Plus Plan',        durationDays: 30 },
  refundable: { price: 49900, name: 'Refundable Plan',  durationDays: 30, refundDays: 7 },
};

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    if (!user || !user.isActive) return res.status(401).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token verification failed' });
  }
};

const requirePlan = (allowedPlans = null) => async (req, res, next) => {
  const user = req.user;
  if (!user.plan) return res.status(403).json({ error: 'Active subscription required', code: 'NO_PLAN' });
  if (user.planExpiresAt && new Date() > user.planExpiresAt) {
    await User.findByIdAndUpdate(user._id, { plan: null, planExpiresAt: null });
    return res.status(403).json({ error: 'Subscription expired', code: 'PLAN_EXPIRED' });
  }
  if (allowedPlans && !allowedPlans.includes(user.plan)) {
    return res.status(403).json({ error: `This feature requires: ${allowedPlans.join(' or ')} plan`, code: 'UPGRADE_REQUIRED' });
  }
  next();
};

// ─── AUTH ROUTES ─────────────────────────────────────────────

// POST /api/auth/signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const user = await User.create({ name, email, password });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email, plan: user.plan }
    });
  } catch (err) {
    res.status(500).json({ error: 'Signup failed', details: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await user.comparePassword(password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user._id, name: user.name, email: user.email,
        plan: user.plan, planExpiresAt: user.planExpiresAt,
        uploads: user.uploads
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Login failed', details: err.message });
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ message: 'If this email exists, a reset link has been sent.' });

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');

    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 min
    await user.save();

    // TODO: Send email with resetToken using nodemailer/sendgrid
    // The reset link: ${process.env.CLIENT_URL}/reset-password?token=${resetToken}

    res.json({ message: 'Password reset link sent to your email.' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process request' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) return res.status(400).json({ error: 'Invalid or expired reset token' });

    user.password = newPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', authenticate, async (req, res) => {
  const u = req.user;
  res.json({
    id: u._id, name: u.name, email: u.email,
    plan: u.plan, planExpiresAt: u.planExpiresAt,
    uploads: u.uploads, planActivatedAt: u.planActivatedAt
  });
});

// ─── PAYMENT ROUTES ───────────────────────────────────────────

// POST /api/payment/create-order
app.post('/api/payment/create-order', authenticate, async (req, res) => {
  try {
    const { plan } = req.body;
    if (!PLANS[plan]) return res.status(400).json({ error: 'Invalid plan' });

    const planConfig = PLANS[plan];

    const order = await razorpay.orders.create({
      amount:   planConfig.price,
      currency: 'INR',
      receipt:  `receipt_${req.user._id}_${Date.now()}`,
      notes:    { userId: req.user._id.toString(), plan, email: req.user.email }
    });

    // Store pending payment record
    await Payment.create({
      userId:          req.user._id,
      razorpayOrderId: order.id,
      plan,
      amount:          planConfig.price,
      status:          'created'
    });

    res.json({
      orderId:   order.id,
      amount:    planConfig.price,
      currency:  'INR',
      keyId:     process.env.RAZORPAY_KEY_ID,
      planName:  planConfig.name,
      userName:  req.user.name,
      userEmail: req.user.email,
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create order', details: err.message });
  }
});

// POST /api/payment/verify
// CRITICAL: Server-side signature verification — never skip this
app.post('/api/payment/verify', authenticate, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ error: 'Missing payment verification fields' });
    }

    // ✅ HMAC-SHA256 signature verification (CRITICAL SECURITY STEP)
    const generatedSignature = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(`${razorpay_order_id}|${razorpay_payment_id}`)
      .digest('hex');

    if (generatedSignature !== razorpay_signature) {
      await Payment.findOneAndUpdate(
        { razorpayOrderId: razorpay_order_id },
        { status: 'failed' }
      );
      return res.status(400).json({ error: 'Payment signature verification failed', code: 'INVALID_SIGNATURE' });
    }

    // Find and update payment record
    const payment = await Payment.findOne({ razorpayOrderId: razorpay_order_id });
    if (!payment) return res.status(404).json({ error: 'Payment record not found' });
    if (payment.userId.toString() !== req.user._id.toString()) {
      return res.status(403).json({ error: 'Payment does not belong to this user' });
    }

    const planConfig = PLANS[payment.plan];
    const expiresAt = new Date(Date.now() + planConfig.durationDays * 24 * 60 * 60 * 1000);

    // Update payment record
    payment.razorpayPaymentId = razorpay_payment_id;
    payment.razorpaySignature = razorpay_signature;
    payment.status = 'paid';
    payment.verifiedAt = new Date();
    await payment.save();

    // ✅ Activate user plan
    await User.findByIdAndUpdate(req.user._id, {
      plan:             payment.plan,
      planActivatedAt:  new Date(),
      planExpiresAt:    expiresAt,
    });

    res.json({
      success:         true,
      plan:            payment.plan,
      planName:        planConfig.name,
      planExpiresAt:   expiresAt,
      paymentId:       razorpay_payment_id,
      message:         `${planConfig.name} activated successfully!`
    });
  } catch (err) {
    res.status(500).json({ error: 'Payment verification failed', details: err.message });
  }
});

// POST /api/payment/refund
app.post('/api/payment/refund', authenticate, requirePlan(['refundable']), async (req, res) => {
  try {
    const user = req.user;

    // Check refund window (7 days)
    const refundDeadline = new Date(user.planActivatedAt);
    refundDeadline.setDate(refundDeadline.getDate() + 7);

    if (new Date() > refundDeadline) {
      return res.status(400).json({ error: 'Refund window has closed (7 days from purchase)' });
    }

    if (user.refundRequested) {
      return res.status(400).json({ error: 'Refund already requested' });
    }

    // Find payment
    const payment = await Payment.findOne({ userId: user._id, plan: 'refundable', status: 'paid' }).sort({ createdAt: -1 });
    if (!payment) return res.status(404).json({ error: 'No qualifying payment found' });

    // Process Razorpay refund
    const refund = await razorpay.payments.refund(payment.razorpayPaymentId, {
      amount: payment.amount,
      notes: { reason: 'User requested refund within 7-day window', userId: user._id.toString() }
    });

    // Update records
    payment.status = 'refunded';
    payment.refundedAt = new Date();
    payment.refundId = refund.id;
    await payment.save();

    await User.findByIdAndUpdate(user._id, {
      plan:            null,
      planExpiresAt:   null,
      refundRequested: true
    });

    res.json({
      success:  true,
      refundId: refund.id,
      amount:   payment.amount / 100,
      message:  'Refund initiated. Amount will credit in 3-5 business days.'
    });
  } catch (err) {
    res.status(500).json({ error: 'Refund failed', details: err.message });
  }
});

// ─── CHAT ANALYZER ROUTES ─────────────────────────────────────

// POST /api/analyze/upload
app.post('/api/analyze/upload', authenticate, requirePlan(), upload.single('chatFile'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const ext = path.extname(req.file.originalname).toLowerCase();

    // Standard plan: only .txt
    if (req.user.plan === 'standard' && ext !== '.txt') {
      return res.status(403).json({ error: 'Standard plan only supports .txt files. Upgrade to Plus for .zip support.' });
    }

    let chatText = '';
    if (ext === '.txt') {
      chatText = req.file.buffer.toString('utf-8');
    } else if (ext === '.zip') {
      // In production: use 'adm-zip' or 'unzipper' to extract .txt from zip
      const AdmZip = require('adm-zip');
      const zip = new AdmZip(req.file.buffer);
      const entries = zip.getEntries();
      const txtEntry = entries.find(e => e.entryName.endsWith('.txt'));
      if (!txtEntry) return res.status(400).json({ error: 'No .txt file found inside zip' });
      chatText = txtEntry.getData().toString('utf-8');
    }

    // Parse chat
    const parsed = parseWhatsAppChat(chatText);

    // Save upload record
    const uploadRecord = {
      name:     req.file.originalname,
      date:     new Date(),
      messages: parsed.messages.length,
      fileId:   crypto.randomUUID()
    };

    await User.findByIdAndUpdate(req.user._id, { $push: { uploads: uploadRecord } });

    // Standard plan: limit data returned
    let responseData = parsed;
    if (req.user.plan === 'standard') {
      responseData = {
        ...parsed,
        messages:  parsed.messages.slice(0, 100),
        limited:   true,
        limitNote: 'Standard plan shows first 100 messages. Upgrade to Plus for full access.'
      };
    }

    res.json({ success: true, upload: uploadRecord, data: responseData });
  } catch (err) {
    res.status(500).json({ error: 'Analysis failed', details: err.message });
  }
});

// GET /api/analyze/history
app.get('/api/analyze/history', authenticate, requirePlan(), async (req, res) => {
  const user = await User.findById(req.user._id).select('uploads');
  res.json({ uploads: user.uploads.reverse() });
});

// ─── CHAT PARSER ──────────────────────────────────────────────
function parseWhatsAppChat(text) {
  const lines  = text.split('\n');
  const messages = [];
  const regex = /^(\d{1,2}\/\d{1,2}\/\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AP]M)?)\s+-\s+([^:]+):\s+(.+)$/;

  for (const line of lines) {
    const match = line.match(regex);
    if (match) {
      const [, date, time, sender, message] = match;
      messages.push({ date, time, sender: sender.trim(), message: message.trim() });
    }
  }

  const senderCounts = {};
  const emojiCounts  = {};
  const hourlyCounts = Array(24).fill(0);
  const emojiRegex   = /[\u{1F600}-\u{1FAFF}\u{2600}-\u{27BF}]/gu;

  for (const msg of messages) {
    senderCounts[msg.sender] = (senderCounts[msg.sender] || 0) + 1;
    const emojis = msg.message.match(emojiRegex) || [];
    for (const e of emojis) emojiCounts[e] = (emojiCounts[e] || 0) + 1;
    const hour = parseInt(msg.time.split(':')[0]);
    if (!isNaN(hour)) hourlyCounts[hour % 24]++;
  }

  return {
    totalMessages: messages.length,
    senders:       Object.entries(senderCounts).sort((a,b) => b[1]-a[1]),
    topEmojis:     Object.entries(emojiCounts).sort((a,b) => b[1]-a[1]).slice(0, 20),
    hourlyCounts,
    messages,
  };
}

// ─── USER ROUTES ──────────────────────────────────────────────
app.get('/api/user/profile', authenticate, async (req, res) => {
  const u = req.user;
  res.json({
    id: u._id, name: u.name, email: u.email,
    plan: u.plan, planExpiresAt: u.planExpiresAt,
    planActivatedAt: u.planActivatedAt, uploads: u.uploads
  });
});

app.put('/api/user/profile', authenticate, async (req, res) => {
  try {
    const { name } = req.body;
    await User.findByIdAndUpdate(req.user._id, { name });
    res.json({ success: true, message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ error: 'Update failed' });
  }
});

// ─── HEALTH CHECK ─────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ─── SERVE FRONTEND ───────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'frontend/build')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend/build', 'index.html'));
});

// ─── ERROR HANDLER ────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// ─── CONNECT & START ──────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => {
    console.log('✅ MongoDB connected');
    app.listen(PORT, () => console.log(`🚀 ChatLens server running on port ${PORT}`));
  })
  .catch(err => { console.error('❌ MongoDB connection failed:', err.message); process.exit(1); });

module.exports = app;
