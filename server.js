require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const Stripe = require('stripe');
const axios = require('axios');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1); // needed on Render so rate limiting sees real IPs

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://goldoffer.netlify.app';
const PUBLIC_BASE = process.env.PUBLIC_BASE_URL || 'https://goldoffer.onrender.com';

// ---------- Security ----------
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https:'],
      formAction: ["'self'"]
    }
  }
}));
app.use(cors({ origin: [FRONTEND_URL, PUBLIC_BASE, 'http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:3000'] }));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { message: 'Too many attempts. Please try again in 15 minutes.' }
});
const publicLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });

// ---------- Stripe webhook (needs the raw body, so it goes before express.json) ----------
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send('Webhook signature failed');
  }
  try {
    if (event.type === 'checkout.session.completed') {
      const s = event.data.object;
      const userId = s.client_reference_id;
      if (userId) {
        await User.findByIdAndUpdate(userId, { subscriptionStatus: 'active', stripeCustomerId: s.customer });
      }
    } else if (event.type === 'customer.subscription.deleted') {
      await User.findOneAndUpdate({ stripeCustomerId: event.data.object.customer }, { subscriptionStatus: 'canceled' });
    }
  } catch (e) {
    console.error('Webhook handling error', e);
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

// Images are kept in the database (memory storage), so no external service and no disk is needed
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))
});

// ---------- Database ----------
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error', err.message));

// Open /api/health in the browser to see whether the database is connected
app.get('/api/health', (req, res) => {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  res.json({
    server: 'ok',
    database: states[mongoose.connection.readyState] || 'unknown',
    mongodbUriSet: !!process.env.MONGODB_URI,
    jwtSecretSet: !!process.env.JWT_SECRET,
    emailSet: !!((process.env.BREVO_API_KEY || process.env.RESEND_API_KEY) && process.env.MAIL_FROM)
  });
});

const UserSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  subscriptionStatus: { type: String, default: 'trial' }, // trial, active, canceled
  stripeCustomerId: String,
  siteName: String,
  slug: { type: String, unique: true, sparse: true },
  category: String,
  city: String,
  theme: { type: String, default: 'gold' },
  font: { type: String, default: 'sans' },
  published: { type: Boolean, default: false },
  categoryLabel: String,
  phone: String,
  address: String,
  hours: String,
  facebook: String,
  instagram: String,
  logoUrl: String,
  lang: { type: String, default: 'bg' },
  notifyEmail: String,
  notifyOn: { type: Boolean, default: true },
  termsAcceptedAt: Date,
  resetTokenHash: String,
  resetExpires: Date,
  emailVerified: { type: Boolean, default: true }, // old accounts count as verified; new sign-ups are saved with false
  verifyCodeHash: String,
  verifyExpires: Date,
  verifyAttempts: { type: Number, default: 0 },
  verifySentAt: Date,
  createdAt: { type: Date, default: Date.now }
});

const OfferSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  title: String,
  price: Number,
  description: String,
  imageUrl: String,
  order: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  offerTitle: String,
  customerName: String,
  customerContact: String,
  amount: Number,
  status: { type: String, default: 'Pending' }, // Pending, Completed, Cancelled
  createdAt: { type: Date, default: Date.now }
});

const ImageSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  contentType: String,
  data: Buffer,
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Image = mongoose.model('Image', ImageSchema);
const Offer = mongoose.model('Offer', OfferSchema);
const Order = mongoose.model('Order', OrderSchema);

// ---------- Themes and fonts (shared look with the builder) ----------
// a/b = gradient colors, ink = readable accent on white, on = text color on the gradient
const THEMES = {
  gold: { a: '#ffd700', b: '#ff8c00', ink: '#b45309', on: '#1a1a1a' },
  'neon-blue': { a: '#00f2fe', b: '#4facfe', ink: '#0369a1', on: '#06222e' },
  emerald: { a: '#00f5a0', b: '#00d9f5', ink: '#047857', on: '#06281c' },
  ruby: { a: '#ff0844', b: '#ff7a59', ink: '#be123c', on: '#ffffff' },
  'purple-haze': { a: '#b300ff', b: '#7928ca', ink: '#7e22ce', on: '#ffffff' },
  'sunset-orange': { a: '#ff4e00', b: '#ec9f05', ink: '#c2410c', on: '#ffffff' },
  'cyber-pink': { a: '#ff007f', b: '#7928ca', ink: '#be185d', on: '#ffffff' },
  'midnight-silver': { a: '#64748b', b: '#1e293b', ink: '#334155', on: '#ffffff' }
};
const FONTS = {
  sans: { css: "'Inter', sans-serif", gf: 'Inter:wght@400;600;700;800' },
  serif: { css: "'Playfair Display', serif", gf: 'Playfair+Display:wght@600;800' },
  mono: { css: "'JetBrains Mono', monospace", gf: 'JetBrains+Mono:wght@400;600' },
  display: { css: "'Oswald', sans-serif", gf: 'Oswald:wght@500;700' },
  script: { css: "'Caveat', cursive", gf: 'Caveat:wght@600' },
  rounded: { css: "'Comfortaa', cursive", gf: 'Comfortaa:wght@600;700' },
  geo: { css: "'Montserrat', sans-serif", gf: 'Montserrat:wght@400;600;800' }
};

// ---------- Helpers ----------
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));

const CYR = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'ts', ч: 'ch', ш: 'sh', щ: 'sht', ъ: 'a', ь: 'y', ю: 'yu', я: 'ya' };
function slugify(text) {
  const s = String(text || '').toLowerCase().split('').map(c => CYR[c] !== undefined ? CYR[c] : c).join('')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40);
  return s || 'site';
}
async function uniqueSlug(base, userId) {
  let candidate = slugify(base);
  for (let i = 0; i < 50; i++) {
    const taken = await User.findOne({ slug: candidate, _id: { $ne: userId } });
    if (!taken) return candidate;
    candidate = `${slugify(base)}-${i + 2}`;
  }
  return `${slugify(base)}-${Date.now().toString(36)}`;
}
// Accepts a full link or just a handle (e.g. "mybusiness") and returns a safe https link or ''
function cleanSocial(value, host) {
  let v = String(value || '').trim().slice(0, 200);
  if (!v) return '';
  if (!/^https?:\/\//i.test(v)) v = /^[A-Za-z0-9._-]+$/.test(v) ? `https://www.${host}/${v}` : `https://${v}`;
  try { const u = new URL(v); return /^https?:$/.test(u.protocol) ? u.toString() : ''; } catch (e) { return ''; }
}
const isEmail = (v) => /^\S+@\S+\.\S+$/.test(String(v || ''));

// ---------- Email confirmation code (6 digits, valid 15 minutes, max 5 wrong tries) ----------
const VERIFY_MINUTES = 15;
const VERIFY_MAX_TRIES = 5;
const VERIFY_COOLDOWN_MS = 60 * 1000;
const hashCode = (email, code) => crypto.createHash('sha256').update(`${String(email).toLowerCase()}:${code}:${process.env.JWT_SECRET}`).digest('hex');
async function issueVerifyCode(user) {
  const code = String(crypto.randomInt(100000, 1000000));
  user.verifyCodeHash = hashCode(user.email, code);
  user.verifyExpires = new Date(Date.now() + VERIFY_MINUTES * 60 * 1000);
  user.verifyAttempts = 0;
  user.verifySentAt = new Date();
  await user.save();
  return sendMail({
    to: user.email,
    subject: `${code} е вашият код за GoldOffer / ${code} is your GoldOffer code`,
    text: `Здравейте,\nВашият код за потвърждение е: ${code}\nВалиден е ${VERIFY_MINUTES} минути.\n\nHello,\nYour confirmation code is: ${code}\nIt is valid for ${VERIFY_MINUTES} minutes.\n\nАко не сте се регистрирали, игнорирайте писмото. / If you did not sign up, ignore this email.`,
    html: `<p>Здравейте,</p><p>Вашият код за потвърждение:</p><p style="font-size:34px;font-weight:700;letter-spacing:10px;margin:8px 0">${code}</p><p>Валиден е ${VERIFY_MINUTES} минути.</p><hr><p>Hello,</p><p>Your confirmation code:</p><p style="font-size:34px;font-weight:700;letter-spacing:10px;margin:8px 0">${code}</p><p>It is valid for ${VERIFY_MINUTES} minutes.</p><p style="color:#777">Ако не сте се регистрирали, игнорирайте писмото. / If you did not sign up, ignore this email.</p>`
  });
}
const canResend = (user) => !user.verifySentAt || Date.now() - new Date(user.verifySentAt).getTime() >= VERIFY_COOLDOWN_MS;
const nowSofia = () => new Date().toLocaleString('bg-BG', { timeZone: 'Europe/Sofia', dateStyle: 'medium', timeStyle: 'short' });

// Sends an email through Brevo or Resend (plain HTTPS, because free Render blocks SMTP ports)
async function sendMail({ to, subject, html, text }) {
  const from = process.env.MAIL_FROM || '';
  const m = from.match(/^\s*(.*?)\s*<([^>]+)>\s*$/);
  const sender = m ? { name: m[1].replace(/^"|"$/g, '') || 'GoldOffer Studio', email: m[2] } : { name: 'GoldOffer Studio', email: from.trim() };
  try {
    if (process.env.BREVO_API_KEY && sender.email) {
      await axios.post('https://api.brevo.com/v3/smtp/email',
        { sender, to: [{ email: to }], subject, htmlContent: html, textContent: text },
        { headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' } });
      return true;
    }
    if (process.env.RESEND_API_KEY && sender.email) {
      await axios.post('https://api.resend.com/emails',
        { from: `${sender.name} <${sender.email}>`, to: [to], subject, html, text },
        { headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY } });
      return true;
    }
    console.warn('Email is not set up: BREVO_API_KEY (or RESEND_API_KEY) and MAIL_FROM are missing.');
  } catch (e) {
    console.error('Email error:', e.response ? JSON.stringify(e.response.data) : e.message);
  }
  return false;
}

// Free plan: up to 10 offers. Paid (active subscription): effectively unlimited.
const FREE_OFFER_LIMIT = 10;
const PAID_OFFER_LIMIT = 500; // safety cap against abuse
const offerLimitFor = (u) => (u.subscriptionStatus === 'active' ? PAID_OFFER_LIMIT : FREE_OFFER_LIMIT);
const publicUser = (u) => ({
  id: u._id, firstName: u.firstName, lastName: u.lastName, email: u.email,
  subscriptionStatus: u.subscriptionStatus, siteName: u.siteName, slug: u.slug,
  category: u.category, city: u.city, theme: u.theme, font: u.font, published: u.published,
  siteUrl: u.slug && u.published ? `${PUBLIC_BASE}/site/${u.slug}` : null,
  offerLimit: offerLimitFor(u),
  categoryLabel: u.categoryLabel, phone: u.phone, address: u.address, hours: u.hours,
  facebook: u.facebook, instagram: u.instagram, logoUrl: u.logoUrl,
  lang: u.lang || 'bg', notifyEmail: u.notifyEmail, notifyOn: u.notifyOn !== false
});
if (!process.env.JWT_SECRET) console.error('WARNING: JWT_SECRET is not set. Login and registration will fail.');
const signToken = (u) => jwt.sign({ id: u._id, email: u.email }, process.env.JWT_SECRET, { expiresIn: '7d' });

const authenticateToken = (req, res, next) => {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Not authorized' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired session' });
    req.user = user;
    next();
  });
};

// ---------- Auth ----------
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { firstName, lastName, email, password, acceptTerms } = req.body || {};
    if (!firstName || !email || !password) return res.status(400).json({ message: 'Please fill in all fields.' });
    if (acceptTerms !== true) return res.status(400).json({ message: 'Please accept the Terms and the Privacy Policy.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ message: 'Invalid email address.' });
    if (String(password).length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters.' });

    const cleanEmail = String(email).toLowerCase().trim();
    let user = await User.findOne({ email: cleanEmail });
    if (user && user.emailVerified !== false) return res.status(400).json({ message: 'This email is already registered.' });
    if (user && !canResend(user)) {
      return res.status(429).json({ message: 'A code was just sent. Please wait a minute before trying again.', needsVerification: true, email: user.email });
    }

    const hashed = await bcrypt.hash(password, 10);
    if (user) {
      // The email signed up before but never confirmed it: refresh the details and send a new code
      user.firstName = String(firstName).trim();
      user.lastName = String(lastName || '').trim();
      user.password = hashed;
      user.termsAcceptedAt = new Date();
    } else {
      user = new User({
        firstName: String(firstName).trim(),
        lastName: String(lastName || '').trim(),
        email: cleanEmail,
        password: hashed,
        termsAcceptedAt: new Date(),
        emailVerified: false
      });
    }
    const sent = await issueVerifyCode(user);
    if (!sent) {
      await User.deleteOne({ _id: user._id });
      return res.status(503).json({ message: 'We could not send the confirmation email. Please check the address and try again later.' });
    }
    res.json({ needsVerification: true, email: user.email });
  } catch (err) {
    console.error('Register error', err.message);
    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ message: 'Server setting JWT_SECRET is missing. Add it in Render, Environment.' });
    }
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ message: 'The database is not connected. Check MONGODB_URI on the server.' });
    }
    res.status(500).json({ message: 'Registration failed. Please try again.' });
  }
});

// Confirm the email with the 6-digit code, then sign the user in
app.post('/api/auth/verify', authLimiter, async (req, res) => {
  try {
    const email = String((req.body || {}).email || '').toLowerCase().trim();
    const code = String((req.body || {}).code || '').replace(/\D/g, '');
    const user = await User.findOne({ email });
    if (!user || user.emailVerified !== false || !user.verifyCodeHash) {
      return res.status(400).json({ message: 'This code is not valid. Please request a new one.' });
    }
    if (!user.verifyExpires || user.verifyExpires < new Date()) {
      return res.status(400).json({ message: 'This code has expired. Please request a new one.' });
    }
    if ((user.verifyAttempts || 0) >= VERIFY_MAX_TRIES) {
      return res.status(429).json({ message: 'Too many wrong attempts. Please request a new code.' });
    }
    const a = Buffer.from(hashCode(email, code), 'hex');
    const b = Buffer.from(user.verifyCodeHash, 'hex');
    if (code.length !== 6 || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      user.verifyAttempts = (user.verifyAttempts || 0) + 1;
      await user.save();
      return res.status(400).json({ message: 'Wrong code. Please check it and try again.' });
    }
    user.emailVerified = true;
    user.verifyCodeHash = undefined;
    user.verifyExpires = undefined;
    user.verifyAttempts = 0;
    await user.save();
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    console.error('Verify error', err.message);
    res.status(500).json({ message: 'Could not confirm the email. Please try again.' });
  }
});

// Send a new code (same answer whether or not the account exists, so emails cannot be probed)
app.post('/api/auth/resend', authLimiter, async (req, res) => {
  const email = String((req.body || {}).email || '').toLowerCase().trim();
  try {
    const user = await User.findOne({ email });
    if (user && user.emailVerified === false && canResend(user)) await issueVerifyCode(user);
  } catch (err) {
    console.error('Resend error', err.message);
  }
  res.json({ message: 'If this account is waiting for confirmation, we sent a new code.' });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email: String(email || '').toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(String(password || ''), user.password))) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }
    if (user.emailVerified === false) {
      if (canResend(user)) await issueVerifyCode(user);
      return res.status(403).json({ message: 'Please confirm your email first. Enter the code we sent you.', needsVerification: true, email: user.email });
    }
    // Security notice (not awaited, so login never waits for email)
    sendMail({
      to: user.email,
      subject: 'Вход в профила ви / New login to your GoldOffer account',
      text: `Здравейте,\nВлязохте в профила си в GoldOffer Studio на ${nowSofia()}.\nАко не сте вие, сменете паролата си веднага от "Forgot your password?" и ни пишете на rayankatsarov2013@gmail.com.\n\nHello,\nYou signed in to your GoldOffer Studio account on ${nowSofia()}.\nIf this was not you, reset your password right away with "Forgot your password?" and write to rayankatsarov2013@gmail.com.`,
      html: `<p>Здравейте,</p><p>Влязохте в профила си в GoldOffer Studio на <b>${esc(nowSofia())}</b>.</p><p>Ако не сте вие, сменете паролата си веднага от „Forgot your password?“ и ни пишете на rayankatsarov2013@gmail.com.</p><hr><p>Hello,</p><p>You signed in to your GoldOffer Studio account on <b>${esc(nowSofia())}</b>.</p><p>If this was not you, reset your password right away with “Forgot your password?” and write to rayankatsarov2013@gmail.com.</p>`
    });
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    console.error('Login error', err.message);
    if (!process.env.JWT_SECRET) {
      return res.status(500).json({ message: 'Server setting JWT_SECRET is missing. Add it in Render, Environment.' });
    }
    res.status(500).json({ message: 'Login failed. Please try again.' });
  }
});

// ---------- Forgot / reset password ----------
app.post('/api/auth/forgot', authLimiter, async (req, res) => {
  const email = String((req.body || {}).email || '').toLowerCase().trim();
  const answer = { message: 'If this email is registered, we sent a link to reset the password.' };
  try {
    const user = await User.findOne({ email });
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      user.resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
      user.resetExpires = new Date(Date.now() + 60 * 60 * 1000);
      await user.save();
      const link = `${PUBLIC_BASE}/reset?token=${token}`;
      sendMail({
        to: user.email,
        subject: 'Нова парола за GoldOffer / Reset your GoldOffer password',
        text: `Здравейте,\nНатиснете връзката, за да зададете нова парола (валидна 1 час):\n${link}\n\nHello,\nOpen this link to set a new password (valid for 1 hour):\n${link}\n\nАко не сте поискали това, игнорирайте писмото. / If you did not ask for this, ignore this email.`,
        html: `<p>Здравейте,</p><p><a href="${link}">Задайте нова парола</a> (валидна 1 час).</p><hr><p>Hello,</p><p><a href="${link}">Set a new password</a> (valid for 1 hour).</p><p style="color:#777">Ако не сте поискали това, игнорирайте писмото. / If you did not ask for this, ignore this email.</p>`
      });
    }
  } catch (err) {
    console.error('Forgot error', err.message);
  }
  res.json(answer);
});

app.post('/api/auth/reset', authLimiter, async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (String(password || '').length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters.' });
    const hash = crypto.createHash('sha256').update(String(token || '')).digest('hex');
    const user = await User.findOne({ resetTokenHash: hash, resetExpires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ message: 'This reset link is invalid or has expired.' });
    user.password = await bcrypt.hash(password, 10);
    user.resetTokenHash = undefined;
    user.resetExpires = undefined;
    user.emailVerified = true; // the reset link arrived in their inbox, so the email is proven
    user.verifyCodeHash = undefined;
    await user.save();
    sendMail({
      to: user.email,
      subject: 'Паролата ви е сменена / Your GoldOffer password was changed',
      text: `Здравейте,\nПаролата на профила ви в GoldOffer Studio беше сменена на ${nowSofia()}.\nАко не сте вие, поискайте нова парола веднага и ни пишете на rayankatsarov2013@gmail.com.\n\nHello,\nThe password of your GoldOffer Studio account was changed on ${nowSofia()}.\nIf this was not you, request a new password right away and write to rayankatsarov2013@gmail.com.`,
      html: `<p>Здравейте,</p><p>Паролата на профила ви в GoldOffer Studio беше сменена на <b>${esc(nowSofia())}</b>.</p><p>Ако не сте вие, поискайте нова парола веднага и ни пишете на rayankatsarov2013@gmail.com.</p><hr><p>Hello,</p><p>The password of your GoldOffer Studio account was changed on <b>${esc(nowSofia())}</b>.</p><p>If this was not you, request a new password right away and write to rayankatsarov2013@gmail.com.</p>`
    });
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ message: 'Could not reset the password.' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: 'User not found' });
  res.json({ user: publicUser(user) });
});

// ---------- Site settings / publishing ----------
app.put('/api/site', authenticateToken, async (req, res) => {
  try {
    const b = req.body || {};
    const { siteName, category, city, theme, font, publish } = b;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (siteName !== undefined) user.siteName = String(siteName).trim().slice(0, 80);
    if (category !== undefined) user.category = String(category).slice(0, 80);
    if (b.categoryLabel !== undefined) user.categoryLabel = String(b.categoryLabel).slice(0, 80);
    if (city !== undefined) user.city = String(city).slice(0, 80);
    if (b.phone !== undefined) user.phone = String(b.phone).trim().slice(0, 40);
    if (b.address !== undefined) user.address = String(b.address).trim().slice(0, 160);
    if (b.hours !== undefined) user.hours = String(b.hours).trim().slice(0, 400);
    if (b.facebook !== undefined) user.facebook = cleanSocial(b.facebook, 'facebook.com');
    if (b.instagram !== undefined) user.instagram = cleanSocial(b.instagram, 'instagram.com');
    if (b.logoUrl !== undefined) user.logoUrl = /^https:\/\//.test(b.logoUrl || '') ? b.logoUrl : '';
    if (b.lang === 'bg' || b.lang === 'en') user.lang = b.lang;
    if (b.notifyEmail !== undefined) user.notifyEmail = isEmail(b.notifyEmail) ? String(b.notifyEmail).trim() : '';
    if (typeof b.notifyOn === 'boolean') user.notifyOn = b.notifyOn;
    if (Object.keys(THEMES).includes(theme)) user.theme = theme;
    if (Object.keys(FONTS).includes(font)) user.font = font;
    if (!user.slug && user.siteName) user.slug = await uniqueSlug(user.siteName, user._id);
    if (publish === true) {
      if (!user.siteName) return res.status(400).json({ message: 'Please set a site name first.' });
      user.published = true;
    }
    await user.save();
    res.json({ user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ message: 'Could not save site settings.' });
  }
});

app.put('/api/site/slug', authenticateToken, async (req, res) => {
  try {
    const slug = slugify(req.body && req.body.slug);
    const taken = await User.findOne({ slug, _id: { $ne: req.user.id } });
    if (taken) return res.status(400).json({ message: 'That address is already taken.' });
    const user = await User.findByIdAndUpdate(req.user.id, { slug }, { new: true });
    res.json({ user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ message: 'Could not change the address.' });
  }
});

// ---------- Offers ----------
app.get('/api/offers', authenticateToken, async (req, res) => {
  const offers = await Offer.find({ userId: req.user.id }).sort({ order: 1, createdAt: 1 });
  res.json({ offers });
});

app.post('/api/offers', authenticateToken, async (req, res) => {
  try {
    const owner = await User.findById(req.user.id);
    if (!owner) return res.status(404).json({ message: 'User not found' });
    const limit = offerLimitFor(owner);
    const existing = await Offer.countDocuments({ userId: req.user.id });
    if (existing >= limit) {
      return res.status(402).json({
        message: owner.subscriptionStatus === 'active'
          ? `You reached the maximum of ${limit} offers.`
          : `The free plan allows up to ${FREE_OFFER_LIMIT} offers. Upgrade to add more.`,
        limitReached: true
      });
    }
    const { title, price, description, imageUrl } = req.body || {};
    if (!title || !String(title).trim()) return res.status(400).json({ message: 'Title is required.' });
    const p = Number(price);
    if (!isFinite(p) || p < 0) return res.status(400).json({ message: 'Invalid price.' });
    const offer = await Offer.create({
      userId: req.user.id,
      title: String(title).trim().slice(0, 120),
      price: p,
      description: String(description || '').slice(0, 500),
      imageUrl: /^https:\/\//.test(imageUrl || '') ? imageUrl : null,
      order: existing
    });
    res.json({ offer });
  } catch (err) {
    res.status(500).json({ message: 'Could not save the offer.' });
  }
});

app.delete('/api/offers/:id', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  await Offer.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

// New order of the offers: body { ids: [...] } in the wanted order (declared before "/:id")
app.put('/api/offers/reorder', authenticateToken, async (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids.filter(id => mongoose.isValidObjectId(id)) : [];
  if (!ids.length) return res.status(400).json({ message: 'Nothing to reorder.' });
  await Offer.bulkWrite(ids.map((id, i) => ({ updateOne: { filter: { _id: id, userId: req.user.id }, update: { $set: { order: i } } } })));
  res.json({ ok: true });
});

// Edit an existing offer
app.put('/api/offers/:id', authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
    const b = req.body || {};
    const set = {};
    if (b.title !== undefined) {
      if (!String(b.title).trim()) return res.status(400).json({ message: 'Title is required.' });
      set.title = String(b.title).trim().slice(0, 120);
    }
    if (b.price !== undefined) {
      const p = Number(b.price);
      if (!isFinite(p) || p < 0) return res.status(400).json({ message: 'Invalid price.' });
      set.price = p;
    }
    if (b.description !== undefined) set.description = String(b.description).slice(0, 500);
    if (b.imageUrl !== undefined) set.imageUrl = /^https:\/\//.test(b.imageUrl || '') ? b.imageUrl : null;
    const offer = await Offer.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { $set: set }, { new: true });
    if (!offer) return res.status(404).json({ message: 'Offer not found' });
    res.json({ offer });
  } catch (err) {
    res.status(500).json({ message: 'Could not save the offer.' });
  }
});

// Remove only the photo of an offer (the offer itself stays)
app.delete('/api/offers/:id/image', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  const offer = await Offer.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { imageUrl: null }, { new: true });
  if (!offer) return res.status(404).json({ message: 'Offer not found' });
  res.json({ offer });
});

// ---------- Orders ----------
app.patch('/api/orders/:id', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  const status = req.body && req.body.status;
  if (!['Pending', 'Completed', 'Cancelled'].includes(status)) return res.status(400).json({ message: 'Invalid status' });
  const order = await Order.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { status }, { new: true });
  if (!order) return res.status(404).json({ message: 'Order not found' });
  res.json({ order });
});

app.post('/api/orders', authenticateToken, async (req, res) => {
  const { offerTitle, customerName, amount } = req.body || {};
  const a = Number(amount);
  if (!isFinite(a) || a < 0) return res.status(400).json({ message: 'Invalid amount' });
  const order = await Order.create({
    userId: req.user.id, offerTitle: String(offerTitle || '').slice(0, 120),
    customerName: String(customerName || '').slice(0, 80), amount: a, status: 'Completed'
  });
  res.json({ order });
});

// ---------- Dashboard (real numbers from the database) ----------
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const [orders, offersCount] = await Promise.all([
      Order.find({ userId: req.user.id }).sort({ createdAt: -1 }),
      Offer.countDocuments({ userId: req.user.id })
    ]);
    const completed = orders.filter(o => o.status === 'Completed');
    const totalRevenue = completed.reduce((s, o) => s + (o.amount || 0), 0);

    const now = new Date();
    const months = [];
    for (let i = 5; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push({ key: `${d.getFullYear()}-${d.getMonth()}`, label: d.toLocaleString('en', { month: 'short' }), revenue: 0 });
    }
    completed.forEach(o => {
      const d = new Date(o.createdAt);
      const m = months.find(x => x.key === `${d.getFullYear()}-${d.getMonth()}`);
      if (m) m.revenue += o.amount || 0;
    });

    res.json({
      totalRevenue,
      completedOrders: completed.length,
      pendingOrders: orders.filter(o => o.status === 'Pending').length,
      offersCount,
      monthly: months.map(m => ({ label: m.label, revenue: m.revenue })),
      recentOrders: orders.slice(0, 10)
    });
  } catch (err) {
    res.status(500).json({ message: 'Could not load statistics.' });
  }
});

// ---------- AI market price ----------
app.post('/api/ai/market-price', authenticateToken, async (req, res) => {
  const { query, category, city } = req.body || {};
  try {
    const response = await axios.post(
      'https://api.openai.com/v1/responses',
      {
        model: 'gpt-4o-mini',
        tools: [{ type: 'web_search' }],
        input: `You are a price analyst for Bulgaria. Find current real prices for: "${query}". Category: "${category}". Region: "${city}".
Use web search and only real offers found. Do not invent prices. Prices must be in EUR (convert from BGN at 1.95583 if needed).
Return ONLY JSON: {"minPrice": number, "maxPrice": number, "avgPrice": number, "description": "short description in English", "sources": [{"name": "", "price": number, "url": ""}]}`
      },
      { headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' } }
    );
    let text = response.data.output_text;
    if (!text && Array.isArray(response.data.output)) {
      const msg = response.data.output.find(o => o.type === 'message');
      text = msg && msg.content && msg.content[0] && msg.content[0].text;
    }
    const match = String(text || '').match(/\{[\s\S]*\}/);
    if (!match) throw new Error('No JSON in AI response');
    res.json({ ...JSON.parse(match[0]), estimated: false });
  } catch (err) {
    console.error('AI price error:', err.response ? JSON.stringify(err.response.data) : err.message);
    // No live price data: fill in a description only, never invent prices
    const where = city ? ` in ${city}` : '';
    res.json({
      estimated: true,
      description: `Professional ${query}${where}. Quality work, fair prices and reliable service.`,
      message: 'Live market prices are unavailable right now. Please enter the price manually.'
    });
  }
});

// ---------- Image upload ----------
app.post('/api/upload', authenticateToken, (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) {
      const msg = err.code === 'LIMIT_FILE_SIZE' ? 'The image is too big (max 5 MB).' : 'Image upload failed: ' + err.message;
      return res.status(400).json({ message: msg });
    }
    if (!req.file) return res.status(400).json({ message: 'Please choose an image file (JPG, PNG, WEBP or GIF, max 5 MB).' });
    try {
      const img = await Image.create({ userId: req.user.id, contentType: req.file.mimetype, data: req.file.buffer });
      res.json({ url: PUBLIC_BASE + '/api/image/' + img._id });
    } catch (e) {
      console.error('Upload error:', e.message);
      res.status(500).json({ message: 'Image upload failed. Please try again.' });
    }
  });
});

// Public: images must load on the public site and on the builder (a different domain)
app.get('/api/image/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).end();
    const img = await Image.findById(req.params.id).lean();
    if (!img) return res.status(404).end();
    res.set({
      'Content-Type': img.contentType || 'image/jpeg',
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Cross-Origin-Resource-Policy': 'cross-origin'
    });
    res.send(img.data.buffer ? Buffer.from(img.data.buffer) : img.data);
  } catch (e) {
    res.status(404).end();
  }
});

// ---------- Public customer site (futuristic design, themed with the customer's colors and font) ----------
function renderSite(user, offers, sent) {
  const t = THEMES[user.theme] || THEMES.gold;
  const f = FONTS[user.font] || FONTS.sans;
  const okImg = (u) => /^https:\/\//.test(u || '');
  const firstImg = offers.find(o => okImg(o.imageUrl));
  const heroBg = firstImg ? `<div class="herobg" style="background-image:url('${esc(encodeURI(firstImg.imageUrl))}')"></div>` : '';
  const names = offers.map(o => `<span>${esc(o.title)}</span>`).join('');
  const meta = [user.category, user.city].filter(Boolean).map(esc).join(' &middot; ');
  const cards = offers.length === 0
    ? '<p class="none">No offers yet. Please check back soon.</p>'
    : offers.map((o, i) => `
<article class="card rv" style="--d:${(i % 6) * 70}ms">
  <div class="pic">${okImg(o.imageUrl)
    ? `<img src="${esc(o.imageUrl)}" alt="${esc(o.title)}" loading="lazy">`
    : `<div class="ph">${esc(String(o.title || '?').charAt(0).toUpperCase())}</div>`}
    <span class="tag">&euro;${Number(o.price || 0).toFixed(2)}</span></div>
  <div class="in"><h3>${esc(o.title)}</h3><p>${esc(o.description)}</p>
    <details class="req"><summary>Request this offer</summary>
      <form method="POST" action="/site/${esc(user.slug)}/order">
        <input type="hidden" name="offerId" value="${o._id}">
        <input name="customerName" placeholder="Your name" required maxlength="80">
        <input name="customerContact" placeholder="Phone or email" required maxlength="120">
        <label class="consent"><input type="checkbox" name="consent" value="1" required> <span>I agree that my details are used to answer my request. <a href="${PUBLIC_BASE}/privacy" target="_blank" rel="noopener">Privacy Policy</a></span></label>
        <button type="submit">Send request</button>
      </form></details></div>
</article>`).join('');

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(user.siteName)}</title>
<meta name="description" content="${esc(user.siteName)} - ${esc(user.category)} in ${esc(user.city)}">
<meta name="theme-color" content="#070a10">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=${f.gf}&display=swap" rel="stylesheet">
<style>
:root{--a:${t.a};--b:${t.b};--ink:${t.ink};--on:${t.on}}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:${f.css};background:#f2f2ef;color:#10131a;-webkit-font-smoothing:antialiased;overflow-x:hidden}
.bar{position:fixed;top:0;left:0;right:0;z-index:30;display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 28px;color:#fff;background:rgba(7,10,16,.55);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid rgba(255,255,255,.1)}
.bar b{font-size:1.05rem;letter-spacing:-.01em}
.bar a{color:#fff;text-decoration:none;font-size:.92rem;padding:9px 18px;border-radius:99px;border:1px solid rgba(255,255,255,.28);transition:background .2s}
.bar a:hover{background:rgba(255,255,255,.12)}
.hero{position:relative;min-height:100vh;min-height:100svh;background:#070a10;color:#fff;display:flex;align-items:center;justify-content:center;text-align:center;overflow:hidden;padding:120px 24px 90px}
.herobg{position:absolute;inset:-8%;background-size:cover;background-position:center;filter:blur(30px) saturate(1.3);opacity:.32;transform:scale(1.1)}
.blob{position:absolute;border-radius:50%;filter:blur(90px);opacity:.5;animation:drift 18s ease-in-out infinite alternate;will-change:transform}
.b1{width:560px;height:560px;background:var(--a);left:-10%;top:-14%}
.b2{width:640px;height:640px;background:var(--b);right:-14%;bottom:-20%;animation-delay:-7s}
.gridbg{position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.055) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.055) 1px,transparent 1px);background-size:56px 56px;-webkit-mask-image:radial-gradient(ellipse at center,#000 25%,transparent 72%);mask-image:radial-gradient(ellipse at center,#000 25%,transparent 72%)}
.ring{position:absolute;width:min(82vw,760px);aspect-ratio:1;border:1px solid rgba(255,255,255,.14);border-radius:50%;animation:spin 46s linear infinite}
.ring::after{content:'';position:absolute;top:-6px;left:50%;width:12px;height:12px;border-radius:50%;background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 26px var(--a)}
.ring.r2{width:min(56vw,520px);animation-direction:reverse;animation-duration:28s;border-color:rgba(255,255,255,.1)}
.hero-in{position:relative;z-index:2;max-width:920px}
.chip{display:inline-block;border:1px solid rgba(255,255,255,.25);border-radius:99px;padding:8px 18px;font-size:.86rem;margin-bottom:28px;background:rgba(255,255,255,.07);backdrop-filter:blur(8px);animation:rise .8s both}
h1{font-size:clamp(2.7rem,9vw,7rem);line-height:1.02;letter-spacing:-.035em;background:linear-gradient(100deg,#fff 15%,var(--a) 50%,var(--b) 80%,#fff);background-size:220% auto;-webkit-background-clip:text;background-clip:text;color:transparent;animation:rise .9s .1s both,shine 9s linear infinite;padding-bottom:.08em}
.lead{color:#c3cad6;font-size:clamp(1rem,1.7vw,1.25rem);margin:22px auto 0;max-width:46ch;animation:rise .9s .25s both}
.cta{display:inline-block;margin-top:38px;background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);text-decoration:none;font-weight:700;padding:16px 34px;border-radius:99px;box-shadow:0 12px 40px color-mix(in srgb,var(--a) 45%,transparent);transition:transform .2s;animation:rise .9s .4s both}
.cta:hover{transform:translateY(-3px) scale(1.02)}
.scroll{position:absolute;bottom:26px;left:50%;transform:translateX(-50%);width:22px;height:36px;border:2px solid rgba(255,255,255,.4);border-radius:12px}
.scroll::after{content:'';position:absolute;left:50%;top:7px;width:3px;height:7px;margin-left:-1.5px;border-radius:2px;background:#fff;animation:wheel 1.8s ease-in-out infinite}
.strip{background:#0b0f17;color:#fff;overflow:hidden;border-block:1px solid rgba(255,255,255,.08);padding:20px 0}
.strip div{display:flex;gap:56px;width:max-content;animation:slide 40s linear infinite}
.strip span{font-size:1.5rem;font-weight:700;letter-spacing:-.02em;white-space:nowrap;display:flex;align-items:center;gap:56px}
.strip span::after{content:'';width:10px;height:10px;border-radius:50%;background:linear-gradient(135deg,var(--a),var(--b))}
.offers{max-width:1180px;margin:0 auto;padding:110px 24px 120px}
.offers h2{font-size:clamp(2rem,5vw,3.6rem);letter-spacing:-.03em;margin-bottom:12px}
.offers .sub{color:#5a6372;margin-bottom:56px;max-width:52ch}
.ok{background:#dcfce7;color:#14532d;padding:16px 20px;border-radius:14px;margin-bottom:28px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:22px}
.card{background:#fff;border:1px solid rgba(10,14,20,.08);border-radius:22px;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 14px 40px rgba(10,14,20,.06);transition:transform .35s cubic-bezier(.2,.8,.2,1),box-shadow .35s;transform-style:preserve-3d;will-change:transform}
.card:hover{box-shadow:0 30px 70px rgba(10,14,20,.16)}
.pic{position:relative;aspect-ratio:4/3;overflow:hidden;background:#e8e8e4}
.pic img{width:100%;height:100%;object-fit:cover;transition:transform .8s cubic-bezier(.2,.8,.2,1)}
.card:hover .pic img{transform:scale(1.08)}
.ph{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:4rem;font-weight:800;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b))}
.tag{position:absolute;right:14px;top:14px;background:rgba(7,10,16,.78);color:#fff;backdrop-filter:blur(10px);padding:8px 14px;border-radius:99px;font-weight:700;font-size:.95rem;border:1px solid rgba(255,255,255,.18)}
.in{padding:22px;display:flex;flex-direction:column;flex:1}
.in h3{font-size:1.2rem;letter-spacing:-.01em;margin-bottom:8px}
.in p{color:#5a6372;font-size:.94rem;line-height:1.55;margin-bottom:18px;flex:1}
.req summary{list-style:none;cursor:pointer;text-align:center;font-weight:700;padding:14px;border-radius:14px;background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);transition:filter .2s}
.req summary::-webkit-details-marker{display:none}
.req summary:hover{filter:brightness(1.06)}
.req[open] summary{background:#10131a;color:#fff}
.req form{margin-top:12px;display:grid;gap:8px}
input{width:100%;padding:13px 14px;border:1px solid #d9dbe2;border-radius:12px;font-family:inherit;font-size:.95rem;background:#fff}
input:focus{outline:2px solid var(--ink);border-color:transparent}
button{border:0;border-radius:12px;padding:13px;font-weight:700;font-family:inherit;cursor:pointer;background:#10131a;color:#fff}
.none{color:#5a6372;padding:30px 0}
.consent{display:flex;gap:10px;align-items:flex-start;font-size:.8rem;color:#5a6372;line-height:1.4;text-align:left}
.consent input{width:auto;margin:2px 0 0;flex-shrink:0}
.consent a{color:var(--ink)}
footer{background:#070a10;color:#8b94a5;text-align:center;padding:48px 20px;font-size:.88rem}
footer b{display:block;color:#fff;font-size:1.2rem;margin-bottom:6px}
.rv{opacity:0;transform:translateY(34px);transition:opacity .8s var(--d,0ms),transform .8s var(--d,0ms)}
.rv.in-view{opacity:1;transform:none}
@keyframes drift{to{transform:translate(70px,50px) scale(1.15)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shine{to{background-position:220% center}}
@keyframes rise{from{opacity:0;transform:translateY(26px)}to{opacity:1;transform:none}}
@keyframes wheel{0%{opacity:0;transform:translateY(0)}30%{opacity:1}100%{opacity:0;transform:translateY(12px)}}
@keyframes slide{to{transform:translateX(-50%)}}
@media (max-width:600px){.bar{padding:12px 16px}.offers{padding:80px 18px 90px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}.rv{opacity:1;transform:none}}
</style></head><body>
<header class="bar"><b>${esc(user.siteName)}</b><a href="#offers">View offers</a></header>
<section class="hero">${heroBg}<div class="blob b1"></div><div class="blob b2"></div><div class="gridbg"></div><div class="ring"></div><div class="ring r2"></div>
<div class="hero-in">
${meta ? `<div class="chip">${meta}</div>` : ''}
<h1>${esc(user.siteName)}</h1>
<p class="lead">Browse our offers and send a request in seconds. We will get back to you.</p>
<a class="cta" href="#offers">See what we offer</a></div><div class="scroll" aria-hidden="true"></div></section>
${offers.length ? `<div class="strip" aria-hidden="true"><div>${names}${names}${names}${names}</div></div>` : ''}
<main class="offers" id="offers">
<h2 class="rv">Our offers</h2><p class="sub rv">Pick what you need and send a request. No account needed.</p>
${sent ? '<div class="ok">Thank you. Your request was sent and the business will contact you.</div>' : ''}
<div class="grid">${cards}</div></main>
<footer><b>${esc(user.siteName)}</b>${meta}<div style="margin-top:18px">Built with GoldOffer Studio</div></footer>
<script>
(function(){
  var els=document.querySelectorAll('.rv');
  if('IntersectionObserver' in window){var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in-view');io.unobserve(e.target)}})},{threshold:.12});els.forEach(function(e){io.observe(e)})}
  else els.forEach(function(e){e.classList.add('in-view')});
  var hero=document.querySelector('.hero'),b1=document.querySelector('.b1'),b2=document.querySelector('.b2');
  if(hero&&matchMedia('(pointer:fine)').matches){hero.addEventListener('pointermove',function(e){var x=(e.clientX/innerWidth-.5),y=(e.clientY/innerHeight-.5);b1.style.translate=(x*80)+'px '+(y*60)+'px';b2.style.translate=(-x*90)+'px '+(-y*70)+'px'})}
  if(matchMedia('(pointer:fine)').matches){document.querySelectorAll('.card').forEach(function(c){
    c.addEventListener('pointermove',function(e){var r=c.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;c.style.transform='perspective(900px) rotateY('+(x*6)+'deg) rotateX('+(-y*6)+'deg) translateY(-6px)'});
    c.addEventListener('pointerleave',function(){c.style.transform=''})})}
})();
</script>
</body></html>`;
}

app.get('/site/:slug', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    const offers = await Offer.find({ userId: user._id }).sort({ createdAt: -1 });
    // This page needs one small inline script (scroll animations); everything else stays locked down
    res.setHeader('Content-Security-Policy', [
      "default-src 'self'",
      "script-src 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src https://fonts.gstatic.com",
      "img-src 'self' data: https:",
      "form-action 'self'",
      "base-uri 'self'"
    ].join('; '));
    res.send(renderSite(user, offers, req.query.sent === '1'));
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/site/:slug/order', publicLimiter, async (req, res) => {
  try {
    if (req.body.consent !== '1') return res.status(400).send('Please accept the privacy notice and go back.');
    const user = await User.findOne({ slug: req.params.slug, published: true });
    if (!user || !mongoose.isValidObjectId(req.body.offerId)) return res.status(404).send('Not found');
    const offer = await Offer.findOne({ _id: req.body.offerId, userId: user._id });
    if (!offer) return res.status(404).send('Offer not found');
    await Order.create({
      userId: user._id, offerTitle: offer.title, amount: offer.price,
      customerName: String(req.body.customerName || '').slice(0, 80),
      customerContact: String(req.body.customerContact || '').slice(0, 120),
      status: 'Pending'
    });
    // Tell the business owner right away (not awaited, so the customer never waits for email)
    if (user.notifyOn !== false) {
      const name = String(req.body.customerName || '').slice(0, 80);
      const contact = String(req.body.customerContact || '').slice(0, 120);
      sendMail({
        to: user.notifyEmail || user.email,
        subject: `Нова заявка / New request: ${offer.title}`,
        text: `Нова заявка за "${offer.title}" (EUR ${Number(offer.price || 0).toFixed(2)})\nИме: ${name}\nКонтакт: ${contact}\n\nNew request for "${offer.title}"\nName: ${name}\nContact: ${contact}\n\n${PUBLIC_BASE}/dashboard`,
        html: `<h3>Нова заявка / New request</h3><p><b>${esc(offer.title)}</b> (EUR ${Number(offer.price || 0).toFixed(2)})</p><p>Име / Name: <b>${esc(name)}</b><br>Контакт / Contact: <b>${esc(contact)}</b></p><p><a href="${PUBLIC_BASE}/dashboard">Отвори таблото / Open dashboard</a></p>`
      });
    }
    res.redirect(303, `/site/${user.slug}?sent=1`);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// ---------- Stripe checkout ----------
app.post('/api/stripe/create-checkout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
      allow_promotion_codes: true,
      client_reference_id: String(user._id),
      customer_email: user.email,
      subscription_data: { trial_period_days: 7 },
      success_url: `${PUBLIC_BASE}/dashboard?paid=1`,
      cancel_url: `${PUBLIC_BASE}/build`
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe Checkout Error:', err);
    res.status(500).json({ message: 'Could not start checkout.' });
  }
});

// ---------- The website itself: one page file, several routes (each route is its own page) ----------
function findFile(name) {
  const candidates = [path.join(__dirname, name), path.join(__dirname, '..', name), path.join(process.cwd(), name)];
  return candidates.find(p => fs.existsSync(p));
}

const PAGE_ROUTES = ['/', '/how-it-works', '/features', '/professions', '/pricing', '/about', '/contact', '/build', '/dashboard', '/privacy', '/terms', '/reset'];
app.get(PAGE_ROUTES, (req, res) => {
  const file = findFile('index.html');
  if (!file) return res.send('GoldOffer API is running.');
  // The page uses inline scripts and a few external resources (fonts, chart library, photos)
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "script-src-attr 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https: blob:",
    "connect-src 'self' https://cdn.jsdelivr.net https://en.wikipedia.org",
    "form-action 'self'"
  ].join('; '));
  res.sendFile(file);
});

// Site icon: gold gradient square with a dark "G"
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ffd700"/><stop offset="1" stop-color="#ff8c00"/></linearGradient></defs>
<rect width="64" height="64" rx="14" fill="url(#g)"/>
<text x="32" y="46" font-size="38" font-weight="800" text-anchor="middle" fill="#1a1a1a" font-family="Arial, Helvetica, sans-serif">G</text></svg>`;
app.get('/favicon.svg', (req, res) => {
  res.type('image/svg+xml').set('Cache-Control', 'public, max-age=86400').send(FAVICON_SVG);
});
app.get('/favicon.ico', (req, res) => res.redirect(301, '/favicon.svg'));

app.get('/logo.jpg', (req, res) => {
  const file = findFile('logo.jpg');
  if (!file) return res.status(404).end();
  res.sendFile(file);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));