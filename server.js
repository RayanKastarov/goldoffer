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
  imageUrl: String,                      // cover photo (always the first gallery image)
  images: { type: [String], default: [] }, // gallery: links to /api/image/<id> (the bytes live in the Image collection)
  longDescription: String,
  order: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  offerTitle: String,
  customerName: String,
  customerContact: String,
  contacts: [{ type: { type: String }, value: String, _id: false }],
  note: String,
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
// Ways a customer can be reached: they pick the type for every contact and can add several
const CONTACT_TYPES = { phone: 'Phone', email: 'Email', instagram: 'Instagram', facebook: 'Facebook', x: 'X', tiktok: 'TikTok', telegram: 'Telegram', whatsapp: 'WhatsApp', viber: 'Viber', other: 'Other' };
function parseContacts(body) {
  const types = [].concat((body && body.ctype) || []);
  const vals = [].concat((body && body.cvalue) || []);
  if (!vals.length && body && body.customerContact) vals.push(body.customerContact); // old form
  const contacts = [];
  for (let i = 0; i < vals.length && contacts.length < 5; i++) {
    const value = String(vals[i] || '').trim().slice(0, 120);
    if (!value) continue;
    let type = String(types[i] || 'other').toLowerCase();
    if (!CONTACT_TYPES[type]) type = 'other';
    if (type === 'email' && !isEmail(value)) return { error: 'Please enter a valid email address.' };
    if ((type === 'phone' || type === 'whatsapp' || type === 'viber') && value.replace(/\D/g, '').length < 6) return { error: 'Please enter a valid phone number.' };
    contacts.push({ type, value });
  }
  if (!contacts.length) return { error: 'Please leave at least one way to contact you.' };
  return { contacts, text: contacts.map(c => `${CONTACT_TYPES[c.type]}: ${c.value}`).join(' | ') };
}
const MAX_GALLERY = 8;
const cleanImages = (arr) => (Array.isArray(arr) ? arr : []).filter(u => /^https:\/\//.test(u || '')).map(String).slice(0, MAX_GALLERY);
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
    subject: `${code} is your GoldOffer code`,
    text: `Hello,\nYour confirmation code is: ${code}\nIt is valid for ${VERIFY_MINUTES} minutes.\n\nIf you did not sign up, ignore this email.`,
    html: emailShell({
      icon: '&#9993;',
      preheader: `${code} is your code`,
      heading: ['', 'Confirm your email'],
      intro: ['', `Hello! Enter this code to finish creating your account. It is valid for ${VERIFY_MINUTES} minutes.`],
      code,
      footnote: ['', 'If you did not sign up, simply ignore this email.']
    })
  });
}
const canResend = (user) => !user.verifySentAt || Date.now() - new Date(user.verifySentAt).getTime() >= VERIFY_COOLDOWN_MS;
const nowSofia = () => new Date().toLocaleString('en-GB', { timeZone: 'Europe/Sofia', dateStyle: 'medium', timeStyle: 'short' }) + ' (Sofia time)';

// Short description of the browser that made the request (no IP address is stored or sent)
function deviceOf(req) {
  const ua = String((req && req.get && req.get('user-agent')) || '');
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\/|Opera/.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Unknown browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad|iOS/.test(ua) ? 'iOS' : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'unknown system';
  return `${browser} / ${os}`;
}

// One modern layout for every email: dark card, gradient accent, round icon, optional code / details / button.
// heading, intro, buttonText and footnote are [unused, English]; details rows are [unused, label, value]. Everything shown is English.
function emailShell({ icon, preheader, heading, intro, code, details, buttonText, link, footnote }) {
  const l = link ? esc(link) : '';
  const rows = (details || []).map(([kb, ke, v], i, all) => {
    const line = i < all.length - 1 ? 'border-bottom:1px solid #232c3b;' : '';
    return `<tr><td style="padding:11px 16px;font-size:13px;color:#8b94a5;width:36%;${line}">${esc(ke)}</td><td style="padding:11px 16px;font-size:14px;color:#f1eee8;font-weight:600;${line}">${esc(v)}</td></tr>`;
  }).join('');
  const detailsBlock = rows ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 26px;background:#0a0e15;border:1px solid #232c3b;border-radius:12px;">${rows}</table>` : '';
  const codeBlock = code ? `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 26px;"><tr><td align="center" style="padding:20px 10px 20px 22px;background:#0a0e15;border:1px solid #2d3850;border-radius:14px;font-family:'Courier New',Courier,monospace;font-size:38px;line-height:1;font-weight:700;letter-spacing:12px;color:#ffffff;">${esc(code)}</td></tr></table>` : '';
  const button = l && buttonText ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 24px;"><tr><td style="border-radius:11px;background:#7f8cf2;background-image:linear-gradient(135deg,#8b7bff,#4fe3cf);"><a href="${l}" style="display:inline-block;padding:15px 30px;font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:700;color:#07090d;text-decoration:none;border-radius:11px;">${buttonText[1]} / ${buttonText[1]}</a></td></tr></table>` : '';
  const fallback = l && buttonText ? `<p style="margin:0 0 24px;font-size:12px;line-height:1.6;color:#6f7889;">Button not working? Copy this link:<br><a href="${l}" style="color:#4fe3cf;word-break:break-all;text-decoration:none;">${l}</a></p>` : '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark light"><meta name="supported-color-schemes" content="dark light"><title>GoldOffer Studio</title></head>
<body style="margin:0;padding:0;background:#05070b;font-family:Arial,Helvetica,sans-serif;">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;font-size:1px;line-height:1px;color:#05070b;">${preheader || ''}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#05070b;"><tr><td align="center" style="padding:34px 12px;">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" style="width:100%;max-width:560px;">
<tr><td align="center" style="padding:0 0 22px;"><table role="presentation" cellpadding="0" cellspacing="0"><tr>
<td align="center" width="34" height="34" style="width:34px;height:34px;border-radius:9px;background:#7f8cf2;background-image:linear-gradient(135deg,#8b7bff,#4fe3cf);font-size:20px;line-height:34px;font-weight:800;color:#07090d;">G</td>
<td style="padding-left:11px;font-size:19px;font-weight:700;color:#f1eee8;letter-spacing:-.01em;">GoldOffer Studio</td></tr></table></td></tr>
<tr><td style="background:#10151e;border:1px solid #232c3b;border-radius:18px;overflow:hidden;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr><td style="height:4px;line-height:4px;font-size:0;background:#7f8cf2;background-image:linear-gradient(90deg,#8b7bff,#4fe3cf);">&nbsp;</td></tr>
<tr><td style="padding:38px 34px 30px;color:#c4cad5;font-size:15px;line-height:1.65;">
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 22px;"><tr><td align="center" width="58" height="58" style="width:58px;height:58px;border-radius:50%;background:#171e2a;border:1px solid #2d3850;font-size:26px;line-height:58px;color:#4fe3cf;">${icon || '&#10003;'}</td></tr></table>
<h1 style="margin:0 0 4px;font-size:25px;line-height:1.25;color:#ffffff;font-weight:700;">${heading[0]}</h1>
<p style="margin:0 0 16px;font-size:15px;color:#8b94a5;">${heading[1]}</p>
<p style="margin:0 0 8px;color:#c4cad5;">${intro[0]}</p>
<p style="margin:0 0 26px;color:#8b94a5;font-size:14px;">${intro[1]}</p>
${codeBlock}${detailsBlock}${button}${fallback}
<p style="margin:0;padding-top:20px;border-top:1px solid #232c3b;font-size:13px;line-height:1.6;color:#8b94a5;">${footnote[1]}</p>
</td></tr></table>
</td></tr>
<tr><td align="center" style="padding:22px 10px 0;font-size:12px;line-height:1.6;color:#5f697a;">GoldOffer Studio &middot; This is an automated message, please do not reply.</td></tr>
</table></td></tr></table></body></html>`;
}

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
    if (user && typeof user.password !== 'string') {
      return res.status(400).json({ message: 'This account has no password yet. Press "Forgot your password?" to set one.' });
    }
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
      subject: 'New login to your GoldOffer account',
      text: `Hello,\nYou signed in to your GoldOffer Studio account on ${nowSofia()}.\nIf this was not you, reset your password right away with "Forgot your password?" and write to rayankatsarov2013@gmail.com.`,
      html: emailShell({
        icon: '&#128274;',
        preheader: 'New sign-in to your account',
        heading: ['', 'New sign-in to your account'],
        intro: ['', 'We noticed a sign-in to your GoldOffer Studio account. If this was you, there is nothing to do.'],
        details: [['', 'When', nowSofia()], ['', 'Device', deviceOf(req)]],
        buttonText: ['', 'This was not me'], link: `${PUBLIC_BASE}/?forgot=1`,
        footnote: ['', 'If you do not recognise this sign-in, reset your password right away.']
      })
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
      // updateOne skips full-document validation, so old accounts without a password field can still get a reset link
      await User.updateOne({ _id: user._id }, { $set: {
        resetTokenHash: crypto.createHash('sha256').update(token).digest('hex'),
        resetExpires: new Date(Date.now() + 60 * 60 * 1000)
      } });
      const link = `${PUBLIC_BASE}/reset?token=${token}`;
      sendMail({
        to: user.email,
        subject: 'Reset your GoldOffer password',
        text: `Hello,\nOpen this link to set a new password (valid for 1 hour):\n${link}\n\nIf you did not ask for this, ignore this email.`,
        html: emailShell({
          icon: '&#128273;',
          preheader: 'Set a new password',
          heading: ['', 'Reset your password'],
          intro: ['', 'We received a request to reset your password. Press the button and choose a new one. The link is valid for 1 hour.'],
          buttonText: ['', 'Set a new password'], link,
          footnote: ['', 'The link works only once. If you did not ask for it, ignore this email and your password will not change.']
        })
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
      subject: 'Your GoldOffer password was changed',
      text: `Hello,\nThe password of your GoldOffer Studio account was changed on ${nowSofia()}.\nIf this was not you, request a new password right away and write to rayankatsarov2013@gmail.com.`,
      html: emailShell({
        icon: '&#10003;',
        preheader: 'Your password was changed',
        heading: ['', 'Your password was changed'],
        intro: ['', 'The password of your GoldOffer Studio account was just changed.'],
        details: [['', 'When', nowSofia()], ['', 'Device', deviceOf(req)]],
        buttonText: ['', 'I did not do this'], link: `${PUBLIC_BASE}/?forgot=1`,
        footnote: ['', 'If you changed it yourself, ignore this email. If not, reset it again right now and write to us.']
      })
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

// Change the name shown in the top bar
app.put('/api/auth/profile', authenticateToken, async (req, res) => {
  try {
    const b = req.body || {};
    const firstName = String(b.firstName || '').trim().slice(0, 40);
    if (!firstName) return res.status(400).json({ message: 'Please enter your name.' });
    const user = await User.findByIdAndUpdate(req.user.id, { firstName, lastName: String(b.lastName || '').trim().slice(0, 40) }, { new: true });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json({ user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ message: 'Could not save your name.' });
  }
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
    const { title, price, description, imageUrl, longDescription } = req.body || {};
    const gallery = cleanImages(req.body && req.body.images);
    if (!gallery.length && /^https:\/\//.test(imageUrl || '')) gallery.push(imageUrl);
    if (!title || !String(title).trim()) return res.status(400).json({ message: 'Title is required.' });
    const p = Number(price);
    if (!isFinite(p) || p < 0) return res.status(400).json({ message: 'Invalid price.' });
    const offer = await Offer.create({
      userId: req.user.id,
      title: String(title).trim().slice(0, 120),
      price: p,
      description: String(description || '').slice(0, 500),
      longDescription: String(longDescription || '').slice(0, 4000),
      images: gallery,
      imageUrl: gallery[0] || null,
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
    if (b.longDescription !== undefined) set.longDescription = String(b.longDescription).slice(0, 4000);
    if (b.images !== undefined) { set.images = cleanImages(b.images); set.imageUrl = set.images[0] || null; }
    else if (b.imageUrl !== undefined) set.imageUrl = /^https:\/\//.test(b.imageUrl || '') ? b.imageUrl : null;
    const offer = await Offer.findOneAndUpdate({ _id: req.params.id, userId: req.user.id }, { $set: set }, { new: true });
    if (!offer) return res.status(404).json({ message: 'Offer not found' });
    res.json({ offer });
  } catch (err) {
    res.status(500).json({ message: 'Could not save the offer.' });
  }
});

// Remove one photo of an offer (?url=...) or all photos when no url is given. The offer itself stays.
app.delete('/api/offers/:id/image', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  const offer = await Offer.findOne({ _id: req.params.id, userId: req.user.id });
  if (!offer) return res.status(404).json({ message: 'Offer not found' });
  const url = String(req.query.url || '');
  const all = (offer.images && offer.images.length) ? offer.images : (offer.imageUrl ? [offer.imageUrl] : []);
  offer.images = url ? all.filter(u => u !== url) : [];
  offer.imageUrl = offer.images[0] || null;
  await offer.save();
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

// ---------- Market price: real Google results for the product in the user's city ----------
// Needs ONE of these in Render, Environment:
//   SERPAPI_KEY                       (serpapi.com, real Google results incl. Google Shopping, location aware)
//   GOOGLE_API_KEY + GOOGLE_CX        (Google Programmable Search JSON API, 100 free searches per day)
// Prices are only ever read from real results. Nothing is invented.
const BGN_PER_EUR = 1.95583;
function extractPrices(text) {
  const out = [];
  const t = String(text || '').replace(/\u00a0/g, ' ');
  const num = '(\\d{1,3}(?:[ .]\\d{3})+(?:[.,]\\d{1,2})?|\\d+(?:[.,]\\d{1,2})?)';
  const patterns = [
    { re: new RegExp(num + '\\s*(?:лв\\.?|лева|BGN)', 'gi'), cur: 'BGN' },
    { re: new RegExp(num + '\\s*(?:€|EUR|eur|евро)', 'g'), cur: 'EUR' },
    { re: new RegExp('(?:€|EUR)\\s*' + num, 'g'), cur: 'EUR' }
  ];
  patterns.forEach(({ re, cur }) => {
    let m;
    while ((m = re.exec(t))) {
      let raw = m[1].replace(/ /g, '');
      // "1.200,50" or "1,200.50" or "1.200" (thousands) or "12,50" (decimal)
      if (/^\d{1,3}(\.\d{3})+(,\d{1,2})?$/.test(raw)) raw = raw.replace(/\./g, '').replace(',', '.');
      else raw = raw.replace(',', '.');
      let v = parseFloat(raw);
      if (!isFinite(v) || v <= 0) continue;
      if (cur === 'BGN') v = v / BGN_PER_EUR;
      if (v < 100000) out.push(Math.round(v * 100) / 100);
    }
  });
  return out;
}
const hostOf = (u) => { try { return new URL(u).hostname.replace(/^www\./, ''); } catch (e) { return ''; } };

// Calls SerpAPI. The location parameter must exactly match SerpAPI's own location list, so if it is rejected we retry without it
// (the city is already inside the search text, and gl/hl keep the results Bulgarian).
async function serp(params) {
  const base = { api_key: process.env.SERPAPI_KEY, google_domain: 'google.bg', gl: 'bg', hl: 'bg' };
  try {
    const r = await axios.get('https://serpapi.com/search.json', { timeout: 25000, params: { ...base, ...params } });
    if (r.data && r.data.error) throw Object.assign(new Error(r.data.error), { serpError: r.data.error });
    return r.data || {};
  } catch (err) {
    const msg = (err.response && err.response.data && err.response.data.error) || err.serpError || err.message;
    if (params.location && /location/i.test(String(msg))) {
      const { location, ...rest } = params;
      return serp(rest);
    }
    throw Object.assign(new Error(String(msg)), { serpError: String(msg), status: err.response && err.response.status });
  }
}

async function googleResults(query, city) {
  const items = []; // { name, url, texts: [], price?: number }
  if (process.env.SERPAPI_KEY) {
    const q = `${query} цена ${city}`.trim();
    const d = await serp({ engine: 'google', q, location: `${city}, Bulgaria`, num: 20 });
    (d.shopping_results || []).forEach(x => items.push({ name: x.source || x.title, url: x.link || x.product_link, texts: [x.price || ''], price: x.extracted_price }));
    (d.inline_shopping_results || []).forEach(x => items.push({ name: x.source || x.title, url: x.link, texts: [x.price || ''], price: x.extracted_price }));
    ((d.local_results && d.local_results.places) || []).forEach(x => items.push({ name: x.title, url: x.links && x.links.website, texts: [x.price || '', x.description || ''] }));
    (d.organic_results || []).forEach(x => items.push({ name: x.source || hostOf(x.link), url: x.link, texts: [x.title, x.snippet, ...(x.rich_snippet && x.rich_snippet.top && x.rich_snippet.top.detected_extensions ? [String(x.rich_snippet.top.detected_extensions.price || '')] : [])] }));
    // Few prices in normal results: ask Google Shopping as well (one more search credit)
    const withPrice = items.filter(it => it.price != null || extractPrices((it.texts || []).join(' ')).length).length;
    if (withPrice < 3) {
      try {
        const sh = await serp({ engine: 'google_shopping', q: `${query} ${city}`.trim(), location: `${city}, Bulgaria` });
        (sh.shopping_results || []).forEach(x => items.push({ name: x.source || x.title, url: x.product_link || x.link, texts: [x.price || ''], price: x.extracted_price }));
      } catch (e) { /* the normal results are still used */ }
    }
    return items;
  }
  if (process.env.GOOGLE_API_KEY && process.env.GOOGLE_CX) {
    const q = `${query} цена ${city}`.trim();
    const r = await axios.get('https://www.googleapis.com/customsearch/v1', {
      timeout: 20000,
      params: { key: process.env.GOOGLE_API_KEY, cx: process.env.GOOGLE_CX, q, gl: 'bg', hl: 'bg', lr: 'lang_bg', num: 10 }
    });
    (r.data.items || []).forEach(x => {
      const og = (x.pagemap && x.pagemap.offer) || [];
      items.push({ name: x.displayLink, url: x.link, texts: [x.title, x.snippet, ...og.map(o => `${o.price || ''} ${o.pricecurrency || ''}`)] });
    });
    return items;
  }
  return null; // no Google access configured
}

app.post('/api/ai/market-price', authenticateToken, async (req, res) => {
  const query = String((req.body && req.body.query) || '').trim().slice(0, 120);
  const city = String((req.body && req.body.city) || '').trim().slice(0, 80) || 'Bulgaria';
  if (!query) return res.status(400).json({ message: 'Enter a title first.' });
  const fallbackDesc = `Professional ${query} in ${city}. Quality work, fair prices and reliable service.`;
  try {
    const items = await googleResults(query, city);
    if (items === null) {
      return res.json({ estimated: true, description: fallbackDesc, message: 'Live price search is not set up on the server yet (SERPAPI_KEY or GOOGLE_API_KEY + GOOGLE_CX is missing). Please enter the price manually.' });
    }
    const found = []; // { price, name, url }
    items.forEach(it => {
      const prices = it.price != null && isFinite(it.price) ? [it.price] : extractPrices((it.texts || []).join(' | '));
      // a result counts once, with its first price, so one page with many prices cannot skew the range
      if (prices.length) found.push({ price: Number(prices[0]), name: it.name || hostOf(it.url), url: it.url });
    });
    if (found.length < 2) {
      return res.json({ estimated: true, description: fallbackDesc, message: `Google returned ${items.length} results for "${query}" in ${city}, but only ${found.length} showed a price (at least 2 are needed). Try a more common product name, or enter the price manually.` });
    }
    // drop outliers: keep prices within 0.33x to 3x of the median
    const sorted = found.map(f => f.price).sort((a, b) => a - b);
    const median = sorted[Math.floor(sorted.length / 2)];
    const kept = found.filter(f => f.price >= median / 3 && f.price <= median * 3);
    const ps = kept.map(f => f.price);
    const avg = ps.reduce((a, b) => a + b, 0) / ps.length;
    res.json({
      estimated: false,
      minPrice: Math.min(...ps), maxPrice: Math.max(...ps), avgPrice: Math.round(avg * 100) / 100,
      description: fallbackDesc,
      city,
      sampleSize: kept.length,
      sources: kept.slice(0, 6).map(f => ({ name: f.name, price: f.price, url: f.url }))
    });
  } catch (err) {
    const why = String(err.serpError || (err.response && err.response.data && (err.response.data.error && (err.response.data.error.message || err.response.data.error))) || err.message || 'unknown error').slice(0, 200);
    console.error('Market price error:', why);
    res.json({ estimated: true, description: fallbackDesc, message: `The Google price search failed: ${why}. You can enter the price manually.` });
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

// ---------- Chat between visitors and the business (no account needed for the visitor) ----------
const ConversationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, index: true },
  offerId: mongoose.Schema.Types.ObjectId,
  offerTitle: String,
  customerName: String,
  customerEmail: String,          // optional, only used to say "you have a reply"
  tokenHash: String,              // the visitor proves who they are with a secret kept in their browser
  messages: [{ from: String, text: String, at: { type: Date, default: Date.now }, _id: false }],
  unreadSeller: { type: Number, default: 0 },
  unreadCustomer: { type: Number, default: 0 },
  lastAt: { type: Date, default: Date.now },
  sellerMailedAt: Date,
  customerMailedAt: Date
});
const Conversation = mongoose.model('Conversation', ConversationSchema);

const startLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
const tokHash = (t) => crypto.createHash('sha256').update(String(t || '')).digest('hex');
const cleanMsg = (v) => String(v || '').replace(/\r/g, '').trim().slice(0, 1500);
const MAX_MSGS = 300;
const MAIL_GAP_MS = 10 * 60 * 1000;
function tokenOk(conv, token) {
  if (!conv || !token) return false;
  const a = Buffer.from(conv.tokenHash || '', 'hex'), b = Buffer.from(tokHash(token), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const lastOf = (c) => (c.messages.length ? c.messages[c.messages.length - 1] : null);
const briefConv = (c, forSeller) => ({
  id: c._id, offerId: c.offerId, offerTitle: c.offerTitle, customerName: c.customerName, customerEmail: forSeller ? c.customerEmail : undefined,
  last: lastOf(c), unread: forSeller ? c.unreadSeller : c.unreadCustomer, lastAt: c.lastAt, count: c.messages.length
});

async function siteBySlug(slug) {
  const user = await User.findOne({ slug });
  return user && user.published ? user : null;
}

// Visitor: start a conversation about an offer
app.post('/site/:slug/chat/start', startLimiter, async (req, res) => {
  try {
    const user = await siteBySlug(req.params.slug);
    if (!user) return res.status(404).json({ message: 'Site not found.' });
    const b = req.body || {};
    if (!mongoose.isValidObjectId(b.offerId)) return res.status(400).json({ message: 'Offer not found.' });
    const offer = await Offer.findOne({ _id: b.offerId, userId: user._id });
    if (!offer) return res.status(404).json({ message: 'Offer not found.' });
    const name = String(b.name || '').trim().slice(0, 60);
    const text = cleanMsg(b.text);
    const email = String(b.email || '').trim().slice(0, 120);
    if (!name) return res.status(400).json({ message: 'Please enter your name.' });
    if (!text) return res.status(400).json({ message: 'Please write a message.' });
    if (email && !isEmail(email)) return res.status(400).json({ message: 'That email address does not look right.' });
    const token = crypto.randomBytes(24).toString('hex');
    const conv = await Conversation.create({
      userId: user._id, offerId: offer._id, offerTitle: offer.title, customerName: name, customerEmail: email || undefined,
      tokenHash: tokHash(token), messages: [{ from: 'customer', text, at: new Date() }], unreadSeller: 1, lastAt: new Date(), sellerMailedAt: new Date()
    });
    if (user.notifyOn !== false) {
      sendMail({
        to: user.notifyEmail || user.email,
        subject: `New message about ${offer.title}`,
        text: `${name} wrote about "${offer.title}":\n\n${text}\n\nReply: ${PUBLIC_BASE}/dashboard`,
        html: emailShell({
          icon: '&#128172;', preheader: `${esc(name)}: ${esc(text.slice(0, 80))}`,
          heading: ['', 'New message'], intro: ['', `${esc(name)} sent you a message about “${esc(offer.title)}”.`],
          details: [['', 'From', name], ['', 'Message', text]],
          buttonText: ['', 'Reply in dashboard'], link: `${PUBLIC_BASE}/dashboard`,
          footnote: ['', 'Reply from your dashboard. The visitor sees your answer on the offer page.']
        })
      });
    }
    res.json({ id: conv._id, token, messages: conv.messages });
  } catch (err) {
    res.status(500).json({ message: 'Could not send your message. Please try again.' });
  }
});

// Visitor: list of their own conversations on this site (used by the Saved page)
app.post('/site/:slug/chat/list', chatLimiter, async (req, res) => {
  try {
    const user = await siteBySlug(req.params.slug);
    if (!user) return res.status(404).json({ message: 'Site not found.' });
    const items = (Array.isArray(req.body && req.body.chats) ? req.body.chats : []).slice(0, 20).filter(x => x && mongoose.isValidObjectId(x.id));
    const found = await Conversation.find({ _id: { $in: items.map(x => x.id) }, userId: user._id });
    const out = found.filter(c => tokenOk(c, (items.find(x => String(x.id) === String(c._id)) || {}).token)).map(c => briefConv(c, false));
    out.sort((a, b) => new Date(b.lastAt) - new Date(a.lastAt));
    res.json({ conversations: out });
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// Visitor: read the thread (polled every few seconds by the offer page)
app.get('/site/:slug/chat/:id', chatLimiter, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Not found' });
    const user = await siteBySlug(req.params.slug);
    const conv = user && await Conversation.findOne({ _id: req.params.id, userId: user._id });
    if (!conv || !tokenOk(conv, req.query.token)) return res.status(404).json({ message: 'Conversation not found.' });
    if (conv.unreadCustomer) { conv.unreadCustomer = 0; await conv.save(); }
    res.json({ messages: conv.messages, businessName: user.siteName });
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// Visitor: send another message
app.post('/site/:slug/chat/:id/send', chatLimiter, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Not found' });
    const user = await siteBySlug(req.params.slug);
    const conv = user && await Conversation.findOne({ _id: req.params.id, userId: user._id });
    if (!conv || !tokenOk(conv, req.body && req.body.token)) return res.status(404).json({ message: 'Conversation not found.' });
    const text = cleanMsg(req.body && req.body.text);
    if (!text) return res.status(400).json({ message: 'Please write a message.' });
    if (conv.messages.length >= MAX_MSGS) return res.status(400).json({ message: 'This conversation is full. Please call or use another contact.' });
    conv.messages.push({ from: 'customer', text, at: new Date() });
    conv.unreadSeller += 1; conv.lastAt = new Date();
    const mailNow = user.notifyOn !== false && (!conv.sellerMailedAt || Date.now() - new Date(conv.sellerMailedAt).getTime() > MAIL_GAP_MS);
    if (mailNow) conv.sellerMailedAt = new Date();
    await conv.save();
    if (mailNow) {
      sendMail({
        to: user.notifyEmail || user.email,
        subject: `New message from ${conv.customerName}`,
        text: `${conv.customerName} wrote about "${conv.offerTitle}":\n\n${text}\n\nReply: ${PUBLIC_BASE}/dashboard`,
        html: emailShell({
          icon: '&#128172;', preheader: `${esc(conv.customerName)}: ${esc(text.slice(0, 80))}`,
          heading: ['', 'New message'], intro: ['', `${esc(conv.customerName)} wrote again about “${esc(conv.offerTitle)}”.`],
          details: [['', 'Message', text]], buttonText: ['', 'Reply in dashboard'], link: `${PUBLIC_BASE}/dashboard`,
          footnote: ['', 'You get at most one email every 10 minutes per conversation.']
        })
      });
    }
    res.json({ messages: conv.messages });
  } catch (err) { res.status(500).json({ message: 'Could not send your message. Please try again.' }); }
});

// Public offers by id (for the Saved page, which keeps the ids in the visitor's own browser)
app.get('/site/:slug/offers.json', chatLimiter, async (req, res) => {
  try {
    const user = await siteBySlug(req.params.slug);
    if (!user) return res.status(404).json({ offers: [] });
    const ids = String(req.query.ids || '').split(',').filter(mongoose.isValidObjectId).slice(0, 60);
    const offers = await Offer.find({ userId: user._id, _id: { $in: ids } });
    res.json({ offers: offers.map(o => ({ id: o._id, title: o.title, price: o.price, description: o.description, image: galleryOf(o)[0] || null, photos: galleryOf(o).length })) });
  } catch (err) { res.status(500).json({ offers: [] }); }
});

// Business owner: inbox
app.get('/api/conversations', authenticateToken, async (req, res) => {
  const list = await Conversation.find({ userId: req.user.id }).sort({ lastAt: -1 }).limit(100);
  res.json({ conversations: list.map(c => briefConv(c, true)), unread: list.reduce((n, c) => n + (c.unreadSeller || 0), 0) });
});
app.get('/api/conversations/:id', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  const c = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
  if (!c) return res.status(404).json({ message: 'Conversation not found' });
  if (c.unreadSeller) { c.unreadSeller = 0; await c.save(); }
  res.json({ conversation: { ...briefConv(c, true), messages: c.messages } });
});
app.post('/api/conversations/:id/reply', authenticateToken, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
    const c = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: 'Conversation not found' });
    const text = cleanMsg(req.body && req.body.text);
    if (!text) return res.status(400).json({ message: 'Please write a message.' });
    if (c.messages.length >= MAX_MSGS) return res.status(400).json({ message: 'This conversation is full.' });
    c.messages.push({ from: 'seller', text, at: new Date() });
    c.unreadCustomer += 1; c.lastAt = new Date();
    const owner = await User.findById(req.user.id);
    const mailNow = c.customerEmail && (!c.customerMailedAt || Date.now() - new Date(c.customerMailedAt).getTime() > MAIL_GAP_MS);
    if (mailNow) c.customerMailedAt = new Date();
    await c.save();
    if (mailNow && owner) {
      const link = `${PUBLIC_BASE}/site/${owner.slug}/offer/${c.offerId}#chat`;
      sendMail({
        to: c.customerEmail,
        subject: `${owner.siteName} replied to you`,
        text: `${owner.siteName} replied about "${c.offerTitle}":\n\n${text}\n\nOpen the chat: ${link}`,
        html: emailShell({
          icon: '&#128172;', preheader: esc(text.slice(0, 90)),
          heading: ['', 'You have a reply'], intro: ['', `${esc(owner.siteName)} answered your message about “${esc(c.offerTitle)}”.`],
          details: [['', 'Reply', text]], buttonText: ['', 'Open the chat'], link,
          footnote: ['', 'Open the same browser you used before to continue the conversation.']
        })
      });
    }
    res.json({ conversation: { ...briefConv(c, true), messages: c.messages } });
  } catch (err) { res.status(500).json({ message: 'Could not send the reply.' }); }
});
app.delete('/api/conversations/:id', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  await Conversation.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});

// ---------- Public customer site: dark luxury design, neon cards, 3D parallax ----------
const okImg = (u) => /^https:\/\//.test(u || '');
const galleryOf = (o) => {
  const list = (o.images && o.images.length ? o.images : (o.imageUrl ? [o.imageUrl] : [])).filter(okImg);
  return list.slice(0, MAX_GALLERY);
};
const HEART_PATH = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 21s-7.5-4.6-9.6-9.2C.9 8.4 2.7 5 6 5c2 0 3.4 1.1 4 2.2.6-1.1 2-2.2 4-2.2 3.3 0 5.1 3.4 3.6 6.8C19.5 16.4 12 21 12 21z"/></svg>';
const HEART_SMALL = (id) => `<button type="button" class="heart" data-id="${id}" aria-label="Save to favorites" aria-pressed="false">${HEART_PATH}</button>`;
const eur = (n) => `&euro;${Number(n || 0).toFixed(2)}`;

function siteCss(t, f) {
  return `:root{--a:${t.a};--b:${t.b};--ink:${t.ink};--on:${t.on};--bg:#05070b;--panel:#0d121b;--line:rgba(255,255,255,.09);--mute:#8b94a5;--soft:#c3cad6}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:${f.css};background:var(--bg);color:#f1eee8;-webkit-font-smoothing:antialiased;overflow-x:hidden;line-height:1.5}
a{color:inherit}
.bar{position:fixed;top:0;left:0;right:0;z-index:40;display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 28px;color:#fff;background:rgba(5,7,11,.6);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-bottom:1px solid var(--line)}
.bar b{font-size:1.05rem;letter-spacing:-.01em;text-decoration:none}
.bar nav{display:flex;gap:10px}
.bar nav a{text-decoration:none;font-size:.9rem;padding:9px 18px;border-radius:99px;border:1px solid rgba(255,255,255,.2);transition:background .2s,border-color .2s}
.bar nav a:hover{background:rgba(255,255,255,.08);border-color:var(--a)}
.hero{position:relative;min-height:100vh;min-height:100svh;display:flex;align-items:center;justify-content:center;text-align:center;overflow:hidden;padding:120px 24px 90px;perspective:1200px}
.layer{position:absolute;will-change:transform}
.herobg{inset:-8%;background-size:cover;background-position:center;filter:blur(34px) saturate(1.4);opacity:.28}
.blob{border-radius:50%;filter:blur(100px);opacity:.42}
.b1{width:560px;height:560px;background:var(--a);left:-10%;top:-14%}
.b2{width:640px;height:640px;background:var(--b);right:-14%;bottom:-22%}
.gridbg{inset:-10% 0 0;background-image:linear-gradient(rgba(255,255,255,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px);background-size:56px 56px;-webkit-mask-image:radial-gradient(ellipse at center,#000 22%,transparent 72%);mask-image:radial-gradient(ellipse at center,#000 22%,transparent 72%)}
.ring{width:min(82vw,760px);aspect-ratio:1;border:1px solid rgba(255,255,255,.12);border-radius:50%;animation:spin 46s linear infinite}
.ring::after{content:'';position:absolute;top:-6px;left:50%;width:12px;height:12px;border-radius:50%;background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 28px var(--a)}
.ring.r2{width:min(56vw,520px);animation-direction:reverse;animation-duration:28s}
.hero-in{position:relative;z-index:2;max-width:920px;transform-style:preserve-3d;transition:transform .15s ease-out}
.chip{display:inline-block;border:1px solid rgba(255,255,255,.22);border-radius:99px;padding:8px 18px;font-size:.86rem;margin-bottom:28px;background:rgba(255,255,255,.06);backdrop-filter:blur(8px);animation:rise .8s both}
h1{font-size:clamp(2.7rem,9vw,7rem);line-height:1.02;letter-spacing:-.035em;background:linear-gradient(100deg,#fff 15%,var(--a) 50%,var(--b) 80%,#fff);background-size:220% auto;-webkit-background-clip:text;background-clip:text;color:transparent;animation:rise .9s .1s both,shine 9s linear infinite;padding-bottom:.08em}
.lead{color:var(--soft);font-size:clamp(1rem,1.7vw,1.25rem);margin:22px auto 0;max-width:46ch;animation:rise .9s .25s both}
.cta{display:inline-block;margin-top:38px;background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);text-decoration:none;font-weight:700;padding:16px 34px;border-radius:99px;box-shadow:0 0 40px color-mix(in srgb,var(--a) 45%,transparent);transition:transform .2s;animation:rise .9s .4s both}
.cta:hover{transform:translateY(-3px) scale(1.03)}
.scroll{position:absolute;bottom:26px;left:50%;transform:translateX(-50%);width:22px;height:36px;border:2px solid rgba(255,255,255,.4);border-radius:12px}
.scroll::after{content:'';position:absolute;left:50%;top:7px;width:3px;height:7px;margin-left:-1.5px;border-radius:2px;background:#fff;animation:wheel 1.8s ease-in-out infinite}
.strip{background:#080b11;overflow:hidden;border-block:1px solid var(--line);padding:20px 0}
.strip div{display:flex;gap:56px;width:max-content;animation:slide 40s linear infinite}
.strip span{font-size:1.5rem;font-weight:700;letter-spacing:-.02em;white-space:nowrap;display:flex;align-items:center;gap:56px;color:#dfe3ea}
.strip span::after{content:'';width:10px;height:10px;border-radius:50%;background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 14px var(--a)}
.wrap{max-width:1180px;margin:0 auto;padding:110px 24px 60px}
.wrap h2{font-size:clamp(2rem,5vw,3.6rem);letter-spacing:-.03em;margin-bottom:12px}
.sub{color:var(--mute);margin-bottom:56px;max-width:52ch}
.ok{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.4);color:#86efac;padding:16px 20px;border-radius:14px;margin-bottom:28px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:26px;perspective:1400px}
/* neon card: gradient edge, glow that follows the cursor, 3D tilt */
.card{position:relative;display:flex;flex-direction:column;text-decoration:none;background:var(--panel);border-radius:22px;overflow:hidden;transform-style:preserve-3d;transition:transform .25s cubic-bezier(.2,.8,.2,1),box-shadow .35s;box-shadow:0 0 0 1px var(--line),0 18px 50px rgba(0,0,0,.45);will-change:transform}
.card::before{content:'';position:absolute;inset:0;border-radius:inherit;padding:1.5px;background:linear-gradient(135deg,var(--a),transparent 40%,transparent 60%,var(--b));-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;opacity:.55;transition:opacity .3s;pointer-events:none;z-index:3}
.card::after{content:'';position:absolute;inset:0;background:radial-gradient(420px circle at var(--mx,50%) var(--my,0%),color-mix(in srgb,var(--a) 22%,transparent),transparent 60%);opacity:0;transition:opacity .3s;pointer-events:none;z-index:2}
.card:hover{box-shadow:0 0 0 1px color-mix(in srgb,var(--a) 50%,transparent),0 0 46px color-mix(in srgb,var(--a) 30%,transparent),0 30px 70px rgba(0,0,0,.6)}
.card:hover::before{opacity:1}.card:hover::after{opacity:1}
.pic{position:relative;aspect-ratio:4/3;overflow:hidden;background:#111722}
.pic img{width:100%;height:100%;object-fit:cover;transition:transform .8s cubic-bezier(.2,.8,.2,1)}
.card:hover .pic img{transform:scale(1.09)}
.ph{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:4rem;font-weight:800;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b))}
.tag{position:absolute;right:14px;top:14px;z-index:4;background:rgba(5,7,11,.78);color:#fff;backdrop-filter:blur(10px);padding:8px 14px;border-radius:99px;font-weight:700;font-size:.95rem;border:1px solid color-mix(in srgb,var(--a) 55%,transparent);box-shadow:0 0 18px color-mix(in srgb,var(--a) 35%,transparent)}
.count{position:absolute;left:14px;top:14px;z-index:4;background:rgba(5,7,11,.7);backdrop-filter:blur(10px);padding:6px 11px;border-radius:99px;font-size:.78rem;border:1px solid var(--line)}
.in{padding:22px;display:flex;flex-direction:column;flex:1;transform:translateZ(30px)}
.in h3{font-size:1.2rem;letter-spacing:-.01em;margin-bottom:8px}
.in p{color:var(--mute);font-size:.94rem;line-height:1.55;margin-bottom:18px;flex:1}
.more{font-weight:700;color:var(--a);display:flex;align-items:center;gap:8px}
.more::after{content:'\\2192';transition:transform .25s}
.card:hover .more::after{transform:translateX(6px)}
.none{color:var(--mute);padding:30px 0}
.glass{background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.02));border:1px solid var(--line);border-radius:22px;padding:30px;backdrop-filter:blur(10px)}
.about{display:grid;grid-template-columns:1fr 1fr;gap:26px}
.about h3{font-size:1.5rem;letter-spacing:-.02em;margin-bottom:4px}
.about .cat{color:var(--mute);margin-bottom:20px}
.row{display:flex;gap:14px;padding:13px 0;border-top:1px solid var(--line)}
.row small{width:96px;flex-shrink:0;color:var(--mute);font-size:.82rem;text-transform:uppercase;letter-spacing:.06em;padding-top:2px}
.row div,.row a{color:#f1eee8;white-space:pre-line}
.row a{text-decoration:none;border-bottom:1px solid color-mix(in srgb,var(--a) 60%,transparent)}
.map{border-radius:18px;overflow:hidden;border:1px solid var(--line);min-height:300px;background:#0a0e15}
.map iframe{width:100%;height:100%;min-height:300px;border:0;display:block;filter:invert(.92) hue-rotate(180deg) saturate(.8)}
.mapbtn{display:inline-block;margin-top:12px;font-size:.9rem;color:var(--a);text-decoration:none}
/* offer page */
.crumb{display:inline-flex;align-items:center;gap:8px;color:var(--soft);text-decoration:none;font-size:.92rem;margin-bottom:26px}
.crumb:hover{color:var(--a)}
.detail{display:grid;grid-template-columns:1.15fr 1fr;gap:44px;align-items:start}
.gal{position:sticky;top:90px;perspective:1200px}
.main{position:relative;aspect-ratio:4/3;border-radius:24px;overflow:hidden;background:#111722;box-shadow:0 0 0 1px var(--line),0 0 60px color-mix(in srgb,var(--a) 22%,transparent),0 30px 80px rgba(0,0,0,.6);transition:transform .2s ease-out;transform-style:preserve-3d}
.main img{width:100%;height:100%;object-fit:cover;display:block;cursor:zoom-in}
.main .ph{font-size:7rem}
.nav{position:absolute;top:50%;transform:translateY(-50%);width:44px;height:44px;border-radius:50%;border:1px solid var(--line);background:rgba(5,7,11,.7);color:#fff;font-size:1.3rem;cursor:pointer;backdrop-filter:blur(8px);z-index:5}
.nav:hover{border-color:var(--a)}
.nav.p{left:14px}.nav.n{right:14px}
.thumbs{display:flex;gap:10px;margin-top:14px;overflow-x:auto;padding:4px}
.thumbs button{flex:0 0 84px;height:64px;border-radius:12px;overflow:hidden;border:2px solid transparent;background:#111722;padding:0;cursor:pointer;opacity:.6;transition:opacity .2s,border-color .2s}
.thumbs button.on{border-color:var(--a);opacity:1;box-shadow:0 0 16px color-mix(in srgb,var(--a) 45%,transparent)}
.thumbs img{width:100%;height:100%;object-fit:cover;display:block}
.info h1{font-size:clamp(2rem,4.5vw,3.4rem);animation:none;margin-bottom:14px;line-height:1.08}
.price{display:inline-block;font-size:1.5rem;font-weight:800;padding:8px 20px;border-radius:99px;margin-bottom:20px;background:rgba(5,7,11,.8);border:1px solid color-mix(in srgb,var(--a) 60%,transparent);box-shadow:0 0 28px color-mix(in srgb,var(--a) 35%,transparent)}
.short{color:var(--soft);font-size:1.08rem;margin-bottom:18px}
.long{color:var(--mute);white-space:pre-line;margin-bottom:28px}
.req h2{font-size:1.3rem;margin-bottom:14px;letter-spacing:-.01em}
.req form{display:grid;gap:10px}
input{width:100%;padding:14px;border:1px solid rgba(255,255,255,.14);border-radius:12px;font-family:inherit;font-size:.95rem;background:rgba(255,255,255,.04);color:#fff}
input::placeholder{color:#6f7889}
input:focus{outline:2px solid var(--a);border-color:transparent}
.btn{border:0;border-radius:14px;padding:15px;font-weight:700;font-family:inherit;font-size:1rem;cursor:pointer;background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);box-shadow:0 0 30px color-mix(in srgb,var(--a) 35%,transparent);transition:transform .2s}
.btn:hover{transform:translateY(-2px)}
.consent{display:flex;gap:10px;align-items:flex-start;font-size:.8rem;color:var(--mute);line-height:1.4}
.consent input{width:auto;margin:2px 0 0;flex-shrink:0}
.consent a{color:var(--a)}
.lb{position:fixed;inset:0;z-index:60;background:rgba(0,0,0,.92);display:none;align-items:center;justify-content:center;padding:24px}
.lb.open{display:flex}.lb img{max-width:100%;max-height:100%;border-radius:12px}
footer{border-top:1px solid var(--line);color:var(--mute);text-align:center;padding:48px 20px;font-size:.88rem;margin-top:60px}
footer b{display:block;color:#fff;font-size:1.2rem;margin-bottom:6px}
.rv{opacity:0;transform:translateY(34px);transition:opacity .8s var(--d,0ms),transform .8s var(--d,0ms)}
.rv.in-view{opacity:1;transform:none}
body::after{content:'';position:fixed;inset:0;z-index:100;pointer-events:none;opacity:.05;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.9' numOctaves='2'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E")}
.prog{position:fixed;top:0;left:0;right:0;height:3px;z-index:50;background:linear-gradient(90deg,var(--a),var(--b));transform-origin:left;transform:scaleX(0);box-shadow:0 0 12px var(--a)}
.spot{position:absolute;inset:0;pointer-events:none;z-index:1}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:20px;margin-top:10px}
.step{position:relative;padding:28px;border-radius:20px;background:linear-gradient(180deg,rgba(255,255,255,.05),rgba(255,255,255,.015));border:1px solid var(--line)}
.step i{font-style:normal;display:inline-flex;width:40px;height:40px;border-radius:12px;align-items:center;justify-content:center;font-weight:800;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 22px color-mix(in srgb,var(--a) 40%,transparent);margin-bottom:16px}
.step h3{font-size:1.1rem;margin-bottom:6px}.step p{color:var(--mute);font-size:.92rem}
.fab{position:fixed;right:20px;bottom:20px;z-index:45;display:flex;align-items:center;gap:8px;text-decoration:none;font-weight:700;padding:14px 20px;border-radius:99px;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 34px color-mix(in srgb,var(--a) 45%,transparent),0 10px 30px rgba(0,0,0,.5)}
.lbl{font-size:.85rem;color:var(--soft);margin-top:4px}
.crow{display:flex;gap:8px;margin-bottom:8px}
.crow select{flex:0 0 132px;padding:14px 10px;border:1px solid rgba(255,255,255,.14);border-radius:12px;font-family:inherit;font-size:.92rem;background:#111722;color:#fff}
.crow input{flex:1;min-width:0}
.cx{flex:0 0 44px;border:1px solid rgba(255,255,255,.14);border-radius:12px;background:transparent;color:#fff;font-size:1.2rem;cursor:pointer}
.addc{background:none;border:1px dashed color-mix(in srgb,var(--a) 55%,transparent);color:var(--a);border-radius:12px;padding:11px;font-family:inherit;font-weight:600;cursor:pointer}
.addc:hover{background:color-mix(in srgb,var(--a) 10%,transparent)}
.share{display:inline-flex;align-items:center;gap:8px;margin:0 0 22px;padding:10px 18px;border-radius:99px;border:1px solid rgba(255,255,255,.2);background:transparent;color:#fff;font-family:inherit;font-size:.9rem;cursor:pointer}
.share:hover{border-color:var(--a)}
.stick{display:none}
@media (max-width:860px){.steps{grid-template-columns:1fr}.stick{position:fixed;left:0;right:0;bottom:0;z-index:45;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px calc(12px + env(safe-area-inset-bottom));background:rgba(5,7,11,.88);backdrop-filter:blur(16px);border-top:1px solid var(--line)}.stick b{font-size:1.15rem}.stick a{text-decoration:none;font-weight:700;padding:12px 24px;border-radius:99px;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b))}.fab{bottom:78px}footer{padding-bottom:90px}}
.heart{position:absolute;right:14px;bottom:14px;z-index:6;width:42px;height:42px;border-radius:50%;border:1px solid rgba(255,255,255,.25);background:rgba(5,7,11,.7);backdrop-filter:blur(10px);color:#fff;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:transform .2s,background .2s,border-color .2s}
.heart svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2}
.heart:hover{transform:scale(1.12);border-color:#ff5d8f}
.heart.on{background:#ff3d7f;border-color:#ff3d7f;box-shadow:0 0 22px rgba(255,61,127,.6)}.heart.on svg{fill:#fff;stroke:#fff}
.heart.lg{position:static;width:auto;height:auto;border-radius:99px;padding:10px 18px;gap:8px;display:inline-flex;font-family:inherit;font-size:.9rem;margin:0 8px 22px 0}
.heart.lg .t::before{content:'Save'}.heart.lg.on .t::before{content:'Saved'}
.favlink{display:inline-flex;gap:6px;align-items:center}
.chat h2{font-size:1.3rem;margin-bottom:4px}.chat .hint{color:var(--mute);font-size:.88rem;margin-bottom:14px}
.chat form{display:grid;gap:10px}
.chat textarea,.req textarea{width:100%;padding:14px;border:1px solid rgba(255,255,255,.14);border-radius:12px;font-family:inherit;font-size:.95rem;background:rgba(255,255,255,.04);color:#fff;resize:vertical;min-height:84px}
.chat textarea:focus,.req textarea:focus{outline:2px solid var(--a);border-color:transparent}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chips button{border:1px solid rgba(255,255,255,.18);background:transparent;color:var(--soft);border-radius:99px;padding:7px 13px;font-family:inherit;font-size:.82rem;cursor:pointer}
.chips button:hover{border-color:var(--a);color:#fff}
.msgs{height:340px;overflow-y:auto;display:flex;flex-direction:column;gap:10px;padding:6px 2px 10px;margin-bottom:10px;scroll-behavior:smooth}
.bub{max-width:82%;padding:10px 14px;border-radius:16px;font-size:.95rem;white-space:pre-wrap;word-break:break-word}
.bub small{display:block;margin-top:4px;font-size:.7rem;opacity:.65}
.bub.me{align-self:flex-end;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b));border-bottom-right-radius:4px}
.bub.them{align-self:flex-start;background:rgba(255,255,255,.08);border:1px solid var(--line);border-bottom-left-radius:4px}
.chat .sendrow{display:flex;gap:8px;align-items:flex-end}.sendrow textarea{min-height:48px;height:48px}
.sendrow .btn{padding:13px 20px}
.callbtn{display:inline-block;margin-top:10px;font-size:.88rem;color:var(--a);text-decoration:none}
.msgrow{display:flex;justify-content:space-between;gap:14px;align-items:center;text-decoration:none;padding:16px 18px;border-radius:16px;border:1px solid var(--line);background:rgba(255,255,255,.03);margin-bottom:10px}
.msgrow:hover{border-color:var(--a)}.msgrow b{display:block}.msgrow span{color:var(--mute);font-size:.88rem}
.newdot{background:#ff3d7f;color:#fff;border-radius:99px;font-size:.75rem;padding:3px 9px;font-weight:700}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shine{to{background-position:220% center}}
@keyframes rise{from{opacity:0;transform:translateY(26px)}to{opacity:1;transform:none}}
@keyframes wheel{0%{opacity:0;transform:translateY(0)}30%{opacity:1}100%{opacity:0;transform:translateY(12px)}}
@keyframes slide{to{transform:translateX(-50%)}}
@media (max-width:860px){.detail,.about{grid-template-columns:1fr}.gal{position:static}.bar{padding:12px 16px}.wrap{padding:90px 18px 40px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}.rv{opacity:1;transform:none}}`;
}

// One script for both pages: reveal on scroll, scroll + pointer parallax, card tilt and glow, gallery, lightbox
const SITE_JS = `(function(){
  var fine=matchMedia('(pointer:fine)').matches, calm=matchMedia('(prefers-reduced-motion:reduce)').matches;
  var els=document.querySelectorAll('.rv');
  if('IntersectionObserver' in window){var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('in-view');io.unobserve(e.target)}})},{threshold:.12});els.forEach(function(e){io.observe(e)})}else els.forEach(function(e){e.classList.add('in-view')});
  var layers=[].slice.call(document.querySelectorAll('[data-depth]'));
  if(layers.length&&!calm){var tick=false;function par(){tick=false;var y=scrollY;layers.forEach(function(l){var d=parseFloat(l.dataset.depth);l.style.transform='translate3d(0,'+(y*d)+'px,0)'})}
    addEventListener('scroll',function(){if(!tick){tick=true;requestAnimationFrame(par)}},{passive:true});par()}
  var hero=document.querySelector('.hero'),hin=document.querySelector('.hero-in');
  if(hero&&hin&&fine&&!calm){hero.addEventListener('pointermove',function(e){var x=e.clientX/innerWidth-.5,y=e.clientY/innerHeight-.5;hin.style.transform='rotateY('+(x*7)+'deg) rotateX('+(-y*7)+'deg)'});hero.addEventListener('pointerleave',function(){hin.style.transform=''})}
  function tiltAll(){if(!(fine&&!calm))return;document.querySelectorAll('.card:not([data-t])').forEach(function(c){c.setAttribute('data-t','1');
    c.addEventListener('pointermove',function(e){var r=c.getBoundingClientRect(),x=(e.clientX-r.left)/r.width,y=(e.clientY-r.top)/r.height;c.style.setProperty('--mx',(x*100)+'%');c.style.setProperty('--my',(y*100)+'%');c.style.transform='perspective(900px) rotateY('+((x-.5)*9)+'deg) rotateX('+((.5-y)*9)+'deg) translateY(-6px)'});
    c.addEventListener('pointerleave',function(){c.style.transform=''})})}
  tiltAll();
  var pg=document.getElementById('prog');
  if(pg){addEventListener('scroll',function(){var h=document.documentElement.scrollHeight-innerHeight;pg.style.transform='scaleX('+(h>0?scrollY/h:0)+')'},{passive:true})}
  var sp=document.querySelector('.spot');
  if(hero&&sp&&fine&&!calm){hero.addEventListener('pointermove',function(e){var r=hero.getBoundingClientRect();sp.style.background='radial-gradient(520px circle at '+(e.clientX-r.left)+'px '+(e.clientY-r.top)+'px,rgba(255,255,255,.07),transparent 60%)'})}
  var sh=document.getElementById('shareBtn');
  if(sh)sh.addEventListener('click',function(){var d={title:document.title,url:location.href.split('#')[0]};if(navigator.share){navigator.share(d).catch(function(){})}else if(navigator.clipboard){navigator.clipboard.writeText(d.url);sh.textContent='Link copied'}});
  var ph={phone:'e.g. +359 88 123 4567',email:'name@example.com',instagram:'@username or profile link',facebook:'Profile name or link',x:'@username or profile link',tiktok:'@username',telegram:'@username or phone',whatsapp:'WhatsApp number',viber:'Viber number',other:'Type your contact details'};
  var cbox=document.getElementById('contacts');
  if(cbox){
    var bind=function(row){var s=row.querySelector('select'),i=row.querySelector('input');s.addEventListener('change',function(){i.placeholder=ph[s.value]||'';i.type=s.value==='email'?'email':'text'})};
    bind(cbox.firstElementChild);
    var addB=document.getElementById('addContact');
    addB.addEventListener('click',function(){
      if(cbox.children.length>=5)return;
      var row=cbox.firstElementChild.cloneNode(true),s=row.querySelector('select'),i=row.querySelector('input');
      s.value='instagram';i.value='';i.required=false;i.type='text';i.placeholder=ph.instagram;
      var x=document.createElement('button');x.type='button';x.className='cx';x.textContent='\u00d7';x.title='Remove';
      x.onclick=function(){row.remove();addB.style.display=''};row.appendChild(x);
      cbox.appendChild(row);bind(row);i.focus();
      if(cbox.children.length>=5)addB.style.display='none';
    });
  }
  var slug=document.body.getAttribute('data-slug')||'';
  function favs(){try{return JSON.parse(localStorage.getItem('fav:'+slug)||'[]')}catch(e){return[]}}
  function paintFavs(){var a=favs();document.querySelectorAll('.heart').forEach(function(h){var on=a.indexOf(h.dataset.id)>-1;h.classList.toggle('on',on);h.setAttribute('aria-pressed',on)});var c=document.getElementById('favCount');if(c)c.textContent=a.length?'('+a.length+')':''}
  document.addEventListener('click',function(e){var h=e.target.closest&&e.target.closest('.heart');if(!h)return;e.preventDefault();e.stopPropagation();var a=favs(),i=a.indexOf(h.dataset.id);if(i>-1)a.splice(i,1);else a.unshift(h.dataset.id);try{localStorage.setItem('fav:'+slug,JSON.stringify(a.slice(0,100)))}catch(x){}paintFavs();
    var fl=document.getElementById('favList');if(fl&&i>-1){var card=h.closest('.card');if(card)card.remove();if(!fl.children.length)fl.innerHTML='<p class="none">No saved offers yet. Tap the heart on any offer to save it here.</p>'}});
  function mk(t,c,x){var n=document.createElement(t);if(c)n.className=c;if(x!=null)n.textContent=x;return n}
  var fl=document.getElementById('favList');
  if(fl){var ids=favs();
    if(!ids.length){fl.innerHTML='<p class="none">No saved offers yet. Tap the heart on any offer to save it here.</p>'}
    else fetch('/site/'+slug+'/offers.json?ids='+ids.join(',')).then(function(r){return r.json()}).then(function(d){fl.textContent='';
      var by={};(d.offers||[]).forEach(function(o){by[o.id]=o});var shown=0;
      ids.forEach(function(id){var o=by[id];if(!o)return;shown++;
        var a=mk('a','card rv in-view');a.href='/site/'+slug+'/offer/'+o.id;
        var pic=mk('div','pic');if(o.image){var im=mk('img');im.src=o.image;im.alt=o.title;im.loading='lazy';pic.appendChild(im)}else pic.appendChild(mk('div','ph',String(o.title||'?').charAt(0).toUpperCase()));
        pic.appendChild(mk('span','tag','\u20ac'+Number(o.price||0).toFixed(2)));
        var hb=mk('button','heart');hb.type='button';hb.dataset.id=o.id;hb.setAttribute('aria-label','Remove from favorites');hb.innerHTML='<svg viewBox="0 0 24 24"><path d="M12 21s-7.5-4.6-9.6-9.2C.9 8.4 2.7 5 6 5c2 0 3.4 1.1 4 2.2.6-1.1 2-2.2 4-2.2 3.3 0 5.1 3.4 3.6 6.8C19.5 16.4 12 21 12 21z"/></svg>';pic.appendChild(hb);
        a.appendChild(pic);var inn=mk('div','in');inn.appendChild(mk('h3',null,o.title));inn.appendChild(mk('p',null,o.description||''));inn.appendChild(mk('span','more','View details'));a.appendChild(inn);fl.appendChild(a)});
      if(!shown)fl.innerHTML='<p class="none">Those offers are no longer available.</p>';paintFavs();tiltAll()}).catch(function(){fl.innerHTML='<p class="none">Could not load your saved offers. Please refresh.</p>'})}
  var cl=document.getElementById('chatList');
  if(cl){var saved=[];try{saved=JSON.parse(localStorage.getItem('chats:'+slug)||'[]')}catch(e){}
    if(!saved.length){cl.innerHTML='<p class="none">No conversations yet. Open an offer and use the chat box to write to the business.</p>'}
    else fetch('/site/'+slug+'/chat/list',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chats:saved})}).then(function(r){return r.json()}).then(function(d){cl.textContent='';var list=d.conversations||[];
      if(!list.length){cl.innerHTML='<p class="none">No conversations yet.</p>';return}
      list.forEach(function(c){var a=mk('a','msgrow');a.href='/site/'+slug+'/offer/'+c.offerId+'#chat';var l=mk('div');l.appendChild(mk('b',null,c.offerTitle));l.appendChild(mk('span',null,c.last?(c.last.from==='seller'?'Business: ':'You: ')+String(c.last.text).slice(0,90):''));a.appendChild(l);if(c.unread)a.appendChild(mk('span','newdot',c.unread+' new'));cl.appendChild(a)})}).catch(function(){})}
  paintFavs();
  var cw=document.getElementById('chat');
  if(cw){
    var offerId=cw.dataset.offer,ckey='chats:'+slug,startF=document.getElementById('chatStart'),thread=document.getElementById('chatThread'),box=document.getElementById('chatMsgs'),cerr=document.getElementById('chErr');
    function chats(){try{return JSON.parse(localStorage.getItem(ckey)||'[]')}catch(e){return[]}}
    function putChats(a){try{localStorage.setItem(ckey,JSON.stringify(a.slice(0,20)))}catch(e){}}
    var mine=chats().filter(function(x){return x.offerId===offerId})[0],count=-1,timer=null;
    function bubble(m){var d=mk('div','bub '+(m.from==='customer'?'me':'them'));d.appendChild(mk('div',null,m.text));d.appendChild(mk('small',null,new Date(m.at).toLocaleString('en-GB',{day:'numeric',month:'short',hour:'2-digit',minute:'2-digit'})));return d}
    function draw(msgs){var stick=count<0||box.scrollHeight-box.scrollTop-box.clientHeight<90;box.textContent='';msgs.forEach(function(m){box.appendChild(bubble(m))});count=msgs.length;if(stick)box.scrollTop=box.scrollHeight}
    function pull(){fetch('/site/'+slug+'/chat/'+mine.id+'?token='+encodeURIComponent(mine.token)).then(function(r){if(r.status===404){forget();return null}return r.json()}).then(function(d){if(d&&d.messages&&d.messages.length!==count)draw(d.messages)}).catch(function(){})}
    function forget(){clearInterval(timer);putChats(chats().filter(function(x){return x.offerId!==offerId}));mine=null;count=-1;thread.style.display='none';startF.style.display='grid'}
    function openThread(){startF.style.display='none';thread.style.display='block';pull();clearInterval(timer);timer=setInterval(function(){if(!document.hidden)pull()},4000)}
    if(mine)openThread();
    startF.querySelectorAll('.chips button').forEach(function(b){b.addEventListener('click',function(){document.getElementById('chText').value=b.textContent})});
    startF.addEventListener('submit',function(e){e.preventDefault();cerr.textContent='';var btn=startF.querySelector('.btn');btn.disabled=true;
      fetch('/site/'+slug+'/chat/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({offerId:offerId,name:document.getElementById('chName').value,email:document.getElementById('chEmail').value,text:document.getElementById('chText').value})})
      .then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d}})}).then(function(x){btn.disabled=false;if(!x.ok){cerr.textContent=x.d.message||'Could not send.';return}
        mine={offerId:offerId,id:x.d.id,token:x.d.token};putChats([mine].concat(chats().filter(function(c){return c.offerId!==offerId})));openThread()}).catch(function(){btn.disabled=false;cerr.textContent='Connection problem. Please try again.'})});
    var sf=document.getElementById('chatSend'),ta=document.getElementById('chReply');
    ta.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sf.requestSubmit()}});
    sf.addEventListener('submit',function(e){e.preventDefault();var t=ta.value.trim();if(!t||!mine)return;ta.value='';
      fetch('/site/'+slug+'/chat/'+mine.id+'/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:mine.token,text:t})}).then(function(r){return r.json().then(function(d){return{ok:r.ok,d:d}})}).then(function(x){if(x.ok&&x.d.messages)draw(x.d.messages);else{ta.value=t;alert(x.d.message||'Could not send.')}}).catch(function(){ta.value=t})});
    if(location.hash==='#chat')cw.scrollIntoView({behavior:'smooth',block:'center'});
  }
  var main=document.getElementById('mainPic');
  if(main){
    var imgs=JSON.parse(main.getAttribute('data-imgs')||'[]'),i=0,mi=document.getElementById('mainImg'),th=[].slice.call(document.querySelectorAll('.thumbs button'));
    function show(n){if(!imgs.length)return;i=(n+imgs.length)%imgs.length;mi.src=imgs[i];th.forEach(function(b,k){b.classList.toggle('on',k===i)})}
    th.forEach(function(b,k){b.addEventListener('click',function(){show(k)})});
    var p=document.getElementById('prev'),n=document.getElementById('next');if(p)p.onclick=function(){show(i-1)};if(n)n.onclick=function(){show(i+1)};
    if(fine&&!calm){main.addEventListener('pointermove',function(e){var r=main.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;main.style.transform='rotateY('+(x*8)+'deg) rotateX('+(-y*8)+'deg)'});main.addEventListener('pointerleave',function(){main.style.transform=''})}
    var lb=document.getElementById('lb'),lbi=document.getElementById('lbImg');
    if(mi&&lb){mi.addEventListener('click',function(){lbi.src=imgs[i];lb.classList.add('open')});lb.addEventListener('click',function(){lb.classList.remove('open')})}
    addEventListener('keydown',function(e){if(e.key==='ArrowLeft')show(i-1);else if(e.key==='ArrowRight')show(i+1);else if(e.key==='Escape'&&lb)lb.classList.remove('open')});
  }
})();`;

function pageShell(user, { title, desc, body }) {
  const t = THEMES[user.theme] || THEMES.gold;
  const f = FONTS[user.font] || FONTS.sans;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta name="theme-color" content="#05070b">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=${f.gf}&display=swap" rel="stylesheet">
<style>${siteCss(t, f)}</style></head><body data-slug="${esc(user.slug)}">
${body}
<script>${SITE_JS}</script>
</body></html>`;
}

const mapQuery = (user) => [user.address, user.city].filter(Boolean).join(', ');

// Company details + map, shown on the main page and under every offer
function aboutBlock(user) {
  const q = mapQuery(user);
  const phone = String(user.phone || '').trim();
  const rows = [
    user.address || user.city ? `<div class="row"><small>Location</small><div>${esc([user.address, user.city].filter(Boolean).join(', '))}</div></div>` : '',
    phone ? `<div class="row"><small>Phone</small><a href="tel:${esc(phone.replace(/[^\d+]/g, ''))}">${esc(phone)}</a></div>` : '',
    user.hours ? `<div class="row"><small>Open</small><div>${esc(user.hours)}</div></div>` : '',
    user.facebook ? `<div class="row"><small>Facebook</small><a href="${esc(user.facebook)}" target="_blank" rel="noopener">${esc(user.facebook.replace(/^https?:\/\/(www\.)?/, ''))}</a></div>` : '',
    user.instagram ? `<div class="row"><small>Instagram</small><a href="${esc(user.instagram)}" target="_blank" rel="noopener">${esc(user.instagram.replace(/^https?:\/\/(www\.)?/, ''))}</a></div>` : ''
  ].join('');
  const cat = [user.categoryLabel || user.category, user.city].filter(Boolean).map(esc).join(' &middot; ');
  return `<section class="about rv" id="about">
<div class="glass"><h3>${esc(user.siteName)}</h3><div class="cat">${cat}</div>${rows || '<div class="row"><small>Info</small><div>Contact details will appear here soon.</div></div>'}</div>
${q ? `<div><div class="map"><iframe title="Map" loading="lazy" referrerpolicy="no-referrer-when-downgrade" src="https://www.google.com/maps?q=${encodeURIComponent(q)}&output=embed"></iframe></div><a class="mapbtn" href="https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}" target="_blank" rel="noopener">Open in Google Maps &rarr;</a></div>` : ''}
</section>`;
}

function offerCard(user, o, i) {
  const g = galleryOf(o);
  return `<a class="card rv" style="--d:${(i % 6) * 70}ms" href="/site/${esc(user.slug)}/offer/${o._id}">
  <div class="pic">${g.length ? `<img src="${esc(g[0])}" alt="${esc(o.title)}" loading="lazy">` : `<div class="ph">${esc(String(o.title || '?').charAt(0).toUpperCase())}</div>`}
    <span class="tag">${eur(o.price)}</span>${HEART_SMALL(o._id)}${g.length > 1 ? `<span class="count">${g.length} photos</span>` : ''}</div>
  <div class="in"><h3>${esc(o.title)}</h3><p>${esc(o.description)}</p><span class="more">View details</span></div>
</a>`;
}

function renderSite(user, offers, sent) {
  const first = offers.map(galleryOf).find(g => g.length);
  const heroBg = first ? `<div class="layer herobg" data-depth=".15" style="background-image:url('${esc(encodeURI(first[0]))}')"></div>` : '';
  const names = offers.map(o => `<span>${esc(o.title)}</span>`).join('');
  const meta = [user.category, user.city].filter(Boolean).map(esc).join(' &middot; ');
  const cards = offers.length === 0 ? '<p class="none">No offers yet. Please check back soon.</p>' : offers.map((o, i) => offerCard(user, o, i)).join('');
  const phoneRaw = String(user.phone || '').replace(/[^\d+]/g, '');
  const body = `<div class="prog" id="prog"></div><header class="bar"><b>${esc(user.siteName)}</b><nav><a href="#offers">Offers</a><a href="#about">About</a><a class="favlink" href="/site/${esc(user.slug)}/favorites">&#9825; Saved <span id="favCount"></span></a></nav></header>
<section class="hero"><div class="spot"></div>${heroBg}<div class="layer blob b1" data-depth=".3"></div><div class="layer blob b2" data-depth="-.12"></div><div class="layer gridbg" data-depth=".22"></div><div class="layer ring" data-depth=".08"></div><div class="layer ring r2" data-depth=".12"></div>
<div class="hero-in">
${meta ? `<div class="chip">${meta}</div>` : ''}
<h1>${esc(user.siteName)}</h1>
<p class="lead">Browse our offers, open any of them for photos and details, and send a request in seconds.</p>
<a class="cta" href="#offers">See what we offer</a></div><div class="scroll" aria-hidden="true"></div></section>
${offers.length ? `<div class="strip" aria-hidden="true"><div>${names}${names}${names}${names}</div></div>` : ''}
<main class="wrap" id="offers">
<h2 class="rv">Our offers</h2><p class="sub rv">Pick what you need and open it for the full details. No account needed.</p>
${sent ? '<div class="ok">Thank you. Your request was sent and the business will contact you.</div>' : ''}
<div class="grid">${cards}</div></main>
<section class="wrap" id="how" style="padding-bottom:20px"><h2 class="rv">How it works</h2><p class="sub rv">Three quick steps. No account, no waiting.</p>
<div class="steps"><div class="step rv"><i>1</i><h3>Choose an offer</h3><p>Open any offer to see photos, the full description and the price.</p></div><div class="step rv" style="--d:80ms"><i>2</i><h3>Send a request</h3><p>Leave your name and the contact you prefer: phone, Instagram, Facebook, email or anything else.</p></div><div class="step rv" style="--d:160ms"><i>3</i><h3>Get a reply</h3><p>${esc(user.siteName)} contacts you directly to confirm the details.</p></div></div></section>
<div class="wrap" style="padding-top:20px">${aboutBlock(user)}</div>
${phoneRaw ? `<a class="fab" href="tel:${esc(phoneRaw)}">&#9742; Call us</a>` : ''}
<footer><b>${esc(user.siteName)}</b>${meta}<div style="margin-top:18px">Built with GoldOffer Studio</div></footer>`;
  return pageShell(user, { title: user.siteName, desc: `${user.siteName} - ${user.category || ''} in ${user.city || ''}`, body });
}

function renderOfferPage(user, offer, others, sent) {
  const g = galleryOf(offer);
  const thumbs = g.length > 1 ? `<div class="thumbs">${g.map((u, i) => `<button type="button" class="${i === 0 ? 'on' : ''}" aria-label="Photo ${i + 1}"><img src="${esc(u)}" alt="" loading="lazy"></button>`).join('')}</div>` : '';
  const main = g.length
    ? `<div class="main" id="mainPic" data-imgs="${esc(JSON.stringify(g))}"><img id="mainImg" src="${esc(g[0])}" alt="${esc(offer.title)}">${g.length > 1 ? '<button class="nav p" id="prev" aria-label="Previous photo">&#8249;</button><button class="nav n" id="next" aria-label="Next photo">&#8250;</button>' : ''}</div>${thumbs}`
    : `<div class="main"><div class="ph">${esc(String(offer.title || '?').charAt(0).toUpperCase())}</div></div>`;
  const more = others.length ? `<h2 class="rv" style="font-size:1.8rem;margin:70px 0 26px">More from ${esc(user.siteName)}</h2><div class="grid">${others.map((o, i) => offerCard(user, o, i)).join('')}</div>` : '';
  const phoneRaw = String(user.phone || '').replace(/[^\d+]/g, '');
  const ld = JSON.stringify({ '@context': 'https://schema.org', '@type': 'Product', name: offer.title, description: String(offer.description || offer.title), image: g, offers: { '@type': 'Offer', price: Number(offer.price || 0).toFixed(2), priceCurrency: 'EUR', availability: 'https://schema.org/InStock', seller: { '@type': 'Organization', name: user.siteName } } }).replace(/</g, '\\u003c');
  const body = `<script type="application/ld+json">${ld}</script><div class="prog" id="prog"></div><header class="bar"><b>${esc(user.siteName)}</b><nav><a href="/site/${esc(user.slug)}#offers">All offers</a><a class="favlink" href="/site/${esc(user.slug)}/favorites">&#9825; Saved <span id="favCount"></span></a></nav></header>
<main class="wrap" style="padding-top:110px">
<a class="crumb" href="/site/${esc(user.slug)}#offers">&larr; Back to all offers</a>
<div class="detail">
  <div class="gal">${main}</div>
  <div class="info">
    <h1>${esc(offer.title)}</h1>
    <div class="price">${eur(offer.price)}</div><br>
    <button type="button" class="heart lg" data-id="${offer._id}" aria-pressed="false">${HEART_PATH}<span class="t"></span></button><button type="button" class="share" id="shareBtn">&#8599; Share this offer</button>
    ${offer.description ? `<p class="short">${esc(offer.description)}</p>` : ''}
    ${offer.longDescription ? `<p class="long">${esc(offer.longDescription)}</p>` : ''}
    <div class="glass req" id="request">
      <h2>Request this offer</h2>
      ${sent ? '<div class="ok" style="margin-bottom:14px">Thank you. Your request was sent and the business will contact you.</div>' : ''}
      <form method="POST" action="/site/${esc(user.slug)}/order">
        <input type="hidden" name="offerId" value="${offer._id}"><input type="hidden" name="from" value="offer">
        <input name="customerName" placeholder="Your name" required maxlength="80">
        <label class="lbl">Describe what you want (optional)</label>
        <textarea name="note" rows="3" maxlength="1000" placeholder="e.g. extra cheese, no onions, a bigger size, the day you need it..."></textarea>
        <label class="lbl">How can we reach you?</label>
        <div class="contacts" id="contacts"><div class="crow">
          <select name="ctype" aria-label="Contact type">${Object.entries(CONTACT_TYPES).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
          <input name="cvalue" placeholder="e.g. +359 88 123 4567" required maxlength="120">
        </div></div>
        <button type="button" class="addc" id="addContact">+ Add another contact</button>
        <label class="consent"><input type="checkbox" name="consent" value="1" required> <span>I agree that my details are used to answer my request. <a href="${PUBLIC_BASE}/privacy" target="_blank" rel="noopener">Privacy Policy</a></span></label>
        <button class="btn" type="submit">Send request</button>
      </form>
    </div>
    <div class="glass chat" id="chat" data-offer="${offer._id}" style="margin-top:20px">
      <h2>Chat with ${esc(user.siteName)}</h2>
      <p class="hint">Ask a question or explain exactly what you want. Their reply shows up right here.</p>
      <form id="chatStart">
        <input id="chName" placeholder="Your name" required maxlength="60">
        <input id="chEmail" type="email" placeholder="Email (optional, we tell you when they reply)" maxlength="120">
        <textarea id="chText" placeholder="Write your message..." required maxlength="1500"></textarea>
        <div class="chips"><button type="button">Is this available?</button><button type="button">Can you customize it for me?</button><button type="button">What is the delivery or pickup time?</button></div>
        <button class="btn" type="submit">Send message</button>
        <div class="err" id="chErr" style="color:#ff8aa5;font-size:.88rem"></div>
      </form>
      <div id="chatThread" style="display:none">
        <div class="msgs" id="chatMsgs" aria-live="polite"></div>
        <form class="sendrow" id="chatSend"><textarea id="chReply" placeholder="Write a message..." maxlength="1500" required></textarea><button class="btn" type="submit">Send</button></form>
        ${phoneRaw ? `<a class="callbtn" href="tel:${esc(phoneRaw)}">&#9742; Call ${esc(user.siteName)}</a>` : ''}
      </div>
    </div>
  </div>
</div>
<div style="margin-top:80px">${aboutBlock(user)}</div>
${more}
</main>
<div class="lb" id="lb"><img id="lbImg" alt=""></div>
<div class="stick"><b>${eur(offer.price)}</b><a href="#request">Request this offer</a></div>
${phoneRaw ? `<a class="fab" href="tel:${esc(phoneRaw)}">&#9742; Call</a>` : ''}
<footer><b>${esc(user.siteName)}</b>${[user.category, user.city].filter(Boolean).map(esc).join(' &middot; ')}<div style="margin-top:18px">Built with GoldOffer Studio</div></footer>`;
  return pageShell(user, { title: `${offer.title} - ${user.siteName}`, desc: String(offer.description || offer.title).slice(0, 160), body });
}

function renderFavoritesPage(user) {
  const body = `<div class="prog" id="prog"></div><header class="bar"><b>${esc(user.siteName)}</b><nav><a href="/site/${esc(user.slug)}#offers">All offers</a><a class="favlink" href="/site/${esc(user.slug)}/favorites">&#9825; Saved <span id="favCount"></span></a></nav></header>
<main class="wrap" style="padding-top:110px">
<a class="crumb" href="/site/${esc(user.slug)}#offers">&larr; Back to all offers</a>
<h2>Your favorites</h2><p class="sub">Offers you saved with the heart. They are kept in this browser only, so no account is needed.</p>
<div class="grid" id="favList"><p class="none">Loading...</p></div>
<h2 style="margin-top:80px">Your messages</h2><p class="sub">Conversations you started with ${esc(user.siteName)} from this browser.</p>
<div id="chatList"><p class="none">Loading...</p></div>
</main>
<footer><b>${esc(user.siteName)}</b>${[user.category, user.city].filter(Boolean).map(esc).join(' &middot; ')}<div style="margin-top:18px">Built with GoldOffer Studio</div></footer>`;
  return pageShell(user, { title: `Favorites - ${user.siteName}`, desc: `Offers you saved at ${user.siteName}`, body });
}

const SITE_CSP = [
  "default-src 'self'",
  "script-src 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "frame-src https://www.google.com",
  "form-action 'self'",
  "base-uri 'self'"
].join('; ');

app.get('/site/:slug', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    const offers = await Offer.find({ userId: user._id }).sort({ createdAt: -1 });
    res.setHeader('Content-Security-Policy', SITE_CSP);
    res.send(renderSite(user, offers, req.query.sent === '1'));
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/site/:slug/favorites', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    res.setHeader('Content-Security-Policy', SITE_CSP);
    res.send(renderFavoritesPage(user));
  } catch (err) { res.status(500).send('Server error'); }
});

// One page per offer: opened by the offer ID from the card link
app.get('/site/:slug/offer/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).send('Offer not found.');
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    const offer = await Offer.findOne({ _id: req.params.id, userId: user._id });
    if (!offer) return res.status(404).send('Offer not found.');
    const others = await Offer.find({ userId: user._id, _id: { $ne: offer._id } }).sort({ createdAt: -1 }).limit(3);
    res.setHeader('Content-Security-Policy', SITE_CSP);
    res.send(renderOfferPage(user, offer, others, req.query.sent === '1'));
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
    const parsed = parseContacts(req.body);
    if (parsed.error) return res.status(400).send(`${esc(parsed.error)} Please go back and try again.`);
    await Order.create({
      userId: user._id, offerTitle: offer.title, amount: offer.price,
      customerName: String(req.body.customerName || '').slice(0, 80),
      customerContact: parsed.text.slice(0, 400),
      contacts: parsed.contacts,
      note: String(req.body.note || '').replace(/\r/g, '').trim().slice(0, 1000),
      status: 'Pending'
    });
    // Tell the business owner right away (not awaited, so the customer never waits for email)
    if (user.notifyOn !== false) {
      const name = String(req.body.customerName || '').slice(0, 80);
      const contact = parsed.text.slice(0, 400);
      const note = String(req.body.note || '').replace(/\r/g, '').trim().slice(0, 1000);
      sendMail({
        to: user.notifyEmail || user.email,
        subject: `New request: ${offer.title}`,
        text: `New request for "${offer.title}"\nName: ${name}\nContact: ${contact}${note ? `\nRequest details: ${note}` : ''}\n\n${PUBLIC_BASE}/dashboard`,
        html: emailShell({
          icon: '&#128276;',
          preheader: `${esc(offer.title)} - ${esc(name)}`,
          heading: ['', 'New request'],
          intro: ['', `A customer requested “${esc(offer.title)}” through your site.`],
          details: [['', 'Offer', offer.title], ['', 'Price', `EUR ${Number(offer.price || 0).toFixed(2)}`], ['', 'Name', name], ['', 'Contact', contact], ...(note ? [['', 'Request details', note]] : [])],
          buttonText: ['', 'Open dashboard'], link: `${PUBLIC_BASE}/dashboard`,
          footnote: ['', 'Contact the customer as soon as you can.']
        })
      });
    }
    if (req.body.from === 'offer') return res.redirect(303, `/site/${user.slug}/offer/${offer._id}?sent=1#request`);
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