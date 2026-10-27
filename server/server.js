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
        await User.updateMany({ ownerId: userId }, { subscriptionStatus: 'active' });
      }
    } else if (event.type === 'customer.subscription.deleted') {
      const own = await User.findOneAndUpdate({ stripeCustomerId: event.data.object.customer }, { subscriptionStatus: 'canceled' });
      if (own) await User.updateMany({ ownerId: own._id }, { subscriptionStatus: 'canceled' });
    }
  } catch (e) {
    console.error('Webhook handling error', e);
  }
  res.json({ received: true });
});

app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));

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
    checks: { databaseReady: mongoose.connection.readyState === 1 }
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
  sellerBio: { type: String, default: '' },
  verificationStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
  slug: { type: String, unique: true, sparse: true },
  category: String,
  city: String,
  theme: { type: String, default: 'gold' },
  layout: { type: String, enum: ['signature','editorial','market','neon','mono','atelier','arcade','aurora'], default: 'signature' },
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
  bookingEnabled: {type:Boolean,default:false},
  announcementText:{type:String,default:''},
  design:{type:mongoose.Schema.Types.Mixed},
  designDraft:{type:mongoose.Schema.Types.Mixed},
  faqItems:{type:[{question:String,answer:String,_id:false}],default:[]},
  termsAcceptedAt: Date,
  siteLang: { type: String, maxlength: 24, default: 'en' }, // language of the public website (the link)
  ownerId: { type: mongoose.Schema.Types.ObjectId, index: true }, // set for extra websites created under a main account
  aiGenerated: { type: Boolean, default: false },
  aiPage: { type: mongoose.Schema.Types.Mixed, default: null },
  siteTranslations: { type: mongoose.Schema.Types.Mixed, default: {} },
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
  offerId: {type:mongoose.Schema.Types.ObjectId,ref:'Offer'},
  customerName: String,
  customerContact: String,
  contacts: [{ type: { type: String }, value: String, _id: false }],
  note: String,
  amount: Number,
  status: { type: String, default: 'Pending' }, // Pending, Accepted, Processing, Completed, Cancelled
  trackToken: { type: String, index: true }, history: { type: [{ status: String, at: Date, by: String, _id: false }], default: [] }, stockApplied: { type: Boolean, default: false }, ownerNote: String, anonymized: Boolean,
  createdAt: { type: Date, default: Date.now }
});

// Visitor feedback is unverified. Never label it as a verified purchase.
const ReviewSchema = new mongoose.Schema({
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  name: { type: String, required: true, maxlength: 60 },
  emailHash: { type: String, required: true, select: false },
  rating: { type: Number, min: 1, max: 5, required: true },
  comment: { type: String, maxlength: 600, default: '' },
  createdAt: { type: Date, default: Date.now }
});
ReviewSchema.index({ sellerId: 1, emailHash: 1 }, { unique: true });
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
const Review = mongoose.model('Review', ReviewSchema);

// ---------- Themes and fonts (shared look with the builder) ----------
// a/b = gradient colors, ink = readable accent on white, on = text color on the gradient
const THEMES = {
  gold: { a: '#ffdf00', b: '#ff9000', ink: '#b45309', on: '#17120a' },
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
const LAYOUTS = {

  atelier: {
    name:'Atelier', eyebrow:'The art of the everyday',
    storyHeading:'Thoughtful details. Beautifully presented.',discoverTitle:'The curated selection',
    discoverText:'An editorial gallery for considered products and personal service.',
    tilesText:'Discover the pieces, the craft and the person behind the brand.',
    profileText:'Learn about our vision and the work that defines this business.',
    fallback:[
      'https://images.unsplash.com/photo-1494438639946-1ebd1d20bf85?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1452860606245-08befc0ff44b?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1519710164239-da123dc03ef4?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1497366754035-f200968a6e72?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  arcade: {
    name:'Arcade', eyebrow:'Next level storefront',
    storyHeading:'Built for a generation that never plays ordinary.',discoverTitle:'Choose your next upgrade',
    discoverText:'A kinetic gaming-style storefront with loud typography and grid composition.',
    tilesText:'Browse releases, gear and experiences in a more energetic layout.',
    profileText:'Meet the creator behind the setup and get connected.',
    fallback:[
      'https://images.unsplash.com/photo-1511512578047-dfb367046420?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1542751371-adc38448a05e?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1593305841991-05c297ba4575?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1550745165-9bc0b252726f?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  aurora: {
    name:'Aurora', eyebrow:'Fresh perspectives',
    storyHeading:'An immersive experience with a softer kind of energy.',discoverTitle:'Made to inspire',
    discoverText:'A luminous, spacious site for modern services and creative brands.',
    tilesText:'Explore our favorites in a fluid, image-led collection.',
    profileText:'The story behind the name, told with clarity and warmth.',
    fallback:[
      'https://images.unsplash.com/photo-1500530855697-b586d89ba3ee?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1470252649378-9c29740c9fa8?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1483985988355-763728e1935b?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1490481651871-ab68de25d43d?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  signature: {
    name: 'Signature',
    eyebrow: 'Signature storefront',
    storyHeading: 'A cinematic storefront built to feel premium.',
    discoverTitle: 'Discover the business',
    discoverText: 'Explore the catalog, meet the seller and connect directly.',
    tilesText: 'A dramatic, premium layout with rich contrast and polished motion.',
    profileText: 'Meet the seller, review the profile and start a conversation instantly.',
    fallback: [
      'https://images.unsplash.com/photo-1515169067868-5387ec356754?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1524758631624-e2822e304c36?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1507679799987-c73779587ccf?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1483985988355-763728e1935b?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  editorial: {
    name: 'Editorial',
    eyebrow: 'Editorial storefront',
    storyHeading: 'A spacious layout focused on trust, story and clarity.',
    discoverTitle: 'Browse the collection',
    discoverText: 'A lighter, more refined presentation with product-first storytelling.',
    tilesText: 'Every section breathes more, making the brand feel elegant and curated.',
    profileText: 'Get to know the seller in a cleaner editorial presentation.',
    fallback: [
      'https://images.unsplash.com/photo-1483985988355-763728e1935b?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1512436991641-6745cdb1723f?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1515886657613-9f3515b0c78f?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1524504388940-b1c1722653e1?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  market: {
    name: 'Modern Market',
    eyebrow: 'Modern storefront',
    storyHeading: 'A bold marketplace look built for conversion and direct contact.',
    discoverTitle: 'Shop the latest offers',
    discoverText: 'The content is centered, bolder and more commerce-oriented.',
    tilesText: 'This layout puts offers first and makes the catalog easier to scan.',
    profileText: 'Seller profile and reviews stay one tap away across the whole site.',
    fallback: [
      'https://images.unsplash.com/photo-1542291026-7eec264c27ff?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1512496015851-a90fb38ba796?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1468495244123-6c6a332a7303?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1511512578047-dfb367046420?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  neon: {
    name: 'Neon Grid',
    eyebrow: 'Gamer / tech storefront',
    storyHeading: 'A futuristic layout with sharper edges, glow and gamer energy.',
    discoverTitle: 'Power up the storefront',
    discoverText: 'Ideal for gaming, tech gear and creators who want a stronger personality.',
    tilesText: 'Sharper cards, more contrast and a glowing interface across the full public link.',
    profileText: 'The seller profile feels more like a modern gaming hub than a generic profile.',
    fallback: [
      'https://images.unsplash.com/photo-1542751371-adc38448a05e?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1511512578047-dfb367046420?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1560253023-3ec5d502959f?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1550745165-9bc0b252726f?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  mono: {
    name: 'Minimal Mono',
    eyebrow: 'Minimal storefront',
    storyHeading: 'A clean monochrome look with calmer typography and restrained accents.',
    discoverTitle: 'Explore the essentials',
    discoverText: 'Minimal Mono reduces visual noise and lets photos and text do the work.',
    tilesText: 'The most minimal version — clean spacing, simple hierarchy and quiet confidence.',
    profileText: 'Seller information becomes simpler, sharper and more business-like.',
    fallback: [
      'https://images.unsplash.com/photo-1516321497487-e288fb19713f?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1516321318423-f06f85e504b3?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1517048676732-d65bc937f952?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1521737604893-d14cc237f11d?auto=format&fit=crop&w=1200&q=80'
    ]
  }
};

// ---------- Helpers ----------
const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));

const CYR = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ж: 'zh', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm', н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'h', ц: 'ts', ч: 'ch', ш: 'sh', щ: 'sht', ъ: 'a', ь: 'y', ю: 'yu', я: 'ya' };
// Name shown to visitors as the person behind the shop (falls back to the shop name)
function sellerName(user) {
  return ([user.firstName, user.lastName].filter(Boolean).join(' ').trim()) || user.siteName;
}
function safeLayout(v) { return LAYOUTS[v] ? v : 'signature'; }
function layoutPack(v) { return LAYOUTS[safeLayout(v)]; }
function initials(v) {
  const parts = String(v || '').trim().split(/\s+/).filter(Boolean).slice(0, 2);
  if (!parts.length) return 'GO';
  return parts.map(x => x.charAt(0).toUpperCase()).join('');
}
function artPlaceholder(title, kicker) {
  return `<div class="ph ph-art"><div class="ph-art-bg"></div><small>${esc(kicker || 'Featured')}</small><strong>${esc(title || 'Offer')}</strong></div>`;
}

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
  subscriptionStatus: u.subscriptionStatus, siteName: u.siteName, sellerBio: u.sellerBio || '', verificationStatus: u.verificationStatus || 'none', slug: u.slug,
  category: u.category, city: u.city, theme: u.theme, layout: u.layout || 'signature', font: u.font, published: u.published,
  siteUrl: u.slug && u.published ? `${PUBLIC_BASE}/site/${u.slug}` : null,
  offerLimit: offerLimitFor(u),
  categoryLabel: u.categoryLabel, phone: u.phone, address: u.address, hours: u.hours,
  facebook: u.facebook, instagram: u.instagram, logoUrl: u.logoUrl,
  lang: u.lang || 'bg', notifyEmail: u.notifyEmail, notifyOn: u.notifyOn !== false,
  siteLang: u.siteLang || 'en', ownerId: u.ownerId || null, aiGenerated: !!u.aiGenerated
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

// Profile biography draft uses the business owner's provided information only.
// It is not represented as researched or AI-authored factual content.
app.post('/api/site/bio-suggestion', authenticateToken, async (req,res)=>{
  try {
    const b=req.body||{};
    const brand=String(b.siteName||'').trim().slice(0,80);
    const category=String(b.category||'').trim().slice(0,80);
    const city=String(b.city||'').trim().slice(0,80);
    const details=String(b.details||'').trim().slice(0,650);
    if(!brand||(!category&&!details))return res.status(400).json({message:'Add a business name and some details first.'});
    let bio='',source='Business details';
    if(process.env.OPENAI_API_KEY){
      try {
        const response=await axios.post('https://api.openai.com/v1/chat/completions',{
          model:process.env.OPENAI_MODEL||'gpt-4o-mini', temperature:0.5,max_tokens:200,
          messages:[{role:'system',content:'Write a polished, concise business introduction in English, max 65 words. Use only user-provided facts; do not invent certifications, reviews, pricing, experience, quality guarantees, opening hours, shipping, delivery, ingredients or product specifications. Return only the paragraph.'},{role:'user',content:JSON.stringify({brand,category,city,details})}]
        },{timeout:12000,headers:{Authorization:'Bearer '+process.env.OPENAI_API_KEY,'Content-Type':'application/json'}});
        bio=String(response.data?.choices?.[0]?.message?.content||'').trim().slice(0,650);
        if(bio)source='AI draft based on your information';
      }catch(e){console.warn('AI draft unavailable:',e.message);}
    }
    if(!bio){bio=[brand+(category?' — '+category:'' )+(city?' in '+city:'' )+'.', details?details.replace(/[.!?]+$/,'')+'.':'', 'Contact the seller to learn more.'].filter(Boolean).join(' ').slice(0,650);}
    res.json({bio,source,needsReview:true});
  }catch(e){res.status(500).json({message:'Unable to suggest a bio.'});}
});
// Verification is a request, NEVER automatic approval. Approval requires manual identity checks.
app.post('/api/site/request-verification', authenticateToken, async(req,res)=>{
  try {
    const user=await User.findById(req.user.id);
    if(!user) return res.status(404).json({message:'Account not found'});
    if(user.verificationStatus==='none' || user.verificationStatus==='rejected') {user.verificationStatus='pending';await user.save();}
    res.json({status:user.verificationStatus,message:'Your request has been recorded. Verification is not automatic.'});
  }catch(e){res.status(500).json({message:'Could not submit verification request'});}
});
// Manual verification workflow: only an authenticated account whose email matches
// ADMIN_EMAIL in Render can review applications. Never auto-approve profiles.
async function requireGoldAdmin(req,res,next) {
  const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  if (!email) return res.status(503).json({message:'ADMIN_EMAIL is not configured.'});
  const current = await User.findById(req.user.id).select('email').lean();
  if (!current || current.email !== email) return res.status(403).json({message:'Administrator access required.'});
  next();
}
app.get('/api/admin/verification-requests', authenticateToken, requireGoldAdmin, async(req,res)=>{
  try { const users=await User.find({verificationStatus:'pending'}).select('firstName lastName email siteName slug createdAt verificationStatus').sort({createdAt:1}).limit(100).lean(); res.json({requests:users}); }
  catch(e){res.status(500).json({message:'Could not load verification requests.'});}
});
app.post('/api/admin/verification-requests/:id',authenticateToken,requireGoldAdmin,async(req,res)=>{
  if(!mongoose.isValidObjectId(req.params.id))return res.status(400).json({message:'Invalid ID'});
  if(!['approved','rejected'].includes(req.body?.decision))return res.status(400).json({message:'Choose approved or rejected.'});
  try { const user=await User.findOneAndUpdate({_id:req.params.id,verificationStatus:'pending'},{$set:{verificationStatus:req.body.decision}},{new:true}).select('siteName verificationStatus');
    if(!user)return res.status(404).json({message:'Pending request not found'});
    res.json({user});
  }catch(e){res.status(500).json({message:'Could not update verification.'});}
});
// ---------- Site settings / publishing ----------
app.put('/api/site', authenticateToken, async (req, res) => {
  try {
    const b = req.body || {};
    const { siteName, category, city, theme, font, publish } = b;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (siteName !== undefined) user.siteName = String(siteName).trim().slice(0, 80);
    if (b.sellerBio !== undefined) user.sellerBio = String(b.sellerBio).trim().slice(0, 650);
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
    if (typeof b.siteLang === 'string' && /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$/.test(b.siteLang)) user.siteLang = b.siteLang;
    if (b.notifyEmail !== undefined) user.notifyEmail = isEmail(b.notifyEmail) ? String(b.notifyEmail).trim() : '';
    if (typeof b.notifyOn === 'boolean') user.notifyOn = b.notifyOn;
    if (Object.keys(THEMES).includes(theme)) user.theme = theme;
    if (['signature','editorial','market','neon','mono','atelier','arcade','aurora'].includes(b.layout)) user.layout = b.layout;
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
app.post('/api/orders', authenticateToken, async (req, res) => {
  const { offerTitle, customerName, amount } = req.body || {};
  const a = Number(amount);
  if (!isFinite(a) || a < 0) return res.status(400).json({ message: 'Invalid amount' });
  const order = await Order.create({
    userId: req.user.id, offerTitle: String(offerTitle || '').slice(0, 120),
    customerName: String(customerName || '').slice(0, 80), amount: a, status: 'Pending'
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

// Compose a short, product-specific draft from Google search snippets.
// Search results are untrusted: never copy markup or claim an exact specification.
function searchDescription(title, items) {
  const stop = new Set(['and','the','for','with','this','that','from','your','или','това','този','както','които','цена','цени','цена:','лв','eur','euro','магазин','онлайн','купи','продажба','внос','new']);
  const words = String(title).toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(w => w.length >= 3 && !stop.has(w));
  const matching = (items || []).filter(x => {
    const txt = ((x.texts || []).join(' ') + ' ' + (x.name || '')).toLowerCase();
    return words.some(w => txt.includes(w));
  });
  const snippets = matching.flatMap(x => (x.texts || []).filter(Boolean))
    .map(t => String(t).replace(/<[^>]*>/g,' ').replace(/https?:\/\/\S+/g,' ').replace(/\s+/g,' ').trim())
    .filter(t => t.length > 45 && t.length < 1000 && !/^\s*(?:\d+[.,]?\d*\s*(?:€|лв|eur))\s*$/i.test(t));
  const sentence = snippets.flatMap(t => t.split(/(?<=[.!?])\s+/)).find(t =>
    t.length >= 40 && t.length <= 240 && words.some(w => t.toLowerCase().includes(w)) &&
    !/cookie|privacy policy|доставка|в наличност|купи сега|промоция|безплатна доставка|register|login/i.test(t)
  );
  if (!sentence) return null;
  // Google descriptions are informational drafts: don't present unrelated commercial boilerplate.
  return `${String(title).trim()}. ${sentence.replace(/[.!?\s]+$/, '')}.`.slice(0, 450);
}

app.post('/api/ai/product-description', authenticateToken, async (req, res) => {
  const query = String((req.body && req.body.query) || '').trim().slice(0, 120);
  if (query.length < 3) return res.status(400).json({ message: 'Enter a product name (at least 3 characters).' });
  try {
    const results = await googleResults(query, 'Bulgaria');
    if (results === null) return res.status(503).json({ message: 'Google search is not configured on the server. Set SERPAPI_KEY or GOOGLE_API_KEY and GOOGLE_CX.' });
    const description = searchDescription(query, results);
    if (!description) return res.json({ description: '', message: 'Not enough reliable information found for this product. Please write the description yourself.' });
    return res.json({ description, source: 'Google search snippets', message: 'Draft from search results. Review the details before publishing.' });
  } catch (err) {
    console.error('Product description search failed:', err.message);
    return res.status(502).json({ message: 'Could not fetch Google results right now. Please try again.' });
  }
});

app.post('/api/ai/market-price', authenticateToken, async (req, res) => {
  const query = String((req.body && req.body.query) || '').trim().slice(0, 120);
  const city = String((req.body && req.body.city) || '').trim().slice(0, 80) || 'Bulgaria';
  if (!query) return res.status(400).json({ message: 'Enter a title first.' });
  // No generic description: use matching Google snippets when available.
  try {
    const items = await googleResults(query, city);
    if (items === null) {
      return res.json({ estimated: true, description: null, message: 'Live price search is not set up on the server yet (SERPAPI_KEY or GOOGLE_API_KEY + GOOGLE_CX is missing). Please enter the price manually.' });
    }
    const found = []; // { price, name, url }
    items.forEach(it => {
      const prices = it.price != null && isFinite(it.price) ? [it.price] : extractPrices((it.texts || []).join(' | '));
      // a result counts once, with its first price, so one page with many prices cannot skew the range
      if (prices.length) found.push({ price: Number(prices[0]), name: it.name || hostOf(it.url), url: it.url });
    });
    if (found.length < 2) {
      return res.json({ estimated: true, description: searchDescription(query, items), message: `Google returned ${items.length} results for "${query}" in ${city}, but only ${found.length} showed a price (at least 2 are needed). Try a more common product name, or enter the price manually.` });
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
      description: searchDescription(query, items),
      city,
      sampleSize: kept.length,
      sources: kept.slice(0, 6).map(f => ({ name: f.name, price: f.price, url: f.url }))
    });
  } catch (err) {
    const why = String(err.serpError || (err.response && err.response.data && (err.response.data.error && (err.response.data.error.message || err.response.data.error))) || err.message || 'unknown error').slice(0, 200);
    console.error('Market price error:', why);
    res.json({ estimated: true, description: null, message: `The Google price search failed: ${why}. You can enter the price manually.` });
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
  offerId: {type:mongoose.Schema.Types.ObjectId,ref:'Offer'},
  customerName: String,
  customerEmail: String,          // optional, only used to say "you have a reply"
  tokenHash: String,              // the visitor proves who they are with a secret kept in their browser
  // from: 'customer' | 'seller' | 'system' (call notes). att = a photo or file sent in the chat
  messages: [{ from: String, text: String, at: { type: Date, default: Date.now }, att: { url: String, name: String, mime: String, size: Number }, _id: false }],
  unreadSeller: { type: Number, default: 0 },
  unreadCustomer: { type: Number, default: 0 },
  lastAt: { type: Date, default: Date.now },
  sellerMailedAt: Date,
  customerMailedAt: Date
});
const Conversation = mongoose.model('Conversation', ConversationSchema);

// Photos and files sent inside a chat. The link contains a random key, so only people in the chat know it.
const ChatFile = mongoose.model('ChatFile', new mongoose.Schema({
  key: { type: String, unique: true, index: true },
  convId: { type: mongoose.Schema.Types.ObjectId, index: true },
  name: String,
  contentType: String,
  size: Number,
  data: Buffer,
  createdAt: { type: Date, default: Date.now }
}));

const startLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10 });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 150 });
const callLimiter = rateLimit({ windowMs: 60 * 1000, max: 300 });
const attachLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 40, message: { message: 'Too many files sent. Please wait a few minutes.' } });
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
const briefConv = (c, forSeller, info) => {
  const o = (info && info[String(c.offerId)]) || {};
  const live = liveCall(c._id);
  const me = forSeller ? 'seller' : 'customer';
  return {
    id: c._id, offerId: c.offerId, offerTitle: c.offerTitle, customerName: c.customerName, customerEmail: forSeller ? c.customerEmail : undefined,
    last: lastOf(c), unread: forSeller ? c.unreadSeller : c.unreadCustomer, lastAt: c.lastAt, count: c.messages.length,
    offerImage: o.image || null, offerPrice: o.price != null ? o.price : null,
    ringing: !!(live && live.status === 'ringing' && live.caller !== me)
  };
};
// Photo and price of the offers behind a list of conversations (for the list screen)
async function offerInfo(convs, userId) {
  const ids = [...new Set(convs.map(c => String(c.offerId || '')).filter(id => mongoose.isValidObjectId(id)))];
  if (!ids.length) return {};
  const offers = await Offer.find({ _id: { $in: ids }, userId });
  const map = {};
  offers.forEach(o => { map[String(o._id)] = { image: galleryOf(o)[0] || null, price: o.price }; });
  return map;
}

// ---------- Chat files ----------
const CHAT_FILE_MAX = 8 * 1024 * 1024;
const BLOCKED_FILE = /\.(exe|bat|cmd|com|scr|msi|jar|vbs|ps1|sh|apk|dll|js|html?|svg|php|lnk)$/i;
const IMAGE_MIMES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const chatUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: CHAT_FILE_MAX, files: 1 } });
// Browsers can send file names as UTF-8 that multer reads as latin1 (Cyrillic names), so repair them
function fixName(n) {
  n = String(n || 'file');
  if (/[\u0080-\u00ff]/.test(n) && !/[^\u0000-\u00ff]/.test(n)) {
    const u = Buffer.from(n, 'latin1').toString('utf8');
    if (!u.includes('\uFFFD')) n = u;
  }
  return n.replace(/[\r\n"\\\/]/g, '_').slice(0, 120) || 'file';
}
// Real image files start with known bytes. A file that only claims to be an image is sent as a plain download.
function sniffMime(buf) {
  if (!buf || buf.length < 12) return 'application/octet-stream';
  if (buf[0] === 0xff && buf[1] === 0xd8) return 'image/jpeg';
  if (buf[0] === 0x89 && buf.toString('ascii', 1, 4) === 'PNG') return 'image/png';
  if (buf.toString('ascii', 0, 3) === 'GIF') return 'image/gif';
  if (buf.toString('ascii', 0, 4) === 'RIFF' && buf.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  return 'application/octet-stream';
}
// Saves an uploaded file and returns the attachment record for the message
async function storeChatFile(conv, file) {
  const name = fixName(file.originalname);
  if (BLOCKED_FILE.test(name)) throw Object.assign(new Error('This file type is not allowed.'), { status: 400 });
  const count = await ChatFile.countDocuments({ convId: conv._id });
  if (count >= 60) throw Object.assign(new Error('This conversation has too many files.'), { status: 400 });
  const key = crypto.randomBytes(16).toString('hex');
  const mime = sniffMime(file.buffer);
  await ChatFile.create({ key, convId: conv._id, name, contentType: mime, size: file.size, data: file.buffer });
  return { url: `${PUBLIC_BASE}/api/file/${key}`, name, mime, size: file.size };
}
function runUpload(req, res, next) {
  chatUpload.single('file')(req, res, (err) => {
    if (err) return res.status(400).json({ message: err.code === 'LIMIT_FILE_SIZE' ? 'The file is too big (max 8 MB).' : 'Upload failed: ' + err.message });
    if (!req.file) return res.status(400).json({ message: 'Please choose a file.' });
    next();
  });
}

// Chat downloads use short-lived signed URLs. Only authenticated conversation API
// responses carry fresh links; storing or forwarding an old link will not grant
// indefinite access. Treat these as bearer links: recipients can still share them
// during their validity window. For stronger isolation use an authenticated file proxy.
const FILE_LINK_TTL_MS = 3 * 60 * 60 * 1000;
function fileSignature(key, exp) {
  return crypto.createHmac('sha256', process.env.JWT_SECRET || 'not-configured')
    .update(String(key) + ':' + String(exp)).digest('hex');
}
function signedFileLink(url) {
  const m = String(url || '').match(/\/api\/file\/([a-f0-9]{32})(?:\?.*)?$/);
  if (!m) return url;
  const exp = Date.now() + FILE_LINK_TTL_MS;
  return String(url).split('?')[0] + '?exp=' + exp + '&sig=' + fileSignature(m[1], exp);
}
function signAttachments(obj, level = 0) {
  if (!obj || typeof obj !== 'object' || level > 8) return;
  if (Array.isArray(obj)) { obj.forEach(x => signAttachments(x, level + 1)); return; }
  if (obj.att && typeof obj.att === 'object' && typeof obj.att.url === 'string') {
    obj.att.url = signedFileLink(obj.att.url);
  }
  for (const [k,v] of Object.entries(obj)) if (k !== 'att') signAttachments(v, level + 1);
}
app.use((req, res, next) => {
  if (!(/^\/site\/[^/]+\/chat\//.test(req.path) || /^\/api\/conversations(?:\/|$)/.test(req.path))) return next();
  const old = res.json.bind(res);
  res.json = (value) => {
    if (value && typeof value === 'object') {
      const serial = JSON.parse(JSON.stringify(value));
      signAttachments(serial);
      return old(serial);
    }
    return old(value);
  };
  next();
});

app.get('/api/file/:key', async (req, res) => {
  try {
    if (!/^[a-f0-9]{32}$/.test(req.params.key)) return res.status(404).end();
    const exp=Number(req.query.exp),sig=String(req.query.sig||'');
    if(!Number.isSafeInteger(exp)||exp<Date.now()||exp>Date.now()+FILE_LINK_TTL_MS||!/^[a-f0-9]{64}$/.test(sig))return res.status(403).end();
    const a=Buffer.from(sig,'hex'),b=Buffer.from(fileSignature(req.params.key,exp),'hex');
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(403).end();
    const f = await ChatFile.findOne({ key: req.params.key });
    if (!f) return res.status(404).end();
    const isImg = IMAGE_MIMES.includes(f.contentType);
    res.set({
      'Content-Type': isImg ? f.contentType : 'application/octet-stream',
      'Content-Disposition': `${isImg ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name || 'file')}`,
      'Cache-Control': 'private, no-store',
      'X-Content-Type-Options': 'nosniff',
      'Cross-Origin-Resource-Policy': 'cross-origin'
    });
    res.send(f.data);
  } catch (e) { res.status(404).end(); }
});

// ---------- Voice calls (WebRTC). The server only passes the setup messages between the two people; the audio goes directly. ----------
const CALLS = new Map(); // conversation id -> call
const RING_MS = 45 * 1000;
function callOf(convId) { return CALLS.get(String(convId)) || null; }
function liveCall(convId) { const c = callOf(convId); return c && c.status !== 'ended' ? c : null; }
const mmss = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
async function finishCall(c, reason) {
  if (c.status === 'ended') return;
  const wasActive = c.status === 'active';
  c.status = 'ended'; c.reason = reason; c.endedAt = Date.now();
  const text = wasActive ? `Call ended \u00b7 ${mmss(Math.max(0, Math.round((c.endedAt - c.answeredAt) / 1000)))}` : (reason === 'declined' ? 'Call declined' : 'Missed call');
  const update = { $push: { messages: { from: 'system', text, at: new Date() } }, $set: { lastAt: new Date() } };
  if (!wasActive && reason !== 'declined') update.$inc = c.caller === 'customer' ? { unreadSeller: 1 } : { unreadCustomer: 1 };
  try { await Conversation.updateOne({ _id: c.convId }, update); } catch (e) { console.error('Call note error', e.message); }
}
setInterval(() => {
  const now = Date.now();
  CALLS.forEach((c, k) => {
    if (c.status === 'ringing') {
      if (now - c.createdAt > RING_MS) finishCall(c, 'missed');
      else if (now - c.seen[c.caller] > 12000) finishCall(c, 'cancelled');
    } else if (c.status === 'active') {
      if (now - c.seen.customer > 40000 || now - c.seen.seller > 40000) finishCall(c, 'dropped');
    } else if (now - c.endedAt > 30000) CALLS.delete(k);
  });
}, 5000).unref();

function callPoll(conv, side, after) {
  const c = callOf(conv._id);
  if (!c) return { call: null, signals: [] };
  c.seen[side] = Date.now();
  return {
    call: { id: c.id, status: c.status, caller: c.caller, reason: c.reason || null },
    signals: c.signals.filter(s => s.n > after && s.from !== side).map(s => ({ n: s.n, type: s.type, data: s.data }))
  };
}
// Handles offer / answer / candidate / decline / hangup from one side. Returns { code, body }.
async function callSignal(conv, side, owner, b) {
  const type = String(b.type || '');
  const data = b.data;
  if (data !== undefined && JSON.stringify(data).length > 20000) return { code: 400, body: { message: 'Bad call data.' } };
  let c = callOf(conv._id);
  if (type === 'offer') {
    if (c && c.status !== 'ended') return { code: 409, body: { message: 'A call is already in progress.' } };
    if (!data || data.type !== 'offer' || typeof data.sdp !== 'string') return { code: 400, body: { message: 'Bad call data.' } };
    c = { id: crypto.randomBytes(8).toString('hex'), convId: conv._id, userId: conv.userId, caller: side, status: 'ringing', createdAt: Date.now(), signals: [], seen: { customer: 0, seller: 0 }, n: 0 };
    c.seen[side] = Date.now();
    c.signals.push({ n: ++c.n, from: side, type: 'offer', data });
    CALLS.set(String(conv._id), c);
    notifyCall(conv, side, owner);
    return { code: 200, body: { callId: c.id } };
  }
  if (!c || c.id !== String(b.callId || '')) return { code: 404, body: { message: 'Call not found.' } };
  if (c.status === 'ended') return { code: 200, body: { ended: true } };
  c.seen[side] = Date.now();
  if (type === 'answer') {
    if (side === c.caller || c.status !== 'ringing' || !data || data.type !== 'answer') return { code: 400, body: { message: 'Bad call data.' } };
    c.status = 'active'; c.answeredAt = Date.now(); c.seen.customer = c.seen.seller = Date.now();
    c.signals.push({ n: ++c.n, from: side, type: 'answer', data });
  } else if (type === 'candidate') {
    if (c.signals.length < 300 && data && typeof data === 'object') c.signals.push({ n: ++c.n, from: side, type: 'candidate', data });
  } else if (type === 'decline') {
    if (side !== c.caller) await finishCall(c, 'declined');
  } else if (type === 'hangup') {
    await finishCall(c, c.status === 'ringing' ? (side === c.caller ? 'cancelled' : 'declined') : 'ended');
  } else return { code: 400, body: { message: 'Unknown call message.' } };
  return { code: 200, body: { ok: true } };
}
// Tell the other person by email, at most once every 10 minutes per conversation
function notifyCall(conv, side, owner) {
  if (!owner) return;
  const gap = (d) => !d || Date.now() - new Date(d).getTime() > MAIL_GAP_MS;
  if (side === 'customer') {
    if (owner.notifyOn === false || !gap(conv.sellerMailedAt)) return;
    Conversation.updateOne({ _id: conv._id }, { $set: { sellerMailedAt: new Date() } }).catch(() => {});
    sendMail({
      to: owner.notifyEmail || owner.email, subject: `${conv.customerName} is calling you`,
      text: `${conv.customerName} is calling you about "${conv.offerTitle}". Open your dashboard to answer: ${PUBLIC_BASE}/dashboard`,
      html: emailShell({ icon: '&#128222;', preheader: `${esc(conv.customerName)} is calling`, heading: ['', 'Incoming call'], intro: ['', `${esc(conv.customerName)} is calling you about \u201c${esc(conv.offerTitle)}\u201d.`], buttonText: ['', 'Open dashboard'], link: `${PUBLIC_BASE}/dashboard`, footnote: ['', 'Keep the dashboard open to receive calls.'] })
    });
  } else if (conv.customerEmail && gap(conv.customerMailedAt)) {
    Conversation.updateOne({ _id: conv._id }, { $set: { customerMailedAt: new Date() } }).catch(() => {});
    const link = `${PUBLIC_BASE}/site/${owner.slug}/messages`;
    sendMail({
      to: conv.customerEmail, subject: `${owner.siteName} is calling you`,
      text: `${owner.siteName} is calling you about "${conv.offerTitle}". Open the chat to answer: ${link}`,
      html: emailShell({ icon: '&#128222;', preheader: `${esc(owner.siteName)} is calling`, heading: ['', 'Incoming call'], intro: ['', `${esc(owner.siteName)} is calling you about \u201c${esc(conv.offerTitle)}\u201d.`], buttonText: ['', 'Open the chat'], link, footnote: ['', 'Open it in the same browser you used before.'] })
    });
  }
}
// Connection servers. STUN is free. For calls over mobile data a TURN server helps: set TURN_URL (+ TURN_USERNAME, TURN_CREDENTIAL)
// or METERED_DOMAIN + METERED_API_KEY (free plan at metered.ca) in Render, Environment.
let iceCache = { at: 0, list: null };
app.get('/api/ice', chatLimiter, async (req, res) => {
  const list = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
  try {
    if (process.env.METERED_DOMAIN && process.env.METERED_API_KEY) {
      if (!iceCache.list || Date.now() - iceCache.at > 30 * 60 * 1000) {
        const r = await axios.get(`https://${process.env.METERED_DOMAIN}/api/v1/turn/credentials`, { params: { apiKey: process.env.METERED_API_KEY }, timeout: 8000 });
        iceCache = { at: Date.now(), list: Array.isArray(r.data) ? r.data : [] };
      }
      list.push(...iceCache.list);
    } else if (process.env.TURN_URL) {
      list.push({ urls: process.env.TURN_URL.split(',').map(s => s.trim()).filter(Boolean), username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL });
    }
  } catch (e) { console.error('ICE error', e.message); }
  res.set("Cache-Control", "no-store");
  res.json({ iceServers: list, relayConfigured: list.some(x => (Array.isArray(x.urls)?x.urls:[x.urls]).some(u => String(u).startsWith("turn:" ) || String(u).startsWith("turns:"))) });
});

async function siteBySlug(slug) {
  const user = await User.findOne({ slug });
  return user && user.published ? user : null;
}


async function rejectOwnerSelfAction(req, res, next) {
  const bearer = String(req.headers.authorization || '').match(/^Bearer (.+)$/i);
  if (!bearer) return next();
  try {
    const session = jwt.verify(bearer[1], process.env.JWT_SECRET);
    const owner = await User.findOne({slug:req.params.slug}).select('_id');
    if (owner && String(owner._id) === String(session.id)) return res.status(403).json({message:'You cannot contact or order from your own storefront.'});
  } catch (_) {}
  next();
}

// Visitor: start a conversation about an offer
app.post('/site/:slug/chat/start', startLimiter, rejectOwnerSelfAction, async (req, res) => {
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
    void pushNote(user._id, 'message', String(conv._id), 'New conversation', `${name}: ${String(text).slice(0, 80)}`, '/messages');
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
    const mine = found.filter(c => tokenOk(c, (items.find(x => String(x.id) === String(c._id)) || {}).token));
    const info = await offerInfo(mine, user._id);
    const out = mine.map(c => briefConv(c, false, info));
    out.sort((a, b) => new Date(b.lastAt) - new Date(a.lastAt));
    res.json({ conversations: out, businessName: sellerName(user), phone: user.phone || '' });
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// Visitor: read the thread (polled every few seconds by the offer page)
app.get('/site/:slug/chat/:id', chatLimiter, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Not found' });
    const user = await siteBySlug(req.params.slug);
    const conv = user && await Conversation.findOne({ _id: req.params.id, userId: user._id });
    if (!conv || !tokenOk(conv, req.query.token)) return res.status(404).json({ message: 'Conversation not found.' });
    if (conv.unreadCustomer) { await Conversation.updateOne({ _id: conv._id }, { $set: { unreadCustomer: 0 } }); }
    const live = liveCall(conv._id);
    res.json({ messages: conv.messages, businessName: sellerName(user), call: live ? { id: live.id, status: live.status, caller: live.caller } : null });
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
    await pushCustomerMessage(user, conv, text, null);
    res.json({ messages: conv.messages });
  } catch (err) { res.status(500).json({ message: 'Could not send your message. Please try again.' }); }
});

// Adds a message from the visitor (text and/or a file) and emails the business at most once every 10 minutes
async function pushCustomerMessage(user, conv, text, att) {
  const msg = { from: 'customer', text, at: new Date() };
  if (att) msg.att = att;
  conv.messages.push(msg);
  conv.unreadSeller += 1; conv.lastAt = new Date();
  const mailNow = user.notifyOn !== false && (!conv.sellerMailedAt || Date.now() - new Date(conv.sellerMailedAt).getTime() > MAIL_GAP_MS);
  if (mailNow) conv.sellerMailedAt = new Date();
  await conv.save();
  void pushNote(user._id, 'message', String(conv._id), 'New message', `${conv.customerName || 'A customer'}: ${String(text || (att ? 'sent a file' : '')).slice(0, 80)}`, '/messages');
  if (mailNow) {
    const shown = text || (att ? `File: ${att.name}` : '');
    sendMail({
      to: user.notifyEmail || user.email,
      subject: `New message from ${conv.customerName}`,
      text: `${conv.customerName} wrote about "${conv.offerTitle}":\n\n${shown}\n\nReply: ${PUBLIC_BASE}/dashboard`,
      html: emailShell({
        icon: '&#128172;', preheader: `${esc(conv.customerName)}: ${esc(shown.slice(0, 80))}`,
        heading: ['', 'New message'], intro: ['', `${esc(conv.customerName)} wrote again about “${esc(conv.offerTitle)}”.`],
        details: [['', 'Message', shown]], buttonText: ['', 'Reply in dashboard'], link: `${PUBLIC_BASE}/dashboard`,
        footnote: ['', 'You get at most one email every 10 minutes per conversation.']
      })
    });
  }
}
// Adds a message from the business (text and/or a file) and emails the visitor (if they left an email) at most once every 10 minutes
async function pushSellerMessage(owner, c, text, att) {
  const msg = { from: 'seller', text, at: new Date() };
  if (att) msg.att = att;
  c.messages.push(msg);
  c.unreadCustomer += 1; c.lastAt = new Date();
  const mailNow = c.customerEmail && (!c.customerMailedAt || Date.now() - new Date(c.customerMailedAt).getTime() > MAIL_GAP_MS);
  if (mailNow) c.customerMailedAt = new Date();
  await c.save();
  if (mailNow && owner) {
    const link = `${PUBLIC_BASE}/site/${owner.slug}/messages`;
    const shown = text || (att ? `File: ${att.name}` : '');
    sendMail({
      to: c.customerEmail,
      subject: `${owner.siteName} replied to you`,
      text: `${owner.siteName} replied about "${c.offerTitle}":\n\n${shown}\n\nOpen the chat: ${link}`,
      html: emailShell({
        icon: '&#128172;', preheader: esc(shown.slice(0, 90)),
        heading: ['', 'You have a reply'], intro: ['', `${esc(owner.siteName)} answered your message about “${esc(c.offerTitle)}”.`],
        details: [['', 'Reply', shown]], buttonText: ['', 'Open the chat'], link,
        footnote: ['', 'Open the same browser you used before to continue the conversation.']
      })
    });
  }
}

// Visitor: send a photo or file (the text box content becomes the caption)
app.post('/site/:slug/chat/:id/attach', chatLimiter, attachLimiter, runUpload, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Not found' });
    const user = await siteBySlug(req.params.slug);
    const conv = user && await Conversation.findOne({ _id: req.params.id, userId: user._id });
    if (!conv || !tokenOk(conv, req.body && req.body.token)) return res.status(404).json({ message: 'Conversation not found.' });
    if (conv.messages.length >= MAX_MSGS) return res.status(400).json({ message: 'This conversation is full.' });
    const att = await storeChatFile(conv, req.file);
    await pushCustomerMessage(user, conv, cleanMsg(req.body && req.body.text), att);
    res.json({ messages: conv.messages });
  } catch (err) { res.status(err.status || 500).json({ message: err.status ? err.message : 'Could not send the file. Please try again.' }); }
});

// Visitor: call status (polled once a second during a call)
app.get('/site/:slug/chat/:id/call', callLimiter, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Not found' });
    const user = await siteBySlug(req.params.slug);
    const conv = user && await Conversation.findOne({ _id: req.params.id, userId: user._id });
    if (!conv || !tokenOk(conv, req.query.token)) return res.status(404).json({ message: 'Conversation not found.' });
    res.json(callPoll(conv, 'customer', Number(req.query.after) || 0));
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});
app.post('/site/:slug/chat/:id/call/signal', callLimiter, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Not found' });
    const user = await siteBySlug(req.params.slug);
    const conv = user && await Conversation.findOne({ _id: req.params.id, userId: user._id });
    if (!conv || !tokenOk(conv, req.body && req.body.token)) return res.status(404).json({ message: 'Conversation not found.' });
    const r = await callSignal(conv, 'customer', user, req.body || {});
    res.status(r.code).json(r.body);
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
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
  const info = await offerInfo(list, req.user.id);
  res.json({ conversations: list.map(c => briefConv(c, true, info)), unread: list.reduce((n, c) => n + (c.unreadSeller || 0), 0) });
});
// Calls from visitors that are ringing right now (the dashboard polls this every few seconds)
app.get('/api/calls/incoming', authenticateToken, callLimiter, (req, res) => {
  const calls = [];
  CALLS.forEach((c) => {
    if (String(c.userId) === String(req.user.id) && c.status === 'ringing' && c.caller === 'customer') calls.push({ convId: c.convId, callId: c.id });
  });
  res.json({ calls });
});
app.get('/api/conversations/:id', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  const c = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
  if (!c) return res.status(404).json({ message: 'Conversation not found' });
  if (c.unreadSeller) { await Conversation.updateOne({ _id: c._id }, { $set: { unreadSeller: 0 } }); c.unreadSeller = 0; }
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
    const owner = await User.findById(req.user.id);
    await pushSellerMessage(owner, c, text, null);
    res.json({ conversation: { ...briefConv(c, true), messages: c.messages } });
  } catch (err) { res.status(500).json({ message: 'Could not send the reply.' }); }
});
// Business owner: send a photo or file
app.post('/api/conversations/:id/attach', authenticateToken, attachLimiter, runUpload, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
    const c = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: 'Conversation not found' });
    if (c.messages.length >= MAX_MSGS) return res.status(400).json({ message: 'This conversation is full.' });
    const owner = await User.findById(req.user.id);
    const att = await storeChatFile(c, req.file);
    await pushSellerMessage(owner, c, cleanMsg(req.body && req.body.text), att);
    res.json({ conversation: { ...briefConv(c, true), messages: c.messages } });
  } catch (err) { res.status(err.status || 500).json({ message: err.status ? err.message : 'Could not send the file.' }); }
});
// Business owner: call status and call messages
app.get('/api/conversations/:id/call', authenticateToken, callLimiter, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
    const c = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: 'Conversation not found' });
    res.json(callPoll(c, 'seller', Number(req.query.after) || 0));
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});
app.post('/api/conversations/:id/call/signal', authenticateToken, callLimiter, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
    const c = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!c) return res.status(404).json({ message: 'Conversation not found' });
    const owner = await User.findById(req.user.id);
    const r = await callSignal(c, 'seller', owner, req.body || {});
    res.status(r.code).json(r.body);
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});
app.delete('/api/conversations/:id', authenticateToken, async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  await Conversation.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ ok: true });
});


// ── GoldOffer Business Suite: authenticated seller tools + limited visitor interactions ──
const Visit = mongoose.model('GOVisit', new mongoose.Schema({
  sellerId: {type:mongoose.Schema.Types.ObjectId,required:true,index:true},
  kind: {type:String,enum:['view','offer','message','call'],required:true},
  offerId: mongoose.Schema.Types.ObjectId,
  visitor: String,
  createdAt: {type:Date,default:Date.now,expires:7776000}
}));
Visit.schema.index({sellerId:1,createdAt:-1});
const Appointment = mongoose.model('GOAppointment',new mongoose.Schema({
 sellerId:{type:mongoose.Schema.Types.ObjectId,index:true,required:true}, offerId:mongoose.Schema.Types.ObjectId,
 customer:{type:String,required:true,maxlength:80}, contact:{type:String,required:true,maxlength:140},
 startsAt:{type:Date,required:true},endsAt:Date,durationMin:Number,anonymized:Boolean,note:{type:String,maxlength:500},
 status:{type:String,enum:['Pending','Confirmed','Cancelled','Completed'],default:'Pending'},
 createdAt:{type:Date,default:Date.now}
}));
Appointment.schema.index({sellerId:1,startsAt:1},{unique:true,partialFilterExpression:{status:{$in:['Pending','Confirmed']}}});
const ShopSetting = mongoose.model('GOShopSetting',new mongoose.Schema({
 sellerId:{type:mongoose.Schema.Types.ObjectId,unique:true,required:true},
 stock: {type:Map,of:Number,default:{}},
 soldOut:{type:[String],default:[]},
 slotsEnabled:{type:Boolean,default:false},
 quickReplies:{type:[String],default:[]},
 announcementText:{type:String,default:''},
 faqItems:{type:[{question:String,answer:String,_id:false}],default:[]},
 customDomain:{type:String,default:''},
 customDomainStatus:{type:String,default:'not-configured'},
 updatedAt:{type:Date,default:Date.now}
}));
const Reminder = mongoose.model('GOReminder',new mongoose.Schema({
 sellerId:{type:mongoose.Schema.Types.ObjectId,index:true,required:true},
 text:{type:String,required:true,maxlength:250},due:{type:Date,default:Date.now},done:{type:Boolean,default:false},createdAt:{type:Date,default:Date.now}
}));
const Note = mongoose.model('GONote',new mongoose.Schema({
 sellerId:{type:mongoose.Schema.Types.ObjectId,index:true,required:true},
 text:{type:String,required:true,maxlength:1200},createdAt:{type:Date,default:Date.now}
}));
const customerId = req => crypto.createHmac('sha256',process.env.JWT_SECRET || 'goldoffer-local-only').update(new Date().toISOString().slice(0,10) + ':' + String(req.ip||'') + ':' + String(req.headers['user-agent']||'')).digest('hex').slice(0,16);
const suiteLimit = rateLimit({windowMs:60*1000,max:60,standardHeaders:'draft-7',legacyHeaders:false});
app.post('/api/storefront/:slug/track',suiteLimit,async(req,res)=>{
 try{
  const owner=await User.findOne({slug:req.params.slug,published:true}).select('_id');if(!owner)return res.sendStatus(404);
  const kind=String(req.body?.kind||'view');if(!['view','offer','message','call'].includes(kind))return res.sendStatus(400);
  const id=req.body?.offerId;
  if(id&&!mongoose.isValidObjectId(id))return res.sendStatus(400);
  // Deduplicate by visitor and page/action within a short window; no precise IP stored.
  const visitor=customerId(req);const since=new Date(Date.now()-10*60*1000);
  const query={sellerId:owner._id,kind,visitor,createdAt:{$gt:since}};
  if(id)query.offerId=id;
  if(!await Visit.exists(query))await Visit.create({sellerId:owner._id,kind,visitor,offerId:id||undefined});
  res.status(204).end();
 }catch(e){res.sendStatus(500)}
});
app.get('/api/business/overview',authenticateToken,async(req,res)=>{
 try{
 const sellerId=req.user.id, since=new Date(Date.now()-30*86400000);
 const [visits,bookings,notes,reminders,setting,orders,conversations]=await Promise.all([
 Visit.aggregate([{$match:{sellerId:new mongoose.Types.ObjectId(sellerId),createdAt:{$gte:since}}},{$group:{_id:'$kind',total:{$sum:1}}}]),
 Appointment.find({sellerId}).sort({startsAt:1}).limit(30).lean(),
 Note.find({sellerId}).sort({createdAt:-1}).limit(20).lean(),
 Reminder.find({sellerId}).sort({due:1}).limit(30).lean(),
 ShopSetting.findOne({sellerId}).lean(),
 Order.find({userId:sellerId}).sort({createdAt:-1}).limit(50).lean(),
 Conversation.countDocuments({userId:sellerId,unreadSeller:{$gt:0}})
 ]);
 res.set('Cache-Control','no-store').json({visits:Object.fromEntries(visits.map(v=>[v._id,v.total])),bookings,notes,reminders,setting:setting||{},orders,unreadConversations:conversations,turnConfigured:!!process.env.TURN_URL});
 }catch(e){res.status(500).json({message:'Could not load business data'})}
});
app.put('/api/business/settings',authenticateToken,async(req,res)=>{
 const b=req.body||{}, update={updatedAt:new Date()};
 if(typeof b.slotsEnabled==='boolean')update.slotsEnabled=b.slotsEnabled;
 if(Array.isArray(b.quickReplies))update.quickReplies=b.quickReplies.slice(0,12).map(x=>String(x).trim().slice(0,180)).filter(Boolean);
 if(typeof b.customDomain==='string'){
   const domain=b.customDomain.trim().toLowerCase();if(domain&&!/^(?=.{4,180}$)(?!-)[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(domain))return res.status(400).json({message:'Enter a valid hostname'});
   update.customDomain=domain;update.customDomainStatus=domain?'pending-dns':'not-configured';
 }
 try{const setting=await ShopSetting.findOneAndUpdate({sellerId:req.user.id},{$set:update}, {new:true,upsert:true,setDefaultsOnInsert:true});res.json({setting})}catch(e){res.status(500).json({message:'Could not save settings'})}
});
app.get('/api/business/quick-replies',authenticateToken,async(req,res)=>{
  const cfg=await ShopSetting.findOne({sellerId:req.user.id}).select('quickReplies').lean();
  res.json({quickReplies:cfg?.quickReplies||[]});
});
app.put('/api/business/stock/:id',authenticateToken,async(req,res)=>{
 try{if(!mongoose.isValidObjectId(req.params.id))return res.sendStatus(400);
 if(!await Offer.exists({_id:req.params.id,userId:req.user.id}))return res.sendStatus(404);
 const count=Number(req.body?.quantity);if(!Number.isSafeInteger(count)||count<0||count>1000000)return res.status(400).json({message:'Quantity must be between 0 and 1000000'});
 const setting=await ShopSetting.findOneAndUpdate({sellerId:req.user.id},{$set:{[`stock.${String(req.params.id)}`]:count,updatedAt:new Date()}},{new:true,upsert:true});res.json({quantity:count,setting:setting._id});
 }catch(e){res.status(500).json({message:'Could not update stock'})}
});
app.post('/api/business/notes',authenticateToken,async(req,res)=>{
 const text=String(req.body?.text||'').trim().slice(0,1200);if(!text)return res.sendStatus(400);
 const note=await Note.create({sellerId:req.user.id,text});res.status(201).json({note});
});
app.delete('/api/business/notes/:id',authenticateToken,async(req,res)=>{
 if(!mongoose.isValidObjectId(req.params.id))return res.sendStatus(400);
 await Note.deleteOne({_id:req.params.id,sellerId:req.user.id});res.json({ok:true});
});
app.post('/api/business/reminders',authenticateToken,async(req,res)=>{
 const text=String(req.body?.text||'').trim().slice(0,250),due=new Date(req.body?.due||Date.now());
 if(!text||!Number.isFinite(due.valueOf()))return res.sendStatus(400);
 const reminder=await Reminder.create({sellerId:req.user.id,text,due});res.status(201).json({reminder});
});
app.patch('/api/business/reminders/:id',authenticateToken,async(req,res)=>{
 if(!mongoose.isValidObjectId(req.params.id))return res.sendStatus(400);
 const row=await Reminder.findOneAndUpdate({_id:req.params.id,sellerId:req.user.id},{$set:{done:!!req.body?.done}},{new:true});return row?res.json({reminder:row}):res.sendStatus(404);
});
app.get('/api/business/export',authenticateToken,async(req,res)=>{
 try{const [offers,orders,appointments]=await Promise.all([Offer.find({userId:req.user.id}).select('title price description createdAt').lean(),Order.find({userId:req.user.id}).select('offerTitle customerName amount status createdAt').lean(),Appointment.find({sellerId:req.user.id}).select('customer contact startsAt status').lean()]);
 res.set('Content-Disposition','attachment; filename="goldoffer-data.json"');res.set('Cache-Control','no-store');res.json({exportedAt:new Date(),offers,orders,appointments});
 }catch(e){res.sendStatus(500)}
});

// ---------- GoldOffer Design Engine (shared by the server and the Studio editor) ----------
// goDesignCore() runs on the server AND (as text) inside the visitor's / editor's browser.
// The server re-validates every design with sanitizeDesign(); the browser copy only draws.
function goDesignCore() {
  const FONT_LIST = [
    ['inter', 'Inter', 'Inter:wght@400;600;800', 'Clean'],
    ['poppins', 'Poppins', 'Poppins:wght@400;600;800', 'Friendly'],
    ['montserrat', 'Montserrat', 'Montserrat:wght@400;600;800', 'Geometric'],
    ['raleway', 'Raleway', 'Raleway:wght@400;600;800', 'Elegant sans'],
    ['space', 'Space Grotesk', 'Space+Grotesk:wght@400;600;700', 'Techy'],
    ['playfair', 'Playfair Display', 'Playfair+Display:wght@500;800', 'Luxury serif'],
    ['dmserif', 'DM Serif Display', 'DM+Serif+Display', 'Magazine'],
    ['lora', 'Lora', 'Lora:wght@400;700', 'Book'],
    ['merri', 'Merriweather', 'Merriweather:wght@400;700', 'Classic serif'],
    ['oswald', 'Oswald', 'Oswald:wght@500;700', 'Condensed'],
    ['anton', 'Anton', 'Anton', 'Poster'],
    ['bebas', 'Bebas Neue', 'Bebas+Neue', 'Headline'],
    ['archivo', 'Archivo Black', 'Archivo+Black', 'Heavy'],
    ['orbitron', 'Orbitron', 'Orbitron:wght@500;800', 'Sci-fi'],
    ['righteous', 'Righteous', 'Righteous', 'Retro'],
    ['pacifico', 'Pacifico', 'Pacifico', 'Brush'],
    ['lobster', 'Lobster', 'Lobster', 'Bold script'],
    ['dancing', 'Dancing Script', 'Dancing+Script:wght@500;700', 'Handwriting'],
    ['caveat', 'Caveat', 'Caveat:wght@500;700', 'Marker'],
    ['marker', 'Permanent Marker', 'Permanent+Marker', 'Graffiti'],
    ['jetbrains', 'JetBrains Mono', 'JetBrains+Mono:wght@400;700', 'Code'],
    ['comfortaa', 'Comfortaa', 'Comfortaa:wght@500;700', 'Rounded']
  ];
  const FONTS = {}; FONT_LIST.forEach(f => { FONTS[f[0]] = { name: f[1], gf: f[2], tag: f[3] }; });
  const fam = (k) => FONTS[k] ? "'" + FONTS[k].name + "',sans-serif" : null;

  // ----- validators: each returns the cleaned value or null -----
  const C_HEX = /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
  const C_RGB = /^rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*(?:,\s*(?:0|1|0?\.\d{1,3})\s*)?\)$/i;
  const C_NAME = /^(?:transparent|white|black|red|blue|green|yellow|orange|purple|pink|gray|grey|gold|silver|cyan|magenta|currentcolor)$/i;
  const color = (v) => { v = String(v).trim(); return (C_HEX.test(v) || C_RGB.test(v) || C_NAME.test(v)) ? v : null; };
  const BAD = /url|expression|javascript|import|attr\(|var\(|env\(|\\|;|\{|\}|<|>|@|\/\*|"|'/i;
  const gradient = (v) => {
    v = String(v).trim();
    if (v.length > 320 || BAD.test(v) || !/^(?:repeating-)?(?:linear|radial|conic)-gradient\([#a-z0-9%.,()\s-]+\)$/i.test(v)) return null;
    let depth = 0; for (const ch of v) { if (ch === '(') depth++; if (ch === ')') depth--; if (depth < 0) return null; }
    return depth === 0 ? v : null;
  };
  const LEN1 = /^-?\d{1,4}(?:\.\d{1,2})?(?:px|%|em|rem|vw|vh)?$/;
  const len = (v) => { v = String(v).trim(); return (LEN1.test(v) || v === 'auto') ? v : null; };
  const lens = (v, max) => { const p = String(v).trim().split(/\s+/); if (p.length < 1 || p.length > (max || 4)) return null; const o = p.map(len); return o.every(x => x !== null) ? o.join(' ') : null; };
  const num = (v, lo, hi) => { const n = Number(v); return (Number.isFinite(n) && n >= lo && n <= hi) ? String(Math.round(n * 1000) / 1000) : null; };
  const oneOf = (list) => (v) => list.includes(String(v)) ? String(v) : null;
  const shadow = (v) => { v = String(v).trim(); if (v === 'none') return v; return (v.length <= 260 && !BAD.test(v) && /^[#a-z0-9%.,()\s-]+$/i.test(v) && /\d/.test(v)) ? v : null; };
  const filt = (v) => { v = String(v).trim(); return /^(?:(?:blur|brightness|contrast|saturate|grayscale|hue-rotate|sepia|invert)\(-?\d{1,3}(?:\.\d{1,2})?(?:px|deg|%)?\)\s*){1,5}$/i.test(v) ? v : null; };
  const ANIMS = ['none', 'float', 'pulse', 'glow', 'shake', 'spin', 'wiggle', 'fadein', 'rise', 'rainbow'];
  // property table. 'k' is also the CSS property name (except the pseudo-props handled in decl()).
  const PROPS = {
    'color': color, 'background-color': color, 'border-color': color, 'outline-color': color,
    'background-image': (v) => v === 'none' ? 'none' : gradient(v),
    'gradText': gradient, 'bgImg': (v) => /^https:\/\/[A-Za-z0-9._~:\/?#@!$&*+,;=%-]{4,500}$/.test(String(v)) ? String(v) : null,
    'font-family': (v) => FONTS[v] ? v : null,
    'font-size': (v) => { v = String(v); return /^\d{1,3}(?:\.\d{1,2})?(?:px|em|rem|%|vw)$/.test(v) ? v : null; },
    'font-weight': oneOf(['100', '200', '300', '400', '500', '600', '700', '800', '900', 'normal', 'bold']),
    'font-style': oneOf(['normal', 'italic']),
    'text-decoration': oneOf(['none', 'underline', 'line-through', 'overline']),
    'text-transform': oneOf(['none', 'uppercase', 'lowercase', 'capitalize']),
    'text-align': oneOf(['left', 'center', 'right', 'justify']),
    'letter-spacing': (v) => /^-?\d{1,2}(?:\.\d{1,2})?(?:px|em)$/.test(String(v)) ? String(v) : null,
    'line-height': (v) => /^\d(?:\.\d{1,2})?$/.test(String(v)) || /^\d{1,3}(?:\.\d{1,2})?(?:px|em|%)$/.test(String(v)) ? String(v) : null,
    'text-shadow': shadow, 'box-shadow': shadow,
    'opacity': (v) => num(v, 0, 1),
    'border-radius': (v) => lens(v, 4),
    'border-width': (v) => lens(v, 4),
    'border-style': oneOf(['none', 'solid', 'dashed', 'dotted', 'double']),
    'padding': (v) => lens(v, 4), 'margin': (v) => lens(v, 4),
    'width': len, 'height': len, 'max-width': len, 'min-height': len, 'min-width': len,
    'gap': len,
    'display': oneOf(['none', 'block', 'flex', 'grid', 'inline-block', 'inline-flex']),
    'flex-direction': oneOf(['row', 'column', 'row-reverse', 'column-reverse']),
    'justify-content': oneOf(['flex-start', 'center', 'flex-end', 'space-between', 'space-around']),
    'align-items': oneOf(['flex-start', 'center', 'flex-end', 'stretch']),
    'translate': (v) => lens(v, 2),
    'rotate': (v) => /^-?\d{1,3}(?:\.\d{1,2})?deg$/.test(String(v)) ? String(v) : null,
    'scale': (v) => num(v, 0.1, 5),
    'filter': filt, 'backdrop-filter': filt,
    'mix-blend-mode': oneOf(['normal', 'multiply', 'screen', 'overlay', 'difference', 'soft-light', 'hard-light', 'lighten', 'darken']),
    'z-index': (v) => /^-?\d{1,3}$/.test(String(v)) ? String(v) : null,
    'overflow': oneOf(['hidden', 'visible']),
    'object-fit': oneOf(['cover', 'contain', 'fill']),
    'cursor': oneOf(['pointer', 'default', 'crosshair', 'grab', 'zoom-in', 'not-allowed']),
    'order': (v) => /^-?\d{1,2}$/.test(String(v)) ? String(v) : null,
    'anim': oneOf(ANIMS)
  };
  const PROP_NAMES = Object.keys(PROPS);
  const clean = (style) => {
    const out = {}; let n = 0;
    if (!style || typeof style !== 'object') return out;
    for (const k of Object.keys(style)) {
      if (n >= 30) break;
      if (!Object.prototype.hasOwnProperty.call(PROPS, k)) continue;
      const v = PROPS[k](style[k]);
      if (v !== null && v !== undefined) { out[k] = v; n++; }
    }
    return out;
  };
  // style object -> "a:b!important;..."
  const decl = (st) => {
    let o = '';
    for (const k of Object.keys(st || {})) {
      const v = st[k]; if (!PROPS[k] || PROPS[k](v) === null) continue;
      if (k === 'font-family') o += 'font-family:' + fam(v) + '!important;';
      else if (k === 'gradText') o += 'background-image:' + v + '!important;-webkit-background-clip:text!important;background-clip:text!important;-webkit-text-fill-color:transparent!important;color:transparent!important;';
      else if (k === 'bgImg') o += 'background-image:url("' + v + '")!important;background-size:cover!important;background-position:center!important;';
      else if (k === 'anim') { if (v !== 'none') o += 'animation:go-a-' + v + ' ' + (v === 'spin' ? '8s linear' : v === 'rainbow' ? '6s linear' : v === 'fadein' || v === 'rise' ? '1.1s ease-out both' : '3s ease-in-out') + (v === 'fadein' || v === 'rise' ? '' : ' infinite') + '!important;'; }
      else o += k + ':' + v + '!important;';
    }
    return o;
  };
  const SEL_OK = /^(?:[a-z][a-z0-9]*|\.[A-Za-z_][\w-]*|#[A-Za-z_][\w-]*|:nth-child\(\d{1,3}\)|:nth-of-type\(\d{1,3}\)|\s*>\s*|\s+)+$/;
  const selOk = (s) => typeof s === 'string' && s.length > 0 && s.length <= 240 && SEL_OK.test(s) && !/^\s*(?:html|body)\b/i.test(s) && !/\.go-(?:st|fr)/.test(s);
  const rulesCss = (map, pre) => {
    let o = '';
    for (const sel of Object.keys(map || {})) { if (!selOk(sel)) continue; const d = decl(map[sel]); if (d) o += pre + sel + '{' + d + '}\n'; }
    return o;
  };
  const luminance = (c) => {
    let h = String(c).trim(); let r = 255, g = 255, b = 255;
    const m = h.match(/^#([0-9a-f]{3,8})$/i);
    if (m) { let x = m[1]; if (x.length < 6) x = x.split('').map(ch => ch + ch).join(''); r = parseInt(x.slice(0, 2), 16); g = parseInt(x.slice(2, 4), 16); b = parseInt(x.slice(4, 6), 16); }
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255;
  };
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));
  const idOk = (id) => /^[a-z0-9]{4,12}$/.test(String(id));
  const hrefOk = (h) => { h = String(h || ''); return /^(?:https:\/\/[^\s"'<>\\]{3,400}|\/[A-Za-z0-9\/_\-?=&#.%]{0,300}|tel:\+?[\d\s()-]{4,30}|mailto:[^\s"'<>\\]{3,120}|#[\w-]{0,60})$/.test(h) ? h : ''; };
  const FX = ['none', 'grain', 'vignette', 'scanlines', 'grid', 'glow', 'aurora', 'snow', 'confetti', 'stars', 'bubbles'];

  const KEYFRAMES = '@keyframes go-a-float{0%,100%{transform:translateY(0)}50%{transform:translateY(-12px)}}@keyframes go-a-pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.07)}}@keyframes go-a-glow{0%,100%{filter:drop-shadow(0 0 0 transparent)}50%{filter:drop-shadow(0 0 14px currentColor)}}@keyframes go-a-shake{0%,100%{transform:translateX(0)}20%,60%{transform:translateX(-5px)}40%,80%{transform:translateX(5px)}}@keyframes go-a-spin{to{transform:rotate(360deg)}}@keyframes go-a-wiggle{0%,100%{transform:rotate(-3deg)}50%{transform:rotate(3deg)}}@keyframes go-a-fadein{from{opacity:0}to{opacity:1}}@keyframes go-a-rise{from{opacity:0;transform:translateY(26px)}to{opacity:1;transform:none}}@keyframes go-a-rainbow{to{filter:hue-rotate(360deg)}}';

  function fxCss(fx) {
    switch (fx) {
      case 'grain': return 'body::after{content:"";position:fixed;inset:0;z-index:2147483000;pointer-events:none;opacity:.09;background-image:url("data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 width=%27160%27 height=%27160%27%3E%3Cfilter id=%27n%27%3E%3CfeTurbulence type=%27fractalNoise%27 baseFrequency=%27.8%27 numOctaves=%272%27/%3E%3C/filter%3E%3Crect width=%27100%25%27 height=%27100%25%27 filter=%27url(%23n)%27/%3E%3C/svg%3E")}';
      case 'vignette': return 'body::after{content:"";position:fixed;inset:0;z-index:2147483000;pointer-events:none;background:radial-gradient(ellipse at center,transparent 55%,rgba(0,0,0,.55) 100%)}';
      case 'scanlines': return 'body::after{content:"";position:fixed;inset:0;z-index:2147483000;pointer-events:none;opacity:.35;background:repeating-linear-gradient(0deg,rgba(0,0,0,.28) 0,rgba(0,0,0,.28) 1px,transparent 1px,transparent 3px)}';
      case 'grid': return 'body::after{content:"";position:fixed;inset:0;z-index:2147483000;pointer-events:none;opacity:.12;background-image:linear-gradient(var(--a) 1px,transparent 1px),linear-gradient(90deg,var(--a) 1px,transparent 1px);background-size:46px 46px}';
      case 'glow': return 'body::after{content:"";position:fixed;inset:-20%;z-index:2147483000;pointer-events:none;opacity:.22;background:radial-gradient(circle at 20% 15%,var(--a),transparent 38%),radial-gradient(circle at 85% 80%,var(--b),transparent 40%)}';
      case 'aurora': return 'body::after{content:"";position:fixed;inset:-30%;z-index:2147483000;pointer-events:none;opacity:.25;mix-blend-mode:screen;background:conic-gradient(from 0deg at 50% 50%,var(--a),var(--b),#00e5ff,#b300ff,var(--a));filter:blur(90px);animation:go-a-spin 28s linear infinite}';
      default: return '';
    }
  }

  function css(d, page) {
    d = d || {}; const v = d.v || {}; let o = KEYFRAMES;
    const root = [];
    if (color(v.accent || '')) { root.push('--a:' + v.accent, '--on:' + (luminance(v.accent) > 0.6 ? '#111111' : '#ffffff')); }
    if (color(v.accent2 || '')) root.push('--b:' + v.accent2);
    if (color(v.bg || '')) root.push('--bg:' + v.bg);
    if (color(v.panel || '')) root.push('--panel:' + v.panel);
    if (root.length) o += ':root{' + root.map(x => x + '!important').join(';') + '}\n';
    let b = '';
    if (FONTS[v.font]) b += 'font-family:' + fam(v.font) + '!important;';
    if (color(v.text || '')) b += 'color:' + v.text + '!important;';
    if (v.bgGrad && gradient(v.bgGrad)) b += 'background:' + v.bgGrad + ' fixed!important;';
    else if (v.bgImg && PROPS.bgImg(v.bgImg)) b += 'background:url("' + v.bgImg + '") center/cover fixed!important;';
    else if (color(v.bg || '')) b += 'background:' + v.bg + '!important;';
    if (b) o += 'html body{' + b + '}\n';
    if (FONTS[v.headFont]) o += 'html body h1,html body h2,html body h3,html body h4,html body .bar b{font-family:' + fam(v.headFont) + '!important}\n';
    const sc = Number(v.scale); if (sc && sc >= 0.7 && sc <= 1.6 && sc !== 1) o += 'html{font-size:' + Math.round(sc * 16 * 100) / 100 + 'px!important}\n';
    const rad = Number(v.radius); if (v.radius !== undefined && v.radius !== '' && rad >= 0 && rad <= 60) o += 'html body .glass,html body .card,html body .tile,html body .feature-card,html body .abtn,html body .btn,html body button,html body input,html body textarea,html body select,html body .cine-visual,html body .main-screen{border-radius:' + rad + 'px!important}\n';
    if (v.noReveal) o += 'html body .rv,html body .copyline,html body .reveal-band{opacity:1!important;transform:none!important;transition:none!important}\n';
    if (v.stickyBar === false) o += 'html body .bar{position:absolute!important}\n';
    o += fxCss(v.fx);
    o += rulesCss(d.g, 'html body ');
    if (page && d.p) o += rulesCss(d.p[page], 'html body ');
    // free-floating elements
    o += '.go-free{position:absolute;left:0;top:0;width:100%;height:0;z-index:60;pointer-events:none}.go-fi{position:absolute;pointer-events:auto;box-sizing:border-box;margin:0;line-height:1.25;overflow-wrap:anywhere;font-family:inherit}.go-ft{color:#fff;font-size:28px;font-weight:700}.go-fb{display:flex;align-items:center;justify-content:center;text-decoration:none;font-weight:700;font-size:16px;color:var(--on);background:var(--a);border-radius:999px;padding:10px 18px;cursor:pointer}.go-fm{object-fit:cover;border-radius:14px;display:block}.go-fs{background:var(--a);border-radius:16px;opacity:.9}.go-fi.go-hid{display:none}\n';
    const fr = (page && d.f && d.f[page]) || [];
    const mf = (d.mf && page && d.mf[page]) || {};
    let base = '', mob = '';
    for (const it of fr) {
      if (!it || !idOk(it.id)) continue;
      const x = Number(it.x) || 0, y = Number(it.y) || 0, w = Number(it.w) || 20, h = Number(it.h) || 0;
      base += '#gf-' + it.id + '{left:' + x + '%;top:' + y + 'px;width:' + w + '%;' + (h ? 'height:' + h + 'px;' : '') + (it.r ? 'rotate:' + Number(it.r) + 'deg;' : '') + decl(it.s) + '}\n';
      const m = mf[it.id];
      if (m) mob += '#gf-' + it.id + '{' + (m.x !== undefined ? 'left:' + Number(m.x) + '%!important;' : '') + (m.y !== undefined ? 'top:' + Number(m.y) + 'px!important;' : '') + (m.w !== undefined ? 'width:' + Number(m.w) + '%!important;' : '') + (m.h !== undefined ? 'height:' + Number(m.h) + 'px!important;' : '') + (m.hide ? 'display:none!important;' : '') + (m.s ? decl(m.s) : '') + '}\n';
    }
    o += base;
    const md = d.m || {};
    let mm = rulesCss(md.g, 'html body ') + (page && md.p ? rulesCss(md.p[page], 'html body ') : '') + mob;
    if (mm) o += '@media(max-width:700px){\n' + mm + '}\n';
    return o;
  }

  function freeHtml(d, page) {
    const fr = (d && d.f && d.f[page]) || []; if (!fr.length) return '<div class="go-free" id="go-free"></div>';
    let o = '<div class="go-free" id="go-free">';
    for (const it of fr) {
      if (!it || !idOk(it.id)) continue;
      const id = 'gf-' + it.id; const t = esc(String(it.text || '').slice(0, 600)).replace(/\n/g, '<br>');
      if (it.k === 'img') { const src = PROPS.bgImg(it.src || ''); o += src ? '<img class="go-fi go-fm" id="' + id + '" src="' + esc(src) + '" alt="' + esc(it.text || '') + '" loading="lazy">' : ''; }
      else if (it.k === 'btn') { const hr = hrefOk(it.href); o += '<a class="go-fi go-fb" id="' + id + '"' + (hr ? ' href="' + esc(hr) + '"' + (/^https:/.test(hr) ? ' target="_blank" rel="noopener"' : '') : '') + '>' + t + '</a>'; }
      else if (it.k === 'shape') o += '<div class="go-fi go-fs" id="' + id + '"></div>';
      else o += '<div class="go-fi go-ft" id="' + id + '">' + t + '</div>';
    }
    return o + '</div>';
  }
  function fontLinks(d) {
    const used = new Set(); const v = (d && d.v) || {};
    if (FONTS[v.font]) used.add(v.font); if (FONTS[v.headFont]) used.add(v.headFont);
    const scan = (map) => { for (const s of Object.keys(map || {})) { const f = map[s] && map[s]['font-family']; if (FONTS[f]) used.add(f); } };
    scan(d && d.g); scan(d && d.m && d.m.g);
    for (const p of Object.keys((d && d.p) || {})) scan(d.p[p]);
    for (const p of Object.keys((d && d.m && d.m.p) || {})) scan(d.m.p[p]);
    for (const p of Object.keys((d && d.f) || {})) for (const it of (d.f[p] || [])) { const f = it && it.s && it.s['font-family']; if (FONTS[f]) used.add(f); }
    return [...used].map(k => FONTS[k].gf);
  }
  return { FONTS, FONT_LIST, PROPS, PROP_NAMES, clean, decl, css, freeHtml, fontLinks, selOk, color, gradient, idOk, hrefOk, FX, ANIMS, esc, luminance };
}
const GD = goDesignCore();

// Strict server-side clean-up of a design coming from the browser. Anything unknown is dropped.
function sanitizeDesign(raw) {
  const d = { v: {}, g: {}, p: {}, m: { g: {}, p: {} }, t: {}, im: {}, f: {}, mf: {} };
  if (!raw || typeof raw !== 'object') return d;
  const PAGES = ['home', 'offer', 'profile', 'favorites', 'messages', 'track'];
  const v = raw.v && typeof raw.v === 'object' ? raw.v : {};
  ['accent', 'accent2', 'bg', 'panel', 'text'].forEach(k => { if (v[k] && GD.color(v[k])) d.v[k] = String(v[k]).trim(); });
  if (v.font && GD.FONTS[v.font]) d.v.font = v.font;
  if (v.headFont && GD.FONTS[v.headFont]) d.v.headFont = v.headFont;
  if (v.bgGrad && GD.gradient(v.bgGrad)) d.v.bgGrad = String(v.bgGrad).trim();
  if (v.bgImg && GD.PROPS.bgImg(v.bgImg)) d.v.bgImg = String(v.bgImg);
  if (Number.isFinite(Number(v.scale)) && Number(v.scale) >= 0.7 && Number(v.scale) <= 1.6) d.v.scale = Number(v.scale);
  if (v.radius !== undefined && v.radius !== '' && Number(v.radius) >= 0 && Number(v.radius) <= 60) d.v.radius = Number(v.radius);
  if (GD.FX.includes(v.fx)) d.v.fx = v.fx;
  if (v.noReveal === true) d.v.noReveal = true;
  if (v.stickyBar === false) d.v.stickyBar = false;
  if (v.glowCursor === true) d.v.glowCursor = true;
  if (v.progress === true) d.v.progress = true;
  const rules = (map, cap) => {
    const out = {}; let n = 0;
    if (!map || typeof map !== 'object') return out;
    for (const sel of Object.keys(map)) {
      if (n >= (cap || 300)) break;
      if (!GD.selOk(sel)) continue;
      const st = GD.clean(map[sel]); if (Object.keys(st).length) { out[sel] = st; n++; }
    }
    return out;
  };
  d.g = rules(raw.g);
  if (raw.m && typeof raw.m === 'object') d.m.g = rules(raw.m.g);
  const texts = (map) => {
    const out = {}; let n = 0; if (!map || typeof map !== 'object') return out;
    for (const sel of Object.keys(map)) { if (n >= 150) break; if (!GD.selOk(sel)) continue; const t = String(map[sel] == null ? '' : map[sel]).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').slice(0, 400); out[sel] = t; n++; }
    return out;
  };
  const imgs = (map) => {
    const out = {}; let n = 0; if (!map || typeof map !== 'object') return out;
    for (const sel of Object.keys(map)) { if (n >= 60) break; if (!GD.selOk(sel)) continue; const u = GD.PROPS.bgImg(map[sel]); if (u) { out[sel] = u; n++; } }
    return out;
  };
  PAGES.forEach(pg => {
    if (raw.p && raw.p[pg]) { const r = rules(raw.p[pg]); if (Object.keys(r).length) d.p[pg] = r; }
    if (raw.m && raw.m.p && raw.m.p[pg]) { const r = rules(raw.m.p[pg]); if (Object.keys(r).length) d.m.p[pg] = r; }
    if (raw.t && raw.t[pg]) { const r = texts(raw.t[pg]); if (Object.keys(r).length) d.t[pg] = r; }
    if (raw.im && raw.im[pg]) { const r = imgs(raw.im[pg]); if (Object.keys(r).length) d.im[pg] = r; }
    if (Array.isArray(raw.f && raw.f[pg])) {
      const items = []; const seen = new Set();
      for (const it of raw.f[pg].slice(0, 40)) {
        if (!it || typeof it !== 'object' || !GD.idOk(it.id) || seen.has(it.id)) continue; seen.add(it.id);
        if (!['text', 'btn', 'img', 'shape'].includes(it.k)) continue;
        const o = { id: it.id, k: it.k, x: Math.max(-50, Math.min(150, Number(it.x) || 0)), y: Math.max(-200, Math.min(20000, Number(it.y) || 0)), w: Math.max(1, Math.min(150, Number(it.w) || 20)), h: Math.max(0, Math.min(3000, Number(it.h) || 0)) };
        if (Number(it.r)) o.r = Math.max(-360, Math.min(360, Number(it.r)));
        if (it.text) o.text = String(it.text).slice(0, 600);
        if (it.k === 'img') { const u = GD.PROPS.bgImg(it.src || ''); if (!u) continue; o.src = u; }
        if (it.k === 'btn') { const h = GD.hrefOk(it.href); if (h) o.href = h; }
        o.s = GD.clean(it.s);
        items.push(o);
      }
      if (items.length) d.f[pg] = items;
    }
    if (raw.mf && raw.mf[pg] && typeof raw.mf[pg] === 'object') {
      const out = {};
      for (const id of Object.keys(raw.mf[pg]).slice(0, 40)) {
        if (!GD.idOk(id)) continue; const m = raw.mf[pg][id] || {}; const o = {};
        ['x', 'w'].forEach(k => { if (Number.isFinite(Number(m[k])) && m[k] !== null && m[k] !== '') o[k] = Math.max(-50, Math.min(150, Number(m[k]))); });
        ['y', 'h'].forEach(k => { if (Number.isFinite(Number(m[k])) && m[k] !== null && m[k] !== '') o[k] = Math.max(0, Math.min(20000, Number(m[k]))); });
        if (m.hide === true) o.hide = true;
        if (Object.keys(o).length) out[id] = o;
      }
      if (Object.keys(out).length) d.mf[pg] = out;
    }
  });
  if (JSON.stringify(d).length > 400000) return { v: {}, g: {}, p: {}, m: { g: {}, p: {} }, t: {}, im: {}, f: {}, mf: {} };
  return d;
}
const designIsEmpty = (d) => !d || (!Object.keys(d.v || {}).length && !Object.keys(d.g || {}).length && !Object.keys(d.p || {}).length && !Object.keys((d.m && d.m.g) || {}).length && !Object.keys((d.m && d.m.p) || {}).length && !Object.keys(d.t || {}).length && !Object.keys(d.im || {}).length && !Object.keys(d.f || {}).length);

// Runs in every visitor's browser (sent as text): applies text/image overrides and visual effects.
function goApplyClient() {
  var node = document.getElementById('go-design'); var D = {};
  try { D = JSON.parse(node ? node.textContent : '{}') || {}; } catch (e) { D = {}; }
  var page = document.body.getAttribute('data-page') || 'home';
  var orig = {}; var fxNodes = [];
  function each(map, fn) { Object.keys(map || {}).forEach(function (sel) { var els; try { els = document.querySelectorAll(sel); } catch (e) { return; } for (var i = 0; i < els.length; i++) fn(els[i], map[sel], sel); }); }
  function apply(d) {
    D = d || D;
    each((D.t || {})[page], function (el, t, sel) { if (el.children.length === 0) { if (!(sel in orig)) orig[sel] = el.textContent; el.textContent = t; } });
    each((D.im || {})[page], function (el, u) { if (el.tagName === 'IMG') { el.removeAttribute('srcset'); el.src = u; } else el.style.backgroundImage = 'url("' + u + '")'; });
    var v = D.v || {};
    fxNodes.forEach(function (n) { n.remove(); }); fxNodes = [];
    var fx = v.fx;
    if (['snow', 'confetti', 'stars', 'bubbles'].indexOf(fx) >= 0) {
      var box = document.createElement('div'); box.setAttribute('aria-hidden', 'true'); box.style.cssText = 'position:fixed;inset:0;pointer-events:none;overflow:hidden;z-index:2147482000';
      var cols = ['#ffd700', '#ff4d6d', '#4dd2ff', '#7cff6b', '#b388ff'];
      for (var i = 0; i < 34; i++) {
        var s = document.createElement('i'); var sz = fx === 'stars' ? 2 + Math.random() * 3 : fx === 'bubbles' ? 10 + Math.random() * 30 : 5 + Math.random() * 7;
        s.style.cssText = 'position:absolute;left:' + Math.random() * 100 + '%;top:' + (fx === 'bubbles' ? '105%' : '-5%') + ';width:' + sz + 'px;height:' + (fx === 'confetti' ? sz * 1.6 : sz) + 'px;border-radius:' + (fx === 'confetti' ? '2px' : '50%') + ';background:' + (fx === 'snow' ? '#fff' : fx === 'stars' ? '#fff' : fx === 'bubbles' ? 'rgba(255,255,255,.14)' : cols[i % 5]) + ';' + (fx === 'bubbles' ? 'border:1px solid rgba(255,255,255,.35);' : '') + 'opacity:' + (fx === 'stars' ? .85 : .75) + ';animation:' + (fx === 'stars' ? 'goTw ' + (2 + Math.random() * 3) + 's ease-in-out infinite' : (fx === 'bubbles' ? 'goUp ' : 'goFall ') + (7 + Math.random() * 9) + 's linear infinite') + ';animation-delay:-' + Math.random() * 14 + 's';
        if (fx === 'stars') s.style.top = Math.random() * 100 + '%';
        box.appendChild(s);
      }
      var st = document.createElement('style'); st.textContent = '@keyframes goFall{to{transform:translateY(110vh) rotate(360deg)}}@keyframes goUp{to{transform:translateY(-115vh)}}@keyframes goTw{0%,100%{opacity:.15}50%{opacity:1}}';
      document.body.appendChild(st); document.body.appendChild(box); fxNodes.push(st, box);
    }
    if (v.progress) { var bar = document.createElement('div'); bar.style.cssText = 'position:fixed;left:0;top:0;height:3px;width:0;background:var(--a);z-index:2147483001'; document.body.appendChild(bar); fxNodes.push(bar); window.addEventListener('scroll', function () { var h = document.documentElement; bar.style.width = (h.scrollTop / Math.max(1, h.scrollHeight - h.clientHeight) * 100) + '%'; }, { passive: true }); }
    if (v.glowCursor && matchMedia('(pointer:fine)').matches) { var g = document.createElement('div'); g.style.cssText = 'position:fixed;left:0;top:0;width:260px;height:260px;margin:-130px 0 0 -130px;border-radius:50%;pointer-events:none;z-index:2147482500;background:radial-gradient(circle,var(--a),transparent 65%);opacity:.18;mix-blend-mode:screen;transition:transform .08s'; document.body.appendChild(g); fxNodes.push(g); window.addEventListener('pointermove', function (e) { g.style.transform = 'translate(' + e.clientX + 'px,' + e.clientY + 'px)'; }, { passive: true }); }
  }
  window.__goApply = apply;
  apply(D);
}

// Runs ONLY inside the Studio editor frame (never for visitors): select, drag, resize, edit text.
function goStudioClient(GDtxt) {
  var GDc = GDtxt();
  var page = document.body.getAttribute('data-page') || 'home';
  var parentWin = window.parent; var selEl = null; var box, hov;
  var STATE = ['in-view', 'on', 'active', 'open', 'show', 'visible', 'rv', 'is-active', 'is-open'];
  function post(m) { m.go = 1; parentWin.postMessage(m, '*'); }
  var st = document.createElement('style'); st.textContent = '.go-st-box{touch-action:none}html.go-st .go-fi{touch-action:none;-webkit-user-select:none;user-select:none}html.go-st{-webkit-touch-callout:none}@media(pointer:coarse){.go-st-h{width:30px!important;height:30px!important;right:-15px!important;bottom:-15px!important}}.go-st-box{position:absolute;z-index:2147483600;pointer-events:none;outline:2px solid #5b8cff;box-shadow:0 0 0 1px #fff8 inset}.go-st-h{position:absolute;right:-7px;bottom:-7px;width:13px;height:13px;border-radius:3px;background:#5b8cff;border:2px solid #fff;pointer-events:auto;cursor:nwse-resize}.go-st-hov{position:absolute;z-index:2147483500;pointer-events:none;outline:1px dashed #5b8cffaa}.go-st-tag{position:absolute;left:-2px;top:-22px;background:#5b8cff;color:#fff;font:600 11px system-ui;padding:2px 7px;border-radius:5px;white-space:nowrap}html.go-st *{cursor:default!important;animation-play-state:running}html.go-st [contenteditable=true]{cursor:text!important;outline:2px solid #ffcf00!important}';
  document.head.appendChild(st); document.documentElement.classList.add('go-st');
  box = document.createElement('div'); box.className = 'go-st-box'; box.style.display = 'none'; box.innerHTML = '<span class="go-st-tag"></span><i class="go-st-h"></i>'; document.body.appendChild(box);
  hov = document.createElement('div'); hov.className = 'go-st-hov'; hov.style.display = 'none'; document.body.appendChild(hov);
  var origText = {};
  function cls(el) { return [].filter.call(el.classList, function (c) { return /^[A-Za-z_][\w-]*$/.test(c) && STATE.indexOf(c) < 0 && c.indexOf('go-') !== 0; }); }
  function selOf(el) {
    if (el.id && /^[A-Za-z_][\w-]*$/.test(el.id) && document.querySelectorAll('#' + el.id).length === 1) return '#' + el.id;
    var c = cls(el), tag = el.tagName.toLowerCase();
    for (var i = 0; i < c.length; i++) { var s = tag + '.' + c[i]; if (document.querySelectorAll(s).length === 1) return s; }
    var parts = [], n = el;
    while (n && n !== document.body && n.parentElement) {
      var p = n.parentElement, idx = [].indexOf.call(p.children, n) + 1, seg = n.tagName.toLowerCase(), c1 = cls(n)[0];
      if (c1) seg += '.' + c1; seg += ':nth-child(' + idx + ')'; parts.unshift(seg); n = p;
      if (n.id && /^[A-Za-z_][\w-]*$/.test(n.id)) { parts.unshift('#' + n.id); break; }
    }
    var sel = parts.join(' > '); try { if (document.querySelector(sel) === el) return sel; } catch (e) {}
    return null;
  }
  function simSel(el) { var c = cls(el)[0]; return c ? el.tagName.toLowerCase() + '.' + c : null; }
  function place(b, el, tag) { var r = el.getBoundingClientRect(); b.style.display = 'block'; b.style.left = (r.left + scrollX) + 'px'; b.style.top = (r.top + scrollY) + 'px'; b.style.width = r.width + 'px'; b.style.height = r.height + 'px'; if (tag !== undefined) b.firstChild.textContent = tag; }
  function info(el) {
    var cs = getComputedStyle(el), fr = el.closest('.go-fi');
    var o = { t: 'select', sel: fr ? null : selOf(el), sim: fr ? null : simSel(el), free: fr ? fr.id.replace('gf-', '') : null, tag: el.tagName.toLowerCase(), text: el.children.length === 0 && !/^(IMG|VIDEO|INPUT|IFRAME)$/.test(el.tagName), img: el.tagName === 'IMG', cs: { color: cs.color, bg: cs.backgroundColor, size: parseFloat(cs.fontSize), weight: cs.fontWeight, family: cs.fontFamily, radius: parseFloat(cs.borderTopLeftRadius) || 0, opacity: cs.opacity, align: cs.textAlign, ls: parseFloat(cs.letterSpacing) || 0, lh: cs.lineHeight, w: Math.round(el.getBoundingClientRect().width), h: Math.round(el.getBoundingClientRect().height) }, label: (el.tagName.toLowerCase() + (cls(el)[0] ? '.' + cls(el)[0] : '')) };
    if (fr) { var it = ((GDc._D && GDc._D.f && GDc._D.f[page]) || []).filter(function (x) { return x.id === o.free; })[0]; o.freeItem = it || null; }
    return o;
  }
  function select(el) { if (selEl && selEl.style) selEl.style.removeProperty('touch-action'); if (!el || el === document.body || el === document.documentElement) { selEl = null; box.style.display = 'none'; post({ t: 'select', sel: null }); return; } selEl = el; try { el.style.setProperty('touch-action', 'none'); } catch (e0) {} var i = info(el); place(box, el, i.label); post(i); }
  document.addEventListener('mousemove', function (e) { var el = e.target; if (el.closest && el.closest('.go-st-box')) return; if (el === document.body || el === document.documentElement || el === selEl) { hov.style.display = 'none'; return; } place(hov, el); }, true);
  document.addEventListener('click', function (e) { if (e.target.classList && e.target.classList.contains('go-st-h')) return; e.preventDefault(); e.stopPropagation(); if (e.detail > 1) return; select(e.target.closest('.go-fi') || e.target); }, true);
  document.addEventListener('submit', function (e) { e.preventDefault(); }, true);
  var drag = null, lastFree = null;
  document.addEventListener('pointerdown', function (e) {
    if (e.button !== 0) return; var el = e.target;
    if (el.classList && el.classList.contains('go-st-h')) { if (!selEl) return; var r0 = selEl.getBoundingClientRect(); drag = { mode: 'size', x: e.clientX, y: e.clientY, w: r0.width, h: r0.height, id: e.pointerId, tgt: el }; try { el.setPointerCapture(e.pointerId); } catch (e2) {} e.preventDefault(); return; }
    if (el.isContentEditable) return;
    var t = el.closest('.go-fi') || el; if (t === document.body || t === document.documentElement) return;
    var wasSel = (t === selEl);
    if (t !== selEl) select(t);
    if (e.pointerType === 'touch' && !wasSel && !(t.classList && t.classList.contains('go-fi'))) return; // first tap only selects, so the page can still scroll
    var fr = selEl && selEl.closest('.go-fi'); var cs = getComputedStyle(selEl);
    drag = { mode: 'move', x: e.clientX, y: e.clientY, dx: 0, dy: 0, free: fr, l: fr ? fr.offsetLeft : 0, t: fr ? fr.offsetTop : 0, moved: false, base: cs.translate, id: e.pointerId, tgt: el };
    try { if (el.setPointerCapture) el.setPointerCapture(e.pointerId); } catch (e1) {}
  }, true);
  document.addEventListener('pointermove', function (e) {
    if (!drag || !selEl) return; var dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (drag.mode === 'move') { if (!drag.moved && Math.abs(dx) + Math.abs(dy) < 4) return; drag.moved = true; drag.dx = dx; drag.dy = dy; if (drag.free) { drag.free.style.left = (drag.l + dx) + 'px'; drag.free.style.top = (drag.t + dy) + 'px'; } else selEl.style.setProperty('translate', 'calc(' + (drag.base && drag.base !== 'none' ? drag.base.split(' ')[0] : '0px') + ' + ' + dx + 'px) calc(' + (drag.base && drag.base !== 'none' && drag.base.split(' ')[1] ? drag.base.split(' ')[1] : '0px') + ' + ' + dy + 'px)', 'important'); }
    else { selEl.style.setProperty('width', Math.max(10, drag.w + dx) + 'px', 'important'); selEl.style.setProperty('height', Math.max(10, drag.h + dy) + 'px', 'important'); }
    place(box, selEl);
  }, true);
  var lastTap = 0;
  function endDrag(ev) {
    if (!drag || !selEl) { drag = null; return; } var d = drag; drag = null; try { if (d.tgt && d.tgt.releasePointerCapture) d.tgt.releasePointerCapture(d.id); } catch (e3) {}
    if (ev && ev.type === 'pointerup' && ev.pointerType === 'touch' && d.mode === 'move' && !d.moved) { var now = Date.now(); if (now - lastTap < 380) { lastTap = 0; try { d.tgt.dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true })); } catch (e4) {} return; } lastTap = now; }
    if (d.mode === 'move' && d.moved) {
      if (d.free) { var W = document.documentElement.clientWidth; post({ t: 'free', id: d.free.id.replace('gf-', ''), x: Math.round((d.free.offsetLeft / W) * 1000) / 10, y: Math.round(d.free.offsetTop) }); }
      else { post({ t: 'move', sel: selOf(selEl), dx: Math.round(d.dx), dy: Math.round(d.dy) }); }
    } else if (d.mode === 'size') {
      var r = selEl.getBoundingClientRect(), fr = selEl.closest('.go-fi');
      if (fr) post({ t: 'free', id: fr.id.replace('gf-', ''), w: Math.round((r.width / document.documentElement.clientWidth) * 1000) / 10, h: Math.round(r.height) });
      else post({ t: 'size', sel: selOf(selEl), w: Math.round(r.width), h: Math.round(r.height) });
    }
  }
  document.addEventListener('pointerup', endDrag, true);
  document.addEventListener('pointercancel', endDrag, true);
  document.addEventListener('dblclick', function (e) {
    var el = e.target.closest('.go-fi') || e.target; if (el.children.length) { var kid = [].filter.call(el.children, function (c) { return c.children.length === 0 && c.textContent.trim(); })[0]; if (kid && e.target === kid) el = kid; else return; }
    if (/^(IMG|VIDEO|INPUT|IFRAME|TEXTAREA|SELECT)$/.test(el.tagName)) return;
    e.preventDefault(); var sel = el.closest('.go-fi') ? null : selOf(el), free = el.closest('.go-fi'); var before = el.innerText;
    el.contentEditable = 'true'; el.focus(); var r = document.createRange(); r.selectNodeContents(el); var s = getSelection(); s.removeAllRanges(); s.addRange(r);
    function done() { el.removeEventListener('blur', done); el.contentEditable = 'false'; el.removeAttribute('contenteditable'); var txt = el.innerText; if (txt !== before) post(free ? { t: 'freeText', id: free.id.replace('gf-', ''), text: txt } : { t: 'text', sel: sel, text: txt.replace(/\n+/g, ' ').trim() }); place(box, el); }
    el.addEventListener('blur', done); el.addEventListener('keydown', function (k) { k.stopPropagation(); if (k.key === 'Escape' || (k.key === 'Enter' && !free)) { k.preventDefault(); el.blur(); } });
  }, true);
  document.addEventListener('keydown', function (e) { if (e.target.isContentEditable) return; post({ t: 'key', k: e.key, ctrl: e.ctrlKey || e.metaKey, shift: e.shiftKey }); if (['Delete', 'Backspace', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown'].indexOf(e.key) >= 0 || ((e.ctrlKey || e.metaKey) && 'zyd'.indexOf(e.key.toLowerCase()) >= 0)) e.preventDefault(); }, true);
  window.addEventListener('scroll', function () { if (selEl) place(box, selEl); }, { passive: true });
  window.addEventListener('resize', function () { if (selEl) place(box, selEl); });
  window.addEventListener('message', function (e) {
    if (e.source !== parentWin) return; var m = e.data; if (!m || m.go !== 1) return;
    if (m.t === 'design') {
      GDc._D = m.d; var s = document.getElementById('go-design-css'); if (s) s.textContent = GDc.css(m.d, page);
      var f = document.getElementById('go-free');
      if (f) { var nh = GDc.freeHtml(m.d, page); if (nh !== lastFree) { var sid = selEl && selEl.closest && selEl.closest('.go-fi') ? selEl.closest('.go-fi').id : null; f.outerHTML = nh; lastFree = nh; if (sid) { var ne = document.getElementById(sid); if (ne) selEl = ne; } } else { [].forEach.call(f.querySelectorAll('.go-fi'), function (x) { x.style.removeProperty('left'); x.style.removeProperty('top'); x.style.removeProperty('width'); x.style.removeProperty('height'); }); } }
      if (!drag && selEl && selEl.style && !(selEl.closest && selEl.closest('.go-fi'))) { selEl.style.removeProperty('translate'); selEl.style.removeProperty('width'); selEl.style.removeProperty('height'); }
      GDc.fontLinks(m.d).forEach(function (g) { var id = 'gf-font-' + g.replace(/\W/g, ''); if (!document.getElementById(id)) { var l = document.createElement('link'); l.id = id; l.rel = 'stylesheet'; l.href = 'https://fonts.googleapis.com/css2?family=' + g + '&display=swap'; document.head.appendChild(l); } });
      var tm = (m.d.t || {})[page] || {};
      Object.keys(origText).forEach(function (sel) { if (!(sel in tm)) { try { var n = document.querySelector(sel); if (n) n.textContent = origText[sel]; } catch (er) {} delete origText[sel]; } });
      Object.keys(tm).forEach(function (sel) { try { var n = document.querySelector(sel); if (n && n.children.length === 0) { if (!(sel in origText)) origText[sel] = n.textContent; n.textContent = tm[sel]; } } catch (er) {} });
      if (window.__goApply) window.__goApply(m.d);
      if (selEl && !document.contains(selEl) && m.keep) selEl = null;
      if (selEl) place(box, selEl); else box.style.display = 'none';
    } else if (m.t === 'select-free') { var el = document.getElementById('gf-' + m.id); if (el) select(el); }
    else if (m.t === 'deselect') { selEl = null; box.style.display = 'none'; }
    else if (m.t === 'refresh') { if (selEl) { place(box, selEl); post(info(selEl)); } }
  });
  post({ t: 'ready', page: page, path: location.pathname });
}

const GO_APPLY_JS='('+goApplyClient.toString()+')()';
// ======================= GoldOffer 5.0 — Studio, Orders, Calendar, CRM, Notifications, Health, Releases =======================
const APP_VERSION = '5.0.0';
const oid = (x) => new mongoose.Types.ObjectId(String(x));
const okId = (x) => mongoose.isValidObjectId(x);

// ----- Notifications -----
const GONotification = mongoose.model('GONotification', new mongoose.Schema({
  sellerId: { type: mongoose.Schema.Types.ObjectId, index: true, required: true },
  kind: String, ref: String, title: String, text: String, link: String,
  count: { type: Number, default: 1 }, read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now, expires: 7776000 }, updatedAt: { type: Date, default: Date.now }
}));
async function pushNote(sellerId, kind, ref, title, text, link) {
  try {
    const hit = await GONotification.findOneAndUpdate({ sellerId, kind, ref: String(ref || ''), read: false }, { $set: { text: String(text || '').slice(0, 200), updatedAt: new Date() }, $inc: { count: 1 } });
    if (!hit) await GONotification.create({ sellerId, kind, ref: String(ref || ''), title, text: String(text || '').slice(0, 200), link });
  } catch (e) { /* notifications must never break the main action */ }
}
app.get('/api/notifications', authenticateToken, async (req, res) => {
  const rows = await GONotification.find({ sellerId: req.user.id }).sort({ updatedAt: -1 }).limit(40).lean();
  res.set('Cache-Control', 'no-store').json({ notifications: rows, unread: rows.filter(r => !r.read).length });
});
app.post('/api/notifications/read', authenticateToken, async (req, res) => {
  const q = { sellerId: req.user.id }; if (okId(req.body && req.body.id)) q._id = req.body.id;
  await GONotification.updateMany(q, { $set: { read: true } }); res.json({ ok: true });
});

// ----- Version history -----
const GOVersion = mongoose.model('GOVersion', new mongoose.Schema({
  sellerId: { type: mongoose.Schema.Types.ObjectId, index: true, required: true },
  kind: String, label: String, snapshot: mongoose.Schema.Types.Mixed, createdAt: { type: Date, default: Date.now }
}));
const snapOf = (u, d) => ({ design: d || u.design || sanitizeDesign(null), theme: u.theme, layout: u.layout, font: u.font, siteName: u.siteName, sellerBio: u.sellerBio, announcementText: u.announcementText || '' });
async function saveVersion(u, kind, label, design) {
  await GOVersion.create({ sellerId: u._id, kind, label: String(label || '').slice(0, 80), snapshot: snapOf(u, design) });
  const all = await GOVersion.find({ sellerId: u._id }).sort({ createdAt: -1 }).select('_id');
  for (const old of all.slice(40)) await GOVersion.deleteOne({ _id: old._id });
}
const summarize = (d) => { d = d || {}; const n = (o) => Object.keys(o || {}).length; let rules = n(d.g); Object.values(d.p || {}).forEach(p => rules += n(p)); let free = 0; Object.values(d.f || {}).forEach(a => free += a.length); return { styled: rules, added: free, texts: Object.values(d.t || {}).reduce((a, b) => a + n(b), 0) }; };
app.get('/api/studio/versions', authenticateToken, async (req, res) => {
  const rows = await GOVersion.find({ sellerId: req.user.id }).sort({ createdAt: -1 }).limit(40).lean();
  res.json({ versions: rows.map(r => ({ _id: r._id, kind: r.kind, label: r.label, createdAt: r.createdAt, siteName: r.snapshot && r.snapshot.siteName, summary: summarize(r.snapshot && r.snapshot.design) })) });
});
app.post('/api/studio/versions', authenticateToken, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.sendStatus(404);
  await saveVersion(u, 'checkpoint', String((req.body && req.body.label) || 'Checkpoint'), u.designDraft || u.design); res.json({ ok: true });
});
app.post('/api/studio/versions/:id/restore', authenticateToken, async (req, res) => {
  if (!okId(req.params.id)) return res.sendStatus(400);
  const u = await User.findById(req.user.id); const v = await GOVersion.findOne({ _id: req.params.id, sellerId: req.user.id });
  if (!u || !v) return res.sendStatus(404);
  await saveVersion(u, 'before-restore', 'Before restoring ' + new Date(v.createdAt).toISOString().slice(0, 16).replace('T', ' '), u.design);
  const s = v.snapshot || {};
  // Only look & feel is restored. Offers, messages, orders, bookings and customers are never touched.
  u.design = sanitizeDesign(s.design); u.designDraft = u.design;
  if (THEMES[s.theme]) u.theme = s.theme; if (LAYOUTS[s.layout]) u.layout = s.layout; if (FONTS[s.font]) u.font = s.font;
  if (typeof s.siteName === 'string' && s.siteName) u.siteName = s.siteName.slice(0, 80);
  if (typeof s.sellerBio === 'string') u.sellerBio = s.sellerBio.slice(0, 650);
  if (typeof s.announcementText === 'string') u.announcementText = s.announcementText.slice(0, 300);
  u.markModified('design'); u.markModified('designDraft'); await u.save();
  res.json({ ok: true, design: u.design, note: 'Design restored. Offers, messages and orders were not changed.' });
});
app.delete('/api/studio/versions/:id', authenticateToken, async (req, res) => { if (okId(req.params.id)) await GOVersion.deleteOne({ _id: req.params.id, sellerId: req.user.id }); res.json({ ok: true }); });

// ----- Studio routes -----
app.post('/api/studio/ticket', authenticateToken, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.sendStatus(404);
  if (!u.slug) { if (!u.siteName) return res.status(400).json({ message: 'Please enter a site name first.' }); u.slug = await uniqueSlug(u.siteName, u._id); await u.save(); }
  res.json({ ticket: jwt.sign({ id: String(u._id), studio: true }, process.env.JWT_SECRET, { expiresIn: '6h' }), slug: u.slug, base: PUBLIC_BASE });
});
app.get('/api/studio/state', authenticateToken, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.sendStatus(404);
  const offers = await Offer.find({ userId: u._id }).sort({ createdAt: -1 }).limit(12).select('_id title');
  res.json({ draft: u.designDraft || u.design || sanitizeDesign(null), live: u.design || sanitizeDesign(null), layout: u.layout, theme: u.theme, offers, slug: u.slug, published: !!u.published, fonts: GD.FONT_LIST, layouts: Object.keys(LAYOUTS) });
});
app.put('/api/studio/draft', authenticateToken, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.sendStatus(404);
  u.designDraft = sanitizeDesign(req.body && req.body.design); u.markModified('designDraft');
  if (req.body && LAYOUTS[req.body.layout]) u.layout = req.body.layout;
  await u.save(); res.json({ ok: true, design: u.designDraft });
});
app.post('/api/studio/publish', authenticateToken, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.sendStatus(404);
  if (!u.designDraft) return res.json({ ok: true, unchanged: true });
  if (u.design && !designIsEmpty(u.design)) await saveVersion(u, 'auto', 'Before publish', u.design);
  u.design = sanitizeDesign(u.designDraft); u.markModified('design'); await u.save();
  await saveVersion(u, 'publish', String((req.body && req.body.label) || 'Published'), u.design);
  res.json({ ok: true });
});
app.get('/api/studio/export', authenticateToken, async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) return res.sendStatus(404);
  const offers = await Offer.find({ userId: u._id }).sort({ createdAt: -1 });
  u._gd = u.designDraft || u.design; u._stockMap = {};
  res.set({ 'Content-Type': 'text/html; charset=utf-8', 'Content-Disposition': `attachment; filename="${(u.slug || 'site').replace(/[^\w-]/g, '')}.html"` }).send(renderSite(u, offers, false).replace(/(href|action)="\/(?!\/)/g, `$1="${PUBLIC_BASE}/`));
});

// ----- Orders: Pending -> Accepted -> Processing -> Completed, with a customer tracking link -----
const ORDER_FLOW = ['Pending', 'Accepted', 'Processing', 'Completed', 'Cancelled'];
const STOCK_STATES = ['Accepted', 'Processing', 'Completed'];
async function applyStock(order, sellerId, to) {
  // Atomic guards make double clicks and repeated requests harmless: stock changes at most once per direction.
  if (!order.offerId) return { ok: true };
  const key = 'stock.' + String(order.offerId);
  if (STOCK_STATES.includes(to) && !order.stockApplied) {
    const setting = await ShopSetting.findOne({ sellerId }).lean();
    const tracked = setting && setting.stock && (setting.stock[String(order.offerId)] !== undefined);
    if (tracked) {
      const claimed = await Order.findOneAndUpdate({ _id: order._id, stockApplied: { $ne: true } }, { $set: { stockApplied: true } });
      if (!claimed) return { ok: true };
      const got = await ShopSetting.findOneAndUpdate({ sellerId, [key]: { $gt: 0 } }, { $inc: { [key]: -1 } });
      if (!got) { await Order.updateOne({ _id: order._id }, { $set: { stockApplied: false } }); return { ok: false, message: 'Not enough stock to accept this order.' }; }
      order.stockApplied = true;
    }
  } else if (!STOCK_STATES.includes(to) && order.stockApplied) {
    const released = await Order.findOneAndUpdate({ _id: order._id, stockApplied: true }, { $set: { stockApplied: false } });
    if (released) await ShopSetting.updateOne({ sellerId, [key]: { $exists: true } }, { $inc: { [key]: 1 } });
    order.stockApplied = false;
  }
  return { ok: true };
}
app.get('/api/orders', authenticateToken, async (req, res) => {
  const rows = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(300).lean();
  res.set('Cache-Control', 'no-store').json({ orders: rows.map(o => ({ ...o, trackUrl: o.trackToken ? PUBLIC_BASE + '/track/' + o.trackToken : '' })) });
});
app.patch('/api/orders/:id', authenticateToken, async (req, res) => {
  if (!okId(req.params.id)) return res.status(400).json({ message: 'Invalid id' });
  const status = req.body && req.body.status;
  if (status !== undefined && !ORDER_FLOW.includes(status)) return res.status(400).json({ message: 'Invalid status' });
  try {
    const order = await Order.findOne({ _id: req.params.id, userId: req.user.id });
    if (!order) return res.status(404).json({ message: 'Order not found' });
    if (typeof (req.body && req.body.ownerNote) === 'string') order.ownerNote = req.body.ownerNote.slice(0, 600);
    if (status && status !== order.status) {
      const r = await applyStock(order, req.user.id, status);
      if (!r.ok) return res.status(409).json({ message: r.message });
      order.status = status; order.history = (order.history || []).concat([{ status, at: new Date() }]).slice(-20);
      if (!order.trackToken) order.trackToken = crypto.randomBytes(12).toString('hex');
      const mail = (order.contacts || []).find(c => c.type === 'email' && isEmail(c.value));
      if (mail) void sendMail({ to: mail.value, subject: `Your request "${order.offerTitle}" is now: ${status}`, text: `Status: ${status}\nTrack it any time: ${PUBLIC_BASE}/track/${order.trackToken}` });
    }
    try { await order.save(); }
    catch (saveErr) {
      // keep stock and order consistent: undo the stock move if the order could not be saved
      try { const fresh = await Order.findById(order._id); if (fresh) await applyStock(fresh, req.user.id, fresh.status); } catch (_) {}
      throw saveErr;
    }
    res.json({ order, trackUrl: order.trackToken ? PUBLIC_BASE + '/track/' + order.trackToken : '' });
  } catch (e) { res.status(500).json({ message: 'Could not change order status' }); }
});
const trackLimiter = rateLimit({ windowMs: 60 * 1000, max: 40 });
app.get('/track/:token', trackLimiter, async (req, res) => {
  try {
    if (!/^[a-f0-9]{24}$/.test(req.params.token)) return res.status(404).send('Not found');
    const o = await Order.findOne({ trackToken: req.params.token }); if (!o) return res.status(404).send('Not found');
    const u = await User.findById(o.userId); if (!u) return res.status(404).send('Not found');
    u._gd = u.design; res.setHeader('Content-Security-Policy', SITE_CSP); res.setHeader('Cache-Control', 'no-store');
    const steps = ['Pending', 'Accepted', 'Processing', 'Completed']; const idx = steps.indexOf(o.status); const cancelled = o.status === 'Cancelled';
    const label = { Pending: 'Received', Accepted: 'Accepted', Processing: 'In progress', Completed: 'Done' };
    const body = `${siteBar(u, 'page')}<main class="wrap" style="padding:120px 0 80px;max-width:640px"><div class="glass" style="padding:28px"><small style="color:var(--mute)">Your request at ${esc(sellerName(u))}</small><h1 style="margin:6px 0 4px;font-size:clamp(26px,5vw,38px)">${esc(o.offerTitle || 'Request')}</h1><p style="color:var(--soft)">EUR ${Number(o.amount || 0).toFixed(2)} · sent ${esc(new Date(o.createdAt).toISOString().slice(0, 10))}</p>
<div style="display:grid;gap:10px;margin:24px 0">${cancelled ? '<div class="ok" style="background:#3a1620;border-color:#ff5d73">This request was cancelled.</div>' : steps.map((s, i) => `<div style="display:flex;gap:12px;align-items:center;opacity:${i <= idx ? 1 : .4}"><span style="width:26px;height:26px;border-radius:50%;display:grid;place-items:center;background:${i <= idx ? 'var(--a)' : 'transparent'};color:var(--on);border:1px solid var(--a);font-weight:800">${i <= idx ? '&#10003;' : ''}</span><b>${label[s]}</b>${i === idx ? '<span style="color:var(--a)">&larr; now</span>' : ''}</div>`).join('')}</div>
${o.status === 'Pending' ? `<form method="POST" action="/track/${o.trackToken}/cancel"><button class="abtn" type="submit">Cancel my request</button></form>` : ''}
<p style="margin-top:20px"><a class="abtn pri" href="/site/${esc(u.slug)}">Back to ${esc(u.siteName)}</a></p></div></main>`;
    res.send(pageShell(u, { title: `Track request - ${u.siteName}`, desc: 'Request status', body, page: 'track' }));
  } catch (e) { res.status(500).send('Server error'); }
});
app.post('/track/:token/cancel', trackLimiter, async (req, res) => {
  if (!/^[a-f0-9]{24}$/.test(req.params.token)) return res.status(404).send('Not found');
  const o = await Order.findOne({ trackToken: req.params.token }); if (!o) return res.status(404).send('Not found');
  if (o.status === 'Pending') { o.status = 'Cancelled'; o.history = (o.history || []).concat([{ status: 'Cancelled', at: new Date(), by: 'customer' }]); await o.save(); await pushNote(o.userId, 'order', 'c' + o._id, 'Request cancelled', `${o.customerName || 'A customer'} cancelled "${o.offerTitle}"`, '/orders'); }
  res.redirect(303, '/track/' + o.trackToken);
});

// ----- Booking calendar: working hours, breaks, durations, no double booking -----
const GOCalendar = mongoose.model('GOCalendar', new mongoose.Schema({
  sellerId: { type: mongoose.Schema.Types.ObjectId, unique: true, required: true },
  enabled: { type: Boolean, default: false }, tz: { type: String, default: 'Europe/Sofia' },
  hours: { type: mongoose.Schema.Types.Mixed, default: {} }, breaks: { type: [{ from: String, to: String, _id: false }], default: [] },
  stepMin: { type: Number, default: 30 }, durationMin: { type: Number, default: 60 }, bufferMin: { type: Number, default: 0 },
  noticeHours: { type: Number, default: 2 }, daysAhead: { type: Number, default: 60 }, closedDates: { type: [String], default: [] },
  durations: { type: mongoose.Schema.Types.Mixed, default: {} }
}));
const GOSlot = mongoose.model('GOSlot', new mongoose.Schema({ sellerId: { type: mongoose.Schema.Types.ObjectId, required: true }, t: { type: Date, required: true }, apptId: mongoose.Schema.Types.ObjectId }));
GOSlot.schema.index({ sellerId: 1, t: 1 }, { unique: true });
const DAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];
const hhmm = (s) => { const m = /^([01]?\d|2[0-3]):([0-5]\d)$/.exec(String(s || '')); return m ? Number(m[1]) * 60 + Number(m[2]) : null; };
const pad2 = (n) => String(n).padStart(2, '0');
function tzOffsetMin(tz, ms) { const p = Object.fromEntries(new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }).formatToParts(new Date(ms)).map(x => [x.type, x.value])); return (Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - ms) / 60000; }
function zonedToUtc(dateStr, min, tz) { const [y, m, d] = dateStr.split('-').map(Number); const g = Date.UTC(y, m - 1, d, Math.floor(min / 60), min % 60); let o = tzOffsetMin(tz, g); let u = g - o * 60000; o = tzOffsetMin(tz, u); return g - o * 60000; }
const UNIT = 15 * 60000;
const durationFor = (cal, offerId) => { const d = offerId && cal.durations && Number(cal.durations[String(offerId)]); return Math.max(5, Math.min(600, d || cal.durationMin || 60)); };
async function slotsFor(cal, dateStr, durationMin) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr || '')) return [];
  const tz = cal.tz || 'Europe/Sofia'; const [y, m, d] = dateStr.split('-').map(Number);
  const dow = DAYS[new Date(Date.UTC(y, m - 1, d)).getUTCDay()]; const h = (cal.hours || {})[dow];
  if (!h || !h.on || (cal.closedDates || []).includes(dateStr)) return [];
  const from = hhmm(h.from), to = hhmm(h.to); if (from === null || to === null || to <= from) return [];
  const step = [10, 15, 20, 30, 45, 60].includes(cal.stepMin) ? cal.stepMin : 30; const buffer = cal.bufferMin || 0;
  const dayStart = zonedToUtc(dateStr, 0, tz), dayEnd = dayStart + 36 * 3600000;
  const locks = new Set((await GOSlot.find({ sellerId: cal.sellerId, t: { $gte: new Date(dayStart - 12 * 3600000), $lt: new Date(dayEnd) } }).lean()).map(l => new Date(l.t).getTime()));
  const brk = (cal.breaks || []).map(b => [hhmm(b.from), hhmm(b.to)]).filter(b => b[0] !== null && b[1] !== null && b[1] > b[0]);
  const now = Date.now() + (cal.noticeHours || 0) * 3600000, out = [];
  for (let t = from; t + durationMin <= to; t += step) {
    if (brk.some(b => t < b[1] && t + durationMin > b[0])) continue;
    const s = zonedToUtc(dateStr, t, tz); if (s < now) continue;
    let free = true; for (let u = Math.floor(s / UNIT) * UNIT; u < s + (durationMin + buffer) * 60000; u += UNIT) if (locks.has(u)) { free = false; break; }
    if (free) out.push({ time: pad2(Math.floor(t / 60)) + ':' + pad2(t % 60), iso: new Date(s).toISOString() });
  }
  return out;
}
async function lockRange(sellerId, startMs, durationMin, bufferMin, apptId) {
  const made = [];
  try {
    for (let u = Math.floor(startMs / UNIT) * UNIT; u < startMs + (durationMin + (bufferMin || 0)) * 60000; u += UNIT) { await GOSlot.create({ sellerId, t: new Date(u), apptId }); made.push(u); }
    return true;
  } catch (e) { await GOSlot.deleteMany({ sellerId, apptId }); return false; }
}
const calOf = async (sellerId) => (await GOCalendar.findOne({ sellerId }).lean()) || { sellerId, enabled: false, tz: 'Europe/Sofia', hours: {}, breaks: [], stepMin: 30, durationMin: 60, bufferMin: 0, noticeHours: 2, daysAhead: 60, closedDates: [], durations: {} };
const defaultHours = () => Object.fromEntries(DAYS.map(d => [d, { on: !['sat', 'sun'].includes(d), from: '09:00', to: '18:00' }]));
app.get('/api/calendar', authenticateToken, async (req, res) => {
  const cal = await calOf(req.user.id); if (!cal.hours || !Object.keys(cal.hours).length) cal.hours = defaultHours();
  const from = new Date(req.query.from || Date.now() - 7 * 86400000), to = new Date(req.query.to || Date.now() + 60 * 86400000);
  const appts = await Appointment.find({ sellerId: req.user.id, startsAt: { $gte: from, $lte: to } }).sort({ startsAt: 1 }).lean();
  const offers = await Offer.find({ userId: req.user.id }).select('_id title').lean();
  res.set('Cache-Control', 'no-store').json({ config: cal, appointments: appts, offers });
});
app.put('/api/calendar', authenticateToken, async (req, res) => {
  const b = req.body || {}; const set = {};
  if (typeof b.enabled === 'boolean') set.enabled = b.enabled;
  if (typeof b.tz === 'string') { try { new Intl.DateTimeFormat('en', { timeZone: b.tz }); set.tz = b.tz; } catch (e) { return res.status(400).json({ message: 'Unknown time zone' }); } }
  if (b.hours && typeof b.hours === 'object') { const h = {}; DAYS.forEach(d => { const x = b.hours[d] || {}; const f = hhmm(x.from), t = hhmm(x.to); h[d] = { on: !!x.on && f !== null && t !== null && t > f, from: f !== null ? x.from : '09:00', to: t !== null ? x.to : '18:00' }; }); set.hours = h; }
  if (Array.isArray(b.breaks)) set.breaks = b.breaks.slice(0, 6).filter(x => hhmm(x.from) !== null && hhmm(x.to) !== null && hhmm(x.to) > hhmm(x.from)).map(x => ({ from: x.from, to: x.to }));
  const n = (k, lo, hi) => { if (b[k] !== undefined && Number.isFinite(Number(b[k]))) set[k] = Math.max(lo, Math.min(hi, Math.round(Number(b[k])))); };
  n('stepMin', 10, 60); n('durationMin', 5, 600); n('bufferMin', 0, 120); n('noticeHours', 0, 168); n('daysAhead', 1, 365);
  if (Array.isArray(b.closedDates)) set.closedDates = b.closedDates.filter(x => /^\d{4}-\d{2}-\d{2}$/.test(x)).slice(0, 200);
  if (b.durations && typeof b.durations === 'object') { const d = {}; Object.keys(b.durations).slice(0, 100).forEach(k => { if (okId(k) && Number(b.durations[k]) >= 5 && Number(b.durations[k]) <= 600) d[k] = Math.round(Number(b.durations[k])); }); set.durations = d; }
  const cal = await GOCalendar.findOneAndUpdate({ sellerId: req.user.id }, { $set: set }, { new: true, upsert: true, setDefaultsOnInsert: true });
  if (typeof b.enabled === 'boolean') { await User.updateOne({ _id: req.user.id }, { $set: { bookingEnabled: b.enabled } }); await ShopSetting.findOneAndUpdate({ sellerId: req.user.id }, { $set: { slotsEnabled: b.enabled } }, { upsert: true }); }
  res.json({ config: cal });
});
const slotLimiter = rateLimit({ windowMs: 60 * 1000, max: 60 });
app.get('/site/:slug/slots', slotLimiter, async (req, res) => {
  const u = await User.findOne({ slug: req.params.slug, published: true }).select('_id'); if (!u) return res.sendStatus(404);
  const cal = await calOf(u._id); if (!cal.enabled) return res.json({ slots: [], tz: cal.tz, configured: false });
  const date = String(req.query.date || ''); const max = Date.now() + (cal.daysAhead || 60) * 86400000;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || zonedToUtc(date, 0, cal.tz) > max) return res.json({ slots: [], tz: cal.tz, configured: true });
  const dur = durationFor(cal, okId(req.query.offerId) ? req.query.offerId : null);
  res.set('Cache-Control', 'no-store').json({ slots: await slotsFor(cal, date, dur), tz: cal.tz, duration: dur, configured: true });
});
// public booking (replaces the old free-text one: only real free slots are accepted)
app.post('/site/:slug/appointment', publicLimiter, rejectOwnerSelfAction, async (req, res) => {
  try {
    const owner = await User.findOne({ slug: req.params.slug, published: true }).select('_id siteName email notifyEmail'); if (!owner) return res.sendStatus(404);
    const b = req.body || {}; if (b.consent !== '1') return res.status(400).send('Please accept the privacy notice.');
    const cal = await calOf(owner._id); if (!cal.enabled) return res.status(403).send('Booking is not enabled for this business.');
    const customer = String(b.customer || '').trim().slice(0, 80), contact = String(b.contact || '').trim().slice(0, 140);
    const d = new Date(b.startsAt); if (!customer || contact.length < 5 || !Number.isFinite(d.valueOf())) return res.status(400).send('Check the date and contact details.');
    const offerId = okId(b.offerId) ? b.offerId : undefined; if (offerId && !(await Offer.exists({ _id: offerId, userId: owner._id }))) return res.sendStatus(404);
    const dur = durationFor(cal, offerId);
    const dateStr = new Intl.DateTimeFormat('en-CA', { timeZone: cal.tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
    const free = await slotsFor(cal, dateStr, dur);
    if (!free.some(s => new Date(s.iso).getTime() === d.getTime())) return res.status(409).send('This time is no longer available. Please go back and pick another slot.');
    const appt = await Appointment.create({ sellerId: owner._id, offerId, startsAt: d, endsAt: new Date(d.getTime() + dur * 60000), durationMin: dur, customer, contact, note: String(b.note || '').slice(0, 500) });
    if (!(await lockRange(owner._id, d.getTime(), dur, cal.bufferMin, appt._id))) { await Appointment.deleteOne({ _id: appt._id }); return res.status(409).send('Someone just booked this time. Please pick another slot.'); }
    await pushNote(owner._id, 'booking', String(appt._id), 'New booking', `${customer} · ${d.toISOString().slice(0, 16).replace('T', ' ')} UTC`, '/calendar');
    if (owner.email) void sendMail({ to: owner.notifyEmail || owner.email, subject: 'New booking', text: `${customer} booked ${d.toISOString()}. Contact: ${contact}` });
    res.redirect(303, `/site/${encodeURIComponent(req.params.slug)}?booking=1`);
  } catch (e) { res.status(500).send('Booking could not be saved'); }
});
app.post('/api/business/appointments', authenticateToken, async (req, res) => {
  try {
    const b = req.body || {}; const d = new Date(b.startsAt); if (!Number.isFinite(d.valueOf())) return res.status(400).json({ message: 'Invalid appointment date' });
    const cal = await calOf(req.user.id); const dur = Math.max(5, Math.min(600, Number(b.durationMin) || durationFor(cal, okId(b.offerId) ? b.offerId : null)));
    const appt = await Appointment.create({ sellerId: req.user.id, startsAt: d, endsAt: new Date(d.getTime() + dur * 60000), durationMin: dur, customer: String(b.customer || '').trim().slice(0, 80) || 'Manual booking', contact: String(b.contact || '').slice(0, 140) || 'Added by owner', note: String(b.note || '').slice(0, 500) });
    if (!(await lockRange(req.user.id, d.getTime(), dur, cal.bufferMin, appt._id))) { await Appointment.deleteOne({ _id: appt._id }); return res.status(409).json({ message: 'That time overlaps another booking.' }); }
    res.status(201).json({ appointment: appt });
  } catch (e) { res.status(e.code === 11000 ? 409 : 500).json({ message: e.code === 11000 ? 'That time is already booked.' : 'Could not save booking' }); }
});
app.patch('/api/business/appointments/:id', authenticateToken, async (req, res) => {
  const st = req.body && req.body.status; if (!okId(req.params.id) || !['Pending', 'Confirmed', 'Cancelled', 'Completed'].includes(st)) return res.sendStatus(400);
  try {
    const row = await Appointment.findOne({ _id: req.params.id, sellerId: req.user.id }); if (!row) return res.sendStatus(404);
    const wasActive = ['Pending', 'Confirmed'].includes(row.status), active = ['Pending', 'Confirmed'].includes(st);
    if (wasActive && st === 'Cancelled') await GOSlot.deleteMany({ sellerId: req.user.id, apptId: row._id });
    if (!wasActive && active) { const cal = await calOf(req.user.id); if (!(await lockRange(req.user.id, new Date(row.startsAt).getTime(), row.durationMin || cal.durationMin || 60, cal.bufferMin, row._id))) return res.status(409).json({ message: 'The requested time is no longer available.' }); }
    row.status = st; await row.save(); res.json({ appointment: row });
  } catch (e) { res.status(e.code === 11000 ? 409 : 500).json({ message: 'Could not change booking' }); }
});

// ----- Customers (mini CRM). Only the seller's own data; erase and export are built in. -----
const GOCustomer = mongoose.model('GOCustomer', new mongoose.Schema({
  sellerId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true }, key: { type: String, required: true },
  status: { type: String, default: 'lead' }, tags: { type: [String], default: [] }, notes: { type: [{ text: String, at: Date, _id: false }], default: [] }, createdAt: { type: Date, default: Date.now }
}));
GOCustomer.schema.index({ sellerId: 1, key: 1 }, { unique: true });
const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i, PHONE_RE = /\+?\d[\d\s().-]{6,}\d/;
function keyOf(name, contact) {
  const t = String(contact || ''); const e = t.match(EMAIL_RE); if (e) return 'e:' + e[0].toLowerCase();
  const p = t.match(PHONE_RE); if (p) return 'p:' + p[0].replace(/\D/g, '');
  return 'n:' + String(name || '').trim().toLowerCase().slice(0, 60);
}
async function customersFor(sellerId) {
  const [orders, appts, convs, prof] = await Promise.all([Order.find({ userId: sellerId }).lean(), Appointment.find({ sellerId }).lean(), Conversation.find({ userId: sellerId }).select('customerName customerEmail lastAt').lean(), GOCustomer.find({ sellerId }).lean()]);
  const map = new Map(); const prof2 = new Map(prof.map(p => [p.key, p]));
  const get = (k, name, contact) => { if (!map.has(k)) map.set(k, { key: k, name: name || '', contacts: new Set(), orders: 0, spent: 0, bookings: 0, chats: 0, last: 0 }); const c = map.get(k); if (name && !c.name) c.name = name; if (contact) c.contacts.add(contact); return c; };
  const touch = (c, d) => { const t = new Date(d || 0).getTime(); if (t > c.last) c.last = t; };
  orders.forEach(o => { if (o.anonymized) return; const ct = o.customerContact || (o.contacts || []).map(x => x.value).join(' '); const c = get(keyOf(o.customerName, ct), o.customerName, ct); c.orders++; if (o.status === 'Completed') c.spent += Number(o.amount || 0); touch(c, o.createdAt); });
  appts.forEach(a => { if (a.anonymized) return; const c = get(keyOf(a.customer, a.contact), a.customer, a.contact); c.bookings++; touch(c, a.startsAt); });
  convs.forEach(v => { const c = get(keyOf(v.customerName, v.customerEmail), v.customerName, v.customerEmail); c.chats++; touch(c, v.lastAt); });
  return [...map.values()].map(c => { const p = prof2.get(c.key) || {}; return { key: c.key, name: c.name || '(no name)', contacts: [...c.contacts].slice(0, 4), orders: c.orders, spent: Math.round(c.spent * 100) / 100, bookings: c.bookings, chats: c.chats, last: c.last, status: p.status || (c.orders ? 'customer' : 'lead'), tags: p.tags || [], notes: (p.notes || []).slice(-30) }; }).sort((a, b) => b.last - a.last);
}
app.get('/api/customers', authenticateToken, async (req, res) => { res.set('Cache-Control', 'no-store').json({ customers: await customersFor(req.user.id) }); });
app.put('/api/customers/profile', authenticateToken, async (req, res) => {
  const b = req.body || {}; const key = String(b.key || '').slice(0, 120); if (!/^[epn]:/.test(key)) return res.sendStatus(400);
  const set = {}; if (['lead', 'customer', 'vip', 'inactive'].includes(b.status)) set.status = b.status;
  if (Array.isArray(b.tags)) set.tags = b.tags.map(t => String(t).trim().slice(0, 24)).filter(Boolean).slice(0, 8);
  const upd = { $set: set }; if (typeof b.note === 'string' && b.note.trim()) upd.$push = { notes: { text: b.note.trim().slice(0, 600), at: new Date() } };
  await GOCustomer.findOneAndUpdate({ sellerId: req.user.id, key }, upd, { upsert: true, new: true }); res.json({ ok: true });
});
// Right to erasure: removes the profile and chats, and blanks personal data in orders/bookings (the sales totals stay).
app.post('/api/customers/erase', authenticateToken, async (req, res) => {
  const key = String((req.body && req.body.key) || ''); if (!/^[epn]:/.test(key)) return res.sendStatus(400);
  const sid = req.user.id; let n = 0;
  for (const o of await Order.find({ userId: sid })) if (keyOf(o.customerName, o.customerContact || (o.contacts || []).map(x => x.value).join(' ')) === key) { o.customerName = 'Erased'; o.customerContact = ''; o.contacts = []; o.note = ''; o.anonymized = true; await o.save(); n++; }
  for (const a of await Appointment.find({ sellerId: sid })) if (keyOf(a.customer, a.contact) === key) { a.customer = 'Erased'; a.contact = ''; a.note = ''; a.anonymized = true; await a.save(); n++; }
  for (const c of await Conversation.find({ userId: sid }).select('_id customerName customerEmail')) if (keyOf(c.customerName, c.customerEmail) === key) { await Conversation.deleteOne({ _id: c._id }); n++; }
  await GOCustomer.deleteOne({ sellerId: sid, key }); res.json({ ok: true, erased: n });
});
app.get('/api/customers/export.csv', authenticateToken, async (req, res) => {
  const safe = (v) => { v = String(v == null ? '' : v); if (/^[=+\-@\t\r]/.test(v)) v = "'" + v; return '"' + v.replace(/"/g, '""') + '"'; };
  const rows = await customersFor(req.user.id);
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="customers.csv"', 'Cache-Control': 'no-store' }).send('name,contacts,status,orders,spent,bookings,chats,tags\n' + rows.map(c => [c.name, c.contacts.join(' | '), c.status, c.orders, c.spent, c.bookings, c.chats, c.tags.join(' | ')].map(safe).join(',')).join('\n'));
});

// ----- System health & releases -----
const timed = async (fn) => { const t = Date.now(); try { const r = await Promise.race([fn(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout (5s)')), 5000))]); return { ...r, ms: Date.now() - t }; } catch (e) { return { status: 'fail', detail: String(e.message || e).slice(0, 160), ms: Date.now() - t }; } };
async function runHealth(sellerId) {
  const u = await User.findById(sellerId).lean();
  const C = [
    ['db', 'MongoDB database', async () => { if (mongoose.connection.readyState !== 1) return { status: 'fail', detail: 'Not connected' }; const n = await GONotification.create({ sellerId, kind: 'probe', title: 'probe', read: true }); const back = await GONotification.findById(n._id); await GONotification.deleteOne({ _id: n._id }); return back ? { status: 'ok', detail: 'Connected. Write, read and delete test passed.' } : { status: 'fail', detail: 'Write succeeded but read-back failed' }; }],
    ['messenger', 'Messenger', async () => { const c = await Conversation.countDocuments({ userId: sellerId }); const unread = await Conversation.countDocuments({ userId: sellerId, unreadSeller: { $gt: 0 } }); return { status: 'ok', detail: `${c} conversation(s), ${unread} unread.` }; }],
    ['calls', 'Voice call setup', async () => { const turn = !!(process.env.TURN_URL || process.env.METERED_API_KEY || process.env.METERED_DOMAIN); return turn ? { status: 'ok', detail: 'STUN + TURN relay configured.' } : { status: 'warn', detail: 'Only STUN is configured. Calls work on most networks, but can fail behind strict mobile/corporate NAT. Add TURN_URL (or Metered keys) for reliable calls.' }; }],
    ['images', 'Image upload', async () => { const img = await Image.create({ userId: sellerId, contentType: 'image/gif', data: Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64') }); const back = await Image.findById(img._id); await Image.deleteOne({ _id: img._id }); const count = await Image.countDocuments({ userId: sellerId }); return back ? { status: 'ok', detail: `Storage test passed. You have ${count} stored image(s). Limit 5 MB each.` } : { status: 'fail', detail: 'Image could not be read back' }; }],
    ['orders', 'Orders', async () => { const old = await Order.countDocuments({ userId: sellerId, status: 'Pending', createdAt: { $lt: new Date(Date.now() - 48 * 3600000) } }); return old ? { status: 'warn', detail: `${old} request(s) waiting more than 48 hours.` } : { status: 'ok', detail: 'No stale requests.' }; }],
    ['bookings', 'Bookings', async () => { const cal = await calOf(sellerId); const active = await Appointment.find({ sellerId, status: { $in: ['Pending', 'Confirmed'] }, startsAt: { $gt: new Date() } }).lean(); let missing = 0; for (const a of active) if (!(await GOSlot.exists({ sellerId, apptId: a._id }))) missing++; if (!cal.enabled) return { status: 'warn', detail: 'Calendar is switched off (customers cannot book).' }; return missing ? { status: 'warn', detail: `${missing} upcoming booking(s) have no time lock (made before the calendar upgrade). They still show, but double booking is possible for them.` } : { status: 'ok', detail: `Calendar on. ${active.length} upcoming booking(s), all protected from double booking.` }; }],
    ['settings', 'Site & settings', async () => { if (!u || !u.slug) return { status: 'warn', detail: 'Site address not created yet.' }; return u.published ? { status: 'ok', detail: `Published at /site/${u.slug}.` } : { status: 'warn', detail: 'Site is not published yet.' }; }],
    ['email', 'Email notifications', async () => (process.env.BREVO_API_KEY || process.env.RESEND_API_KEY || process.env.SMTP_HOST) ? { status: 'ok', detail: 'Mail provider configured.' } : { status: 'warn', detail: 'No mail provider configured: email alerts and tracking emails are not sent.' }],
    ['payments', 'Payments (Stripe)', async () => process.env.STRIPE_SECRET_KEY ? { status: 'ok', detail: 'Stripe key present.' } : { status: 'warn', detail: 'Stripe key missing: subscriptions cannot be started.' }],
    ['security', 'Security basics', async () => process.env.JWT_SECRET && process.env.JWT_SECRET.length >= 24 ? { status: 'ok', detail: 'JWT secret is set and long enough.' } : { status: 'warn', detail: 'JWT_SECRET is missing or short.' }]
  ];
  const checks = []; for (const [id, label, fn] of C) checks.push({ id, label, ...(await timed(fn)) });
  const worst = checks.some(c => c.status === 'fail') ? 'fail' : checks.some(c => c.status === 'warn') ? 'warn' : 'ok';
  return { overall: worst, at: new Date(), uptimeSec: Math.round(process.uptime()), node: process.version, version: APP_VERSION, checks };
}
app.get('/api/system/health', authenticateToken, async (req, res) => { res.set('Cache-Control', 'no-store').json(await runHealth(req.user.id)); });
const CHANGELOG = [
  { version: '5.0.0', date: '2026-10-25', items: ['Design Studio: click, drag, recolor and rewrite anything on your site, on desktop and phone', 'Version History with safe restore (offers, messages and orders are never touched)', 'Booking Calendar with working hours, breaks, durations and no double booking', 'Order Center with Accept → Process → Complete and a customer tracking link', 'Customer Manager (mini CRM) with erase and export', 'Notification Center, System Health and this Release Center'] },
  { version: '4.0.0', date: '2026-10-20', items: ['Messenger with photos, files and real two-way voice calls', 'English-only interface, mobile polish, "More from <seller>"'] }
];
const FEATURES = (turn) => [
  { id: 'studio', name: 'Design Studio', status: 'available' }, { id: 'versions', name: 'Version History', status: 'available' }, { id: 'orders', name: 'Order Center + tracking', status: 'available' },
  { id: 'calendar', name: 'Booking Calendar', status: 'available' }, { id: 'crm', name: 'Customer Manager', status: 'available' }, { id: 'notif', name: 'Notification Center (in-app)', status: 'available' },
  { id: 'push', name: 'Push when the app is closed', status: 'planned', note: 'Needs a web-push service and keys; in-app bell works today.' },
  { id: 'calls', name: 'Voice calls', status: turn ? 'available' : 'needs-setup', note: turn ? '' : 'Add a TURN server for reliable calls on all networks.' }
];
app.get('/api/system/release', authenticateToken, async (req, res) => { const h = await runHealth(req.user.id); res.json({ version: APP_VERSION, features: FEATURES(!!(process.env.TURN_URL || process.env.METERED_API_KEY)), changelog: CHANGELOG, check: { overall: h.overall, at: h.at, failed: h.checks.filter(c => c.status === 'fail').map(c => c.label), warnings: h.checks.filter(c => c.status === 'warn').map(c => c.label), total: h.checks.length } }); });

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
h1{font-size:clamp(2.7rem,9vw,7rem);line-height:1.02;letter-spacing:-.035em;color:#f4f1ea;padding-bottom:.08em}
.lead{color:var(--soft);font-size:clamp(1rem,1.7vw,1.25rem);margin:22px auto 0;max-width:46ch;animation:rise .9s .25s both}
.cta{display:inline-block;margin-top:38px;background:linear-gradient(105deg,var(--a) 0%,#ffcc12 42%,var(--b) 100%);color:var(--on);text-decoration:none;font-weight:700;padding:16px 34px;border-radius:99px;box-shadow:0 0 40px color-mix(in srgb,var(--a) 45%,transparent);transition:transform .2s;animation:rise .9s .4s both}
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
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,290px),1fr));gap:26px;perspective:1400px}
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
/* header icons with badges */
.bar b{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar nav{align-items:center;flex-shrink:0}
.navi{position:relative;display:inline-flex;align-items:center;gap:8px}
.navi svg{width:18px;height:18px;flex-shrink:0;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.nbadge{min-width:19px;height:19px;padding:0 5px;border-radius:99px;background:#ff3d7f;color:#fff;font-size:.7rem;font-weight:700;display:inline-flex;align-items:center;justify-content:center;line-height:1}
.nbadge:empty{display:none}
.ringb{position:fixed;left:12px;right:12px;top:72px;z-index:250;background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);font-weight:800;text-decoration:none;text-align:center;padding:14px 16px;border-radius:16px;box-shadow:0 14px 40px rgba(0,0,0,.6)}
/* offer page: action buttons next to the price (like a classifieds app) */
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 24px}
.abtn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:13px 22px;border-radius:14px;font-family:inherit;font-weight:700;font-size:.98rem;text-decoration:none;cursor:pointer;border:1px solid rgba(255,255,255,.2);background:transparent;color:#fff;transition:transform .2s,border-color .2s}
.abtn svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex-shrink:0}
.abtn:hover{border-color:var(--a)}
.abtn.pri{flex:1 1 190px;border:0;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 30px color-mix(in srgb,var(--a) 35%,transparent)}
.abtn.pri:hover{transform:translateY(-2px)}
.actions .heart.lg,.actions .share{margin:0;padding:13px 16px;border-radius:14px}
.actions .heart.lg{border-radius:14px}
.detail>*,.about>*,.glass{min-width:0}
.long,.short,.in p,.row div,.row a{overflow-wrap:anywhere}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:200;background:#10151e;border:1px solid var(--line);color:#fff;padding:12px 18px;border-radius:14px;font-size:.92rem;box-shadow:0 10px 40px rgba(0,0,0,.6);max-width:90vw}
.mhint{padding:6px 16px;color:var(--mute);font-size:.8rem;border-top:1px solid var(--line)}
/* ---------- Messages page: list of chats on the left, the open chat on the right ---------- */
body.mpage{overflow:hidden}
body.mpage::after{display:none}
.mwrap{position:fixed;top:var(--bh,64px);left:0;right:0;bottom:0;padding:14px 20px 20px}
.msgr{height:100%;max-width:1180px;margin:0 auto;display:grid;grid-template-columns:350px minmax(0,1fr);border:1px solid var(--line);border-radius:20px;overflow:hidden;background:var(--panel)}
.mside{display:flex;flex-direction:column;min-width:0;min-height:0;border-right:1px solid var(--line)}
.mside-h{padding:18px 18px 14px;border-bottom:1px solid var(--line)}
.mside-h h2{font-size:1.3rem;letter-spacing:-.01em}
.mlist{flex:1;overflow-y:auto;overscroll-behavior:contain}
.citem{display:flex;gap:12px;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line);cursor:pointer;background:transparent;border-left:0;border-right:0;border-top:0;width:100%;text-align:left;font-family:inherit;color:inherit}
.citem:hover{background:rgba(255,255,255,.03)}
.citem.on{background:color-mix(in srgb,var(--a) 13%,transparent)}
.cav{width:48px;height:48px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-weight:800;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b));overflow:hidden}
.cav img{width:100%;height:100%;object-fit:cover;display:block}
.cmid{flex:1;min-width:0}
.cmid small{display:block;color:var(--mute);font-size:.75rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cmid b{display:block;font-size:.95rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cmid span{display:block;color:var(--soft);font-size:.86rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-top:2px}
.cend{display:flex;flex-direction:column;align-items:flex-end;gap:6px;color:var(--mute);font-size:.72rem;flex-shrink:0}
.mmain{display:flex;flex-direction:column;min-width:0;min-height:0}
.mempty{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;color:var(--mute);text-align:center;padding:30px}
.mempty .bigico{width:84px;height:84px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:color-mix(in srgb,var(--a) 14%,transparent);color:var(--a)}
.mempty .bigico svg{width:38px;height:38px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
.mpane{flex:1;display:flex;flex-direction:column;min-height:0}
.mhead{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--line)}
.mhead .cav{width:42px;height:42px}
.mtitle{flex:1;min-width:0}
.mtitle b{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mtitle small{color:var(--mute);font-size:.78rem}
.ibtn{width:42px;height:42px;border-radius:50%;border:1px solid var(--line);background:transparent;color:#fff;display:inline-flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;text-decoration:none;font-family:inherit;transition:border-color .2s,background .2s}
.ibtn svg{width:19px;height:19px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.ibtn:hover{border-color:var(--a)}
.ibtn.go{background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);border:0}
.ibtn:disabled{opacity:.5;cursor:default}
.mback{display:none}
.moffer{display:flex;gap:12px;align-items:center;padding:10px 16px;border-bottom:1px solid var(--line);text-decoration:none;color:inherit;background:rgba(255,255,255,.02)}
.moffer img,.moffer .ph2{width:44px;height:44px;border-radius:10px;object-fit:cover;flex-shrink:0;background:linear-gradient(135deg,var(--a),var(--b));display:flex;align-items:center;justify-content:center;color:var(--on);font-weight:800}
.moffer div{min-width:0}
.moffer b{display:block;font-size:.9rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.moffer span{color:var(--a);font-weight:700;font-size:.9rem}
.mbody{flex:1;min-height:0;overflow-y:auto;overscroll-behavior:contain;padding:14px 16px;display:flex;flex-direction:column;gap:6px}
.mbody .hint{margin:auto;color:var(--mute);text-align:center;max-width:32ch;font-size:.92rem}
.dsep{align-self:center;color:var(--mute);font-size:.72rem;margin:8px 0 2px;padding:3px 10px;border-radius:99px;background:rgba(255,255,255,.05)}
.bub.sys{align-self:center;max-width:90%;background:rgba(255,255,255,.05);border:1px solid var(--line);color:var(--soft);font-size:.82rem;padding:6px 14px;border-radius:99px;text-align:center}
.bub.sys small{display:inline;margin-left:8px}
.bub .att-img{display:block;max-width:100%;max-height:280px;border-radius:12px;margin-bottom:6px}
.bub .att-file{display:flex;gap:10px;align-items:center;text-decoration:none;color:inherit;padding:8px 10px;margin-bottom:6px;border-radius:12px;background:rgba(0,0,0,.2)}
.bub .att-file svg{width:22px;height:22px;flex-shrink:0;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.bub .att-file span{min-width:0;overflow-wrap:anywhere;font-size:.88rem}
.bub .att-file small{display:block;opacity:.65;margin:0;font-size:.72rem}
.mcomposer{display:flex;gap:8px;align-items:flex-end;padding:10px 12px calc(10px + env(safe-area-inset-bottom));border-top:1px solid var(--line)}
.mcomposer textarea{flex:1;min-width:0;resize:none;min-height:42px;max-height:130px;padding:11px 14px;border-radius:21px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#fff;font-family:inherit;font-size:.95rem;line-height:1.35}
.mcomposer textarea:focus{outline:2px solid var(--a);border-color:transparent}
.mnew{padding:12px 14px calc(12px + env(safe-area-inset-bottom));border-top:1px solid var(--line);display:grid;gap:8px}
.mnew input,.mnew textarea{width:100%;padding:11px 14px;border-radius:12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.05);color:#fff;font-family:inherit;font-size:.95rem}
.mnew textarea{min-height:70px;resize:none}
.mnew .two{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.mnew .chips button{font-size:.78rem;padding:6px 11px}
.mnew .err{color:#ff8aa5;font-size:.85rem;min-height:1em}
/* call screen */
.callov{position:fixed;inset:0;z-index:300;background:rgba(5,7,11,.92);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);display:none;align-items:center;justify-content:center;padding:24px}
.callov.open{display:flex}
.callbox{text-align:center;width:min(360px,100%)}
.callav{width:112px;height:112px;margin:0 auto 22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:2.8rem;font-weight:800;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b));box-shadow:0 0 0 0 color-mix(in srgb,var(--a) 50%,transparent);animation:pulse 1.8s infinite}
.callov.live .callav{animation:none}
.callbox h3{font-size:1.6rem;margin-bottom:6px}
.callbox p{color:var(--soft);min-height:1.5em}
.callbtns{display:flex;gap:22px;justify-content:center;margin-top:38px}
.cbtn{width:68px;height:68px;border-radius:50%;border:0;color:#fff;display:inline-flex;align-items:center;justify-content:center;cursor:pointer;background:rgba(255,255,255,.14)}
.cbtn svg{width:28px;height:28px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.cbtn.red{background:#e5484d}.cbtn.red svg{transform:rotate(135deg)}
.cbtn.green{background:#22c55e}
.cbtn.on{background:#fff;color:#111}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--a) 50%,transparent)}70%{box-shadow:0 0 0 28px transparent}100%{box-shadow:0 0 0 0 transparent}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes shine{to{background-position:220% center}}
@keyframes rise{from{opacity:0;transform:translateY(26px)}to{opacity:1;transform:none}}
@keyframes wheel{0%{opacity:0;transform:translateY(0)}30%{opacity:1}100%{opacity:0;transform:translateY(12px)}}
@keyframes slide{to{transform:translateX(-50%)}}
@media (max-width:860px){.detail,.about{grid-template-columns:1fr}.gal{position:static}.bar{padding:12px 16px}.wrap{padding:90px 18px 40px}}
/* ---------- storefront (home) ---------- */
.shop{max-width:1180px;margin:0 auto;padding:96px 24px 18px}
.shop-in{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:44px;align-items:center;min-height:min(540px,72vh)}
.shop h1{font-size:clamp(2.9rem,7.4vw,6rem);line-height:.96;letter-spacing:-.045em;font-weight:800;color:#f4f1ea;margin:0 0 16px;overflow-wrap:anywhere;padding:0;animation:none}
.shop-sub{color:var(--soft);font-size:clamp(1.02rem,1.6vw,1.2rem);margin-bottom:14px}
.shop-open{display:inline-flex;align-items:center;gap:10px;color:var(--soft);font-size:.95rem;margin-bottom:26px;max-width:100%}
.shop-open::before{content:'';width:9px;height:9px;border-radius:50%;background:var(--a);flex:none;box-shadow:0 0 0 4px color-mix(in srgb,var(--a) 22%,transparent)}
.shop .actions{margin:0}
.pics{position:relative;width:100%;max-width:470px;aspect-ratio:1/1;margin-left:auto}
.pics::before{content:'';position:absolute;inset:8% 4%;border-radius:50%;background:radial-gradient(closest-side,color-mix(in srgb,var(--a) 20%,transparent),transparent);filter:blur(10px)}
.tile{position:absolute;width:60%;aspect-ratio:4/5;border-radius:20px;overflow:hidden;background:var(--panel);border:1px solid var(--line);box-shadow:0 24px 60px rgba(0,0,0,.6);display:block;text-decoration:none;transition:transform .35s cubic-bezier(.2,.8,.2,1)}
.tile img{width:100%;height:100%;object-fit:cover;display:block}
.tile .ph{font-size:3.4rem}
.tile .tg{position:absolute;left:10px;bottom:10px;right:10px;display:flex;gap:8px;align-items:center;justify-content:space-between;background:#f4f1ea;color:#15130e;padding:7px 12px;border-radius:99px;font-weight:800;font-size:.85rem}
.tile .tg span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}
.tile .tg b{white-space:nowrap}
.t1{left:0;top:6%;transform:rotate(-5deg);z-index:1}
.t2{right:0;top:0;transform:rotate(4deg);z-index:2}
.t3{left:19%;bottom:0;transform:rotate(-1.5deg);z-index:3}
.pics.one .t3{left:20%;width:62%;bottom:auto;top:6%}
.tile:hover{transform:translateY(-8px) rotate(0)}
.sec-head{display:flex;align-items:baseline;justify-content:space-between;gap:16px;border-bottom:1px solid var(--line);padding-bottom:14px;margin-bottom:28px}
.wrap .sec-head h2{margin:0;font-size:clamp(1.7rem,3.6vw,2.4rem)}
.sec-head span{color:var(--mute);font-size:.92rem;white-space:nowrap}
.wrap.top{padding-top:40px}
.findus .about{align-items:start}
.findus .glass{background:none;border:0;padding:0;backdrop-filter:none;border-radius:0}
.findus .about h3{font-size:1.25rem}
.findus .row small{text-transform:none;letter-spacing:0;font-size:.88rem}
footer{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:baseline;gap:8px 24px;text-align:left;max-width:1180px;margin:30px auto 0;padding:26px 24px 40px}
footer b{display:inline;margin:0;font-size:1.05rem}
footer span{color:var(--mute)}
footer a{color:var(--mute)}
.seller{display:flex;align-items:center;gap:12px;padding:14px 0;margin:0 0 22px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);text-decoration:none}
.seller .sav{width:46px;height:46px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;font-weight:800;color:var(--on);background:linear-gradient(135deg,var(--a),var(--b))}
.seller div{min-width:0}
.seller b{display:block}
.seller small{display:block;color:var(--mute);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.seller em{margin-left:auto;font-style:normal;color:var(--a);font-weight:700;font-size:.9rem;white-space:nowrap}
.info h1{color:#f4f1ea}
/* messages page on tablets and phones: one screen at a time (list, then the chat) */
@media (max-width:860px){
.mwrap{padding:0}
.msgr{grid-template-columns:minmax(0,1fr);border:0;border-radius:0;max-width:none}
.msgr[data-view=list] .mmain{display:none}
.msgr[data-view=thread] .mside{display:none}
.mside{border-right:0}
.mback{display:inline-flex}
.mhead{padding:10px 12px}
}
/* phones: smaller type and spacing, nothing wider than the screen, two offers per row like a classifieds app */
@media (max-width:600px){
html{font-size:15px;-webkit-text-size-adjust:100%}
input,textarea,select{font-size:16px!important}
.bar{padding:10px 14px;gap:10px}
.bar b{font-size:.98rem}
.bar nav{gap:8px}
.bar nav a{padding:0;border-radius:50%;width:40px;height:40px;display:inline-flex;align-items:center;justify-content:center}
.bar nav .hide-m{display:none}
.navi .lab{display:none}
.navi .nbadge{position:absolute;top:-4px;right:-4px;min-width:17px;height:17px;font-size:.65rem}
.hero{padding:92px 18px 64px}
h1{font-size:clamp(2.1rem,11vw,3.2rem)}
.lead{font-size:.98rem;margin-top:16px}
.cta{margin-top:26px;padding:13px 26px}
.chip{margin-bottom:18px;padding:6px 14px;font-size:.8rem}
.strip{padding:14px 0}.strip span{font-size:1.1rem}.strip div,.strip span{gap:34px}
.wrap{padding:82px 14px 30px}
.wrap h2{font-size:1.65rem}
.sub{margin-bottom:26px;font-size:.95rem}
.grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.card{border-radius:16px}
.pic{aspect-ratio:1/1}
.in{padding:12px;transform:none}
.in h3{font-size:.95rem;margin-bottom:4px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.in p{font-size:.8rem;margin-bottom:8px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.more{font-size:.82rem}
.tag{right:8px;top:8px;padding:5px 10px;font-size:.8rem}
.count{left:8px;top:8px;padding:4px 8px;font-size:.68rem}
.heart{right:8px;bottom:8px;width:34px;height:34px}.heart svg{width:17px;height:17px}
.ph{font-size:2.6rem}
.steps{gap:12px}.step{padding:20px}
.glass{padding:18px;border-radius:18px}
.about{gap:16px}
.row small{width:76px}
.map{min-height:230px}.map iframe{min-height:230px}
.detail{gap:18px}
.wrap.offerwrap{padding-top:76px}
.gal{margin:0 -14px}
.main{border-radius:0;box-shadow:none}
.main .ph{font-size:4.5rem}
.thumbs{padding:4px 14px}
.thumbs button{flex-basis:64px;height:50px}
.nav{width:38px;height:38px}
.info h1{font-size:1.55rem;margin-bottom:10px}
.price{font-size:1.2rem;padding:6px 16px;margin-bottom:14px}
.short{font-size:.98rem;margin-bottom:14px}
.long{font-size:.94rem;margin-bottom:20px}
.actions{gap:8px;margin-bottom:18px}
.abtn{padding:12px 16px;font-size:.92rem}
.abtn.pri{flex:1 1 100%}
.heart.lg .t,.share .t2{display:none}
.actions .heart.lg,.actions .share{padding:12px 14px}
.crow{flex-wrap:wrap}.crow select{flex:1 1 100%}.crow input{flex:1 1 70%}
.req h2{font-size:1.15rem}
.steps{margin-top:6px}
footer{padding:32px 16px 96px;margin-top:30px}
.fab{padding:11px 16px;right:14px}
body.offerpage .fab{display:none}
.stick{gap:8px;padding:10px 12px calc(10px + env(safe-area-inset-bottom))}
.stick b{font-size:1.05rem;white-space:nowrap}
.stick a{padding:11px 16px;font-size:.9rem;text-align:center;white-space:nowrap}
.stick a.alt{background:transparent;color:#fff;border:1px solid rgba(255,255,255,.28)}
.msgr{font-size:.95rem}
.callbtns{gap:26px}
.shop{padding:70px 16px 8px}
.shop-in{grid-template-columns:minmax(0,1fr);gap:20px;min-height:0}
.shop h1{font-size:clamp(2.5rem,13.5vw,3.6rem)}
.shop-sub{font-size:1rem;margin-bottom:10px}
.shop-open{margin-bottom:18px;font-size:.9rem}
.pics{max-width:330px;margin:4px auto 0;aspect-ratio:1/.82}
.tile{width:54%;border-radius:16px}
.tile .tg{left:7px;right:7px;bottom:7px;padding:5px 9px;font-size:.76rem}
.tile .ph{font-size:2.4rem}
.wrap.top{padding-top:26px}
.sec-head{margin-bottom:18px;padding-bottom:10px}
footer{padding:22px 16px 40px;margin-top:10px}
.seller{padding:12px 0;margin-bottom:16px}
}
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
  if(sh)sh.addEventListener('click',function(){var d={title:document.title,url:location.href.split('#')[0]};if(navigator.share){navigator.share(d).catch(function(){})}else if(navigator.clipboard){navigator.clipboard.writeText(d.url);var lb2=sh.querySelector('.t2');if(lb2)lb2.textContent='Link copied'}});
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
  function paintFavs(){var a=favs();document.querySelectorAll('.heart').forEach(function(h){var on=a.indexOf(h.dataset.id)>-1;h.classList.toggle('on',on);h.setAttribute('aria-pressed',on)});var c=document.getElementById('favCount');if(c)c.textContent=a.length||''}
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
  var mb=document.getElementById('msgBadge');
  if(mb&&!document.getElementById('msgr')){var sv=[];try{sv=JSON.parse(localStorage.getItem('chats:'+slug)||'[]')}catch(e){}
    if(sv.length){var chk=function(){if(document.hidden)return;fetch('/site/'+slug+'/chat/list',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({chats:sv})}).then(function(r){return r.json()}).then(function(d){var n=0,ring=null;(d.conversations||[]).forEach(function(c){n+=c.unread||0;if(c.ringing)ring=c});mb.textContent=n||'';var bn=document.getElementById('ringBanner');if(ring&&!bn){bn=document.createElement('a');bn.id='ringBanner';bn.className='ringb';bn.href='/site/'+slug+'/messages';bn.textContent='\u260E  '+(document.body.getAttribute('data-seller')||'The shop')+' is calling you. Tap to answer';document.body.appendChild(bn)}else if(!ring&&bn){bn.remove()}}).catch(function(){})};chk();setInterval(chk,4000)}}
  paintFavs();
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


const LAYOUT_LOOK = {
  atelier:  { bg:'#efe3d0', panel:'#fbf5ea', text:'#2b1d14', mute:'#7a6552', line:'rgba(60,35,15,.2)', a:'#b9542c', b:'#d98a4e', on:'#ffffff', btn:'#7a2e14', btnText:'#fff', r:'4px', shadow:'0 14px 34px rgba(80,45,15,.12)', font:"Georgia,'Times New Roman',serif", head:"Georgia,'Times New Roman',serif", light:true },
  editorial:{ bg:'#ffffff', panel:'#ffffff', text:'#0b0b0b', mute:'#555555', line:'#0b0b0b', a:'#e10600', b:'#111111', on:'#ffffff', btn:'#e10600', btnText:'#fff', r:'0', shadow:'none', font:"'Helvetica Neue',Arial,sans-serif", head:"Georgia,'Times New Roman',serif", light:true, border:'1.5px solid #0b0b0b' },
  aurora:   { bg:'#eef6ff', bgCss:'linear-gradient(155deg,#e6fbf2,#ece6ff 55%,#ffe8f2)', panel:'rgba(255,255,255,.72)', text:'#1e2340', mute:'#5b6288', line:'rgba(91,108,255,.2)', a:'#5b6cff', b:'#2fd6b0', on:'#ffffff', btn:'linear-gradient(135deg,#5b6cff,#2fd6b0)', btnText:'#fff', r:'28px', shadow:'0 18px 44px rgba(91,108,255,.16)', font:"'Trebuchet MS',Verdana,sans-serif", head:"'Trebuchet MS',Verdana,sans-serif", light:true, blur:true },
  mono:     { bg:'#e6e6e2', panel:'#f7f7f4', text:'#111111', mute:'#666660', line:'#111111', a:'#111111', b:'#444444', on:'#ffffff', btn:'#111111', btnText:'#fff', r:'2px', shadow:'none', font:"'Courier New',Courier,monospace", head:"'Courier New',Courier,monospace", light:true, border:'1px dashed #111' },
  market:   { bg:'#04201b', bgCss:'radial-gradient(900px circle at 85% -10%,rgba(255,138,31,.2),transparent 55%),#04201b', panel:'#0a342b', text:'#f3fff9', mute:'#9fc9b9', line:'rgba(120,255,200,.22)', a:'#ff8a1f', b:'#ffd23f', on:'#1b0e00', btn:'linear-gradient(135deg,#ff8a1f,#ffd23f)', btnText:'#1b0e00', r:'24px', shadow:'0 16px 40px rgba(0,0,0,.35)', font:"'Segoe UI',Tahoma,sans-serif", head:"'Trebuchet MS','Segoe UI',sans-serif" },
  arcade:   { bg:'#12002b', bgCss:'repeating-linear-gradient(0deg,rgba(255,47,179,.06) 0 1px,transparent 1px 30px),#12002b', panel:'#1e0a45', text:'#ffffff', mute:'#c7a8ff', line:'#ff2fb3', a:'#ffe600', b:'#ff2fb3', on:'#1a0035', btn:'#ffe600', btnText:'#1a0035', r:'0', shadow:'6px 6px 0 #ff2fb3', font:"'Courier New',Courier,monospace", head:"'Courier New',Courier,monospace", border:'2px solid #ff2fb3', upper:true },
  neon:     { bg:'#02030a', bgCss:'radial-gradient(700px circle at 10% 0%,rgba(0,240,255,.16),transparent 50%),radial-gradient(700px circle at 95% 100%,rgba(162,59,255,.2),transparent 50%),#02030a', panel:'#070a18', text:'#eaf6ff', mute:'#7f8db8', line:'rgba(0,240,255,.35)', a:'#00f0ff', b:'#a23bff', on:'#02030a', btn:'linear-gradient(135deg,#00f0ff,#a23bff)', btnText:'#02030a', r:'14px', shadow:'0 0 30px rgba(0,240,255,.14)', font:"'Segoe UI',Tahoma,sans-serif", head:"'Segoe UI',Tahoma,sans-serif", glow:true }
};
function layoutLookCss(c) {
  const o = LAYOUT_LOOK[c]; if (!o) return '';
  const L = 'body.layout-' + c;
  const cards = ['.card','.glass','.sp-hero','.sp-about','.sp-review-summary','.sp-review-list','.mwrap .mside','.mwrap .mmain','.detail .main','.detail .req','.detail .seller','.moffer'].map(x => L + ' ' + x).join(',');
  return `
${L}{--bg:${o.bg};--panel:${o.panel};--line:${o.line};--mute:${o.mute};--soft:${o.mute};--a:${o.a};--b:${o.b};--on:${o.on};--ink:${o.a};color:${o.text};background:${o.bgCss || o.bg} !important;font-family:${o.font}}
${L} h1,${L} h2,${L} h3,${L} .bar b,${L} .info h1,${L} .sp-intro h1{font-family:${o.head};color:${o.text}${o.upper ? ';text-transform:uppercase;letter-spacing:.02em' : ''}}
${L} .bar{background:${o.light ? o.panel : o.bg};color:${o.text};border-bottom:${o.border || '1px solid ' + o.line}${o.blur ? ';backdrop-filter:blur(14px)' : ''}}
${L} .bar nav a{color:${o.text};border:${o.border || '1px solid ' + o.line};border-radius:${o.r === '0' ? '0' : '999px'};background:transparent}
${cards}{background:${o.panel};color:${o.text};border:${o.border || '1px solid ' + o.line};border-radius:${o.r};box-shadow:${o.shadow}${o.blur ? ';backdrop-filter:blur(12px)' : ''}}
${L} .card::before,${L} .card::after{${o.glow ? 'opacity:.9;background:linear-gradient(135deg,#00f0ff,transparent 40%,transparent 60%,#a23bff)' : 'display:none'}}
${L} .in h3,${L} .sp-about h3,${L} footer b,${L} .mhead b,${L} .price{color:${o.text}}
${L} .in p,${L} .sub,${L} .short,${L} .long,${L} .sp-subtle,${L} .sp-about p,${L} .crumb,${L} .sp-tabs a{color:${o.mute}}
${L} .tag,${L} .count,${L} .price,${L} .sp-proof span,${L} .seller-pill,${L} .seller-chip{background:${o.light ? 'rgba(0,0,0,.05)' : 'rgba(255,255,255,.06)'};color:${o.text};border:${o.border || '1px solid ' + o.line};border-radius:${o.r === '0' ? '0' : '999px'};box-shadow:none}
${L} .sp-btn.sp-primary,${L} .btn,${L} .abtn.pri{background:${o.btn};color:${o.btnText};border-radius:${o.r === '0' ? '0' : o.r === '4px' || o.r === '2px' ? o.r : '999px'};border:0;box-shadow:${o.glow ? '0 0 26px rgba(0,240,255,.3)' : o.shadow === 'none' ? 'none' : o.shadow};font-weight:800}
${L} .sp-btn,${L} .abtn{border-radius:${o.r === '0' ? '0' : o.r === '4px' || o.r === '2px' ? o.r : '999px'}}
${L} input,${L} textarea,${L} select,${L} .mcomposer textarea{background:${o.light ? '#fff' : 'rgba(255,255,255,.07)'};color:${o.text};border:${o.border || '1px solid ' + o.line}}
${L} .sp-tabs{background:${o.panel};border-bottom-color:${o.line}}
${L} .sp-avatar,${L} .seller .sav{background:${o.btn};color:${o.btnText};border-radius:${o.r === '0' ? '0' : '50%'}}
${L} .ph-art{background:${o.panel};color:${o.text};border-radius:${o.r}}
${L} .ph-art strong{color:${o.text}} ${L} .ph-art small{color:${o.mute}}
${L} .ph-art-bg{background:linear-gradient(135deg,color-mix(in srgb,${o.a} 40%,transparent),color-mix(in srgb,${o.b} 25%,transparent))}
${L} .ph-art::after{background:none}
${L} a.more,${L} .more{color:${o.light ? o.text : o.a}}
`;
}

function layoutGlobalCss(layout) {
  return `
.layout-atelier{--bg:#eee9e0;--panel:#fffdf9;--line:rgba(40,37,32,.14);--mute:#66635f;--soft:#504b43;color:#252321}
.layout-atelier .bar{background:rgba(238,233,224,.88);color:#212020;border-bottom:1px solid #d8d1c6}
.layout-atelier .bar nav a{color:#212020;border-color:#d8d1c6}
.layout-atelier .card,.layout-atelier .glass,.layout-atelier .sp-hero,.layout-atelier .sp-about,.layout-atelier .sp-review-summary,.layout-atelier .sp-review-list,.layout-atelier .mwrap .mside,.layout-atelier .mwrap .mmain,.layout-atelier .detail .req{background:#fffdf9;color:#242321;box-shadow:0 14px 38px rgba(42,31,12,.065);border-radius:4px}
.layout-atelier .sp-intro h1,.layout-atelier .sp-about h3,.layout-atelier .in h3,.layout-atelier .info h1{color:#262321;font-family:Georgia,serif}
.layout-atelier .in p,.layout-atelier .sp-about p,.layout-atelier .sp-subtle{color:#68615a}
.layout-atelier .tag,.layout-atelier .price,.layout-atelier .sp-proof span{box-shadow:none;background:#f1ebe2;color:#262321;border:1px solid #d9d0c4}
.layout-atelier .sp-btn.sp-primary,.layout-atelier .btn,.layout-atelier .abtn.pri{background:#262321;color:#fff;box-shadow:none}
.layout-atelier .sp-tabs{background:#eee9e0;border-bottom-color:#d8d1c6}
.layout-atelier .sp-tabs a,.layout-atelier .crumb{color:#58524c}
.layout-atelier .sp-avatar,.layout-atelier .seller .sav{background:#d9c7a8;color:#352d23}
.layout-atelier .ph-art{background:#dfd4c1;color:#262321}
.layout-atelier .ph-art-bg{background:linear-gradient(135deg,rgba(255,255,255,.55),transparent)}
.layout-arcade{--a:#dbff36;--b:#56efff;--on:#10110c;--bg:#090a12;--panel:#141425;--line:rgba(219,255,54,.28);--mute:#acb0c8;--soft:#e5ecfa}
.layout-arcade .bar{background:#090a12;border-bottom:2px solid #dbff36}
.layout-arcade .card,.layout-arcade .glass,.layout-arcade .sp-hero,.layout-arcade .sp-about,.layout-arcade .sp-review-summary,.layout-arcade .sp-review-list,.layout-arcade .mwrap .mside,.layout-arcade .mwrap .mmain,.layout-arcade .detail .main,.layout-arcade .detail .req{border-radius:7px;background:#141425;box-shadow:8px 8px 0 rgba(219,255,54,.08);border:1px solid rgba(219,255,54,.25)}
.layout-arcade .card::before{opacity:1;background:linear-gradient(130deg,#dbff36,transparent 50%,#56efff)}
.layout-arcade .sp-avatar,.layout-arcade .seller .sav{background:#dbff36;color:#10110c;border-radius:5px}
.layout-arcade .sp-btn,.layout-arcade .abtn,.layout-arcade .btn{border-radius:6px}
.layout-arcade .ph-art-bg{background:repeating-linear-gradient(0deg,rgba(219,255,54,.08) 0 1px,transparent 1px 28px),linear-gradient(135deg,#111627,#080a11)}
.layout-aurora{--a:#78e1d0;--b:#b5acff;--on:#0f2630;--bg:#101524;--panel:#172034;--line:rgba(177,203,255,.17);--mute:#b4c1d5;--soft:#e0e8fb}
.layout-aurora .bar{background:rgba(19,27,48,.72);border-bottom:1px solid rgba(186,192,255,.17)}
.layout-aurora .card,.layout-aurora .glass,.layout-aurora .sp-hero,.layout-aurora .sp-about,.layout-aurora .sp-review-summary,.layout-aurora .sp-review-list,.layout-aurora .mwrap .mside,.layout-aurora .mwrap .mmain,.layout-aurora .detail .main,.layout-aurora .detail .req{border-radius:30px;background:linear-gradient(135deg,#202844,#131f34);box-shadow:0 24px 65px rgba(0,0,0,.24)}
.layout-aurora .sp-avatar,.layout-aurora .seller .sav{background:linear-gradient(135deg,#78e1d0,#b5acff);color:#131c27;border-radius:25px}
.layout-aurora .ph-art-bg{background:radial-gradient(circle at 35% 18%,rgba(120,225,208,.35),transparent 42%),radial-gradient(circle at 85% 85%,rgba(181,172,255,.4),transparent 45%),linear-gradient(145deg,#151e31,#0c1220)}

.ph-art{position:relative;display:flex;flex-direction:column;justify-content:flex-end;align-items:flex-start;padding:18px;background:linear-gradient(160deg,#121721,#0b1017 60%,rgba(255,255,255,.02));color:#fff;isolation:isolate;font-size:inherit}
.ph-art small{position:relative;z-index:2;font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;color:rgba(255,255,255,.55);margin-bottom:8px}
.ph-art strong{position:relative;z-index:2;font-size:clamp(1.2rem,2vw,1.8rem);line-height:1.1;max-width:12ch}
.ph-art-bg,.ph-art::after{position:absolute;inset:0;border-radius:inherit;content:''}
.ph-art-bg{background:radial-gradient(560px circle at 0% 0%,color-mix(in srgb,var(--a) 46%,transparent),transparent 52%),linear-gradient(135deg,rgba(255,255,255,.06),transparent 45%,rgba(255,255,255,.02));opacity:.95}
.ph-art::after{background:linear-gradient(180deg,transparent 10%,rgba(0,0,0,.48));z-index:1}
.seller-chip,.seller-pill{background:rgba(255,255,255,.04);border:1px solid var(--line);border-radius:18px}
.layout-signature .bar{background:rgba(5,7,11,.58)}
.layout-editorial body,.layout-editorial{--bg:#ece9e2;--panel:#ffffff;--line:rgba(19,24,32,.12);--mute:#62676f;--soft:#353a42;color:#16181c}
.layout-editorial body::after{opacity:.02}
.layout-editorial .bar{background:rgba(237,233,226,.8);color:#111;border-bottom:1px solid rgba(19,24,32,.1)}
.layout-editorial .bar nav a{border-color:rgba(19,24,32,.15);color:#1f2328;background:rgba(255,255,255,.5)}
.layout-editorial .card,.layout-editorial .glass,.layout-editorial .sp-hero,.layout-editorial .sp-about,.layout-editorial .sp-review-summary,.layout-editorial .sp-review-list,.layout-editorial .mwrap .mside,.layout-editorial .mwrap .mmain,.layout-editorial .detail .main,.layout-editorial .detail .req,.layout-editorial .detail .seller{background:#fff;color:#1a1d22;box-shadow:0 18px 40px rgba(0,0,0,.06)}
.layout-editorial .in h3,.layout-editorial .info h1,.layout-editorial .sp-intro h1,.layout-editorial footer b,.layout-editorial .mhead b{color:#17191d}
.layout-editorial .in p,.layout-editorial .sub,.layout-editorial .short,.layout-editorial .long,.layout-editorial .sp-subtle,.layout-editorial .sp-about p{color:#5b6068}
.layout-editorial .sp-proof span,.layout-editorial .tag,.layout-editorial .count,.layout-editorial .price,.layout-editorial .seller-pill{background:#f4f1ea;color:#17191d;border-color:#ddd5c6;box-shadow:none}
.layout-editorial .mcomposer textarea,.layout-editorial input,.layout-editorial textarea,.layout-editorial select{background:#f6f2eb;color:#181a1f;border-color:#ddd5c6}
.layout-editorial .ph-art{background:linear-gradient(160deg,#f6efe4,#ebe4d8)}
.layout-market .bar{background:rgba(6,18,24,.7)}
.layout-market .detail{grid-template-columns:1fr 1.08fr}
.layout-market .sp-hero,.layout-market .sp-about,.layout-market .mwrap .mside,.layout-market .mwrap .mmain{border-radius:28px}
.layout-neon{--a:#44f6ff;--b:#9b4dff;--ink:#7dd3fc;--on:#081018;--panel:#090d17;--bg:#03040a;--line:rgba(93,116,255,.23);--mute:#8690b2;--soft:#c9d0ff}
.layout-neon .bar{background:rgba(4,6,16,.78);border-bottom-color:rgba(77,95,255,.35);box-shadow:0 10px 40px rgba(0,0,0,.28)}
.layout-neon .bar nav a{border-color:rgba(88,99,255,.28)}
.layout-neon .card,.layout-neon .glass,.layout-neon .sp-hero,.layout-neon .sp-about,.layout-neon .sp-review-summary,.layout-neon .sp-review-list,.layout-neon .mwrap .mside,.layout-neon .mwrap .mmain,.layout-neon .detail .main,.layout-neon .detail .req,.layout-neon .detail .seller{border-radius:18px;background:linear-gradient(180deg,rgba(11,15,28,.96),rgba(8,10,18,.96));box-shadow:0 0 0 1px rgba(82,96,255,.22),0 0 36px rgba(68,246,255,.08),0 24px 60px rgba(0,0,0,.6)}
.layout-neon .card::before{opacity:.95;background:linear-gradient(135deg,#44f6ff,transparent 36%,transparent 64%,#9b4dff)}
.layout-neon .tag,.layout-neon .count,.layout-neon .price,.layout-neon .sp-proof span{border-color:rgba(68,246,255,.35)}
.layout-neon .abtn.pri,.layout-neon .sp-btn.sp-primary,.layout-neon .btn{background:linear-gradient(135deg,#44f6ff,#9b4dff);color:#081018;box-shadow:0 0 24px rgba(68,246,255,.18)}
.layout-neon .moffer,.layout-neon .sp-tabs,.layout-neon .seller{border-color:rgba(82,96,255,.25)}
.layout-neon .ph-art-bg{background:radial-gradient(360px circle at 10% 10%,rgba(68,246,255,.34),transparent 42%),radial-gradient(360px circle at 90% 90%,rgba(155,77,255,.24),transparent 40%),linear-gradient(140deg,#0a1020,#0b0f1b)}
.layout-neon .wrap h2,.layout-neon .info h1,.layout-neon .sp-intro h1{letter-spacing:-.045em}
.layout-mono{--a:#e8edf3;--b:#bfc7d5;--ink:#475569;--on:#0b0d10;--panel:#101317;--bg:#07090c;--line:rgba(255,255,255,.08);--mute:#98a0ad;--soft:#d5dae2}
.layout-mono .bar{background:rgba(7,9,12,.82)}
.layout-mono .bar nav a,.layout-mono .sp-btn,.layout-mono .abtn,.layout-mono .btn{border-radius:10px}
.layout-mono .card,.layout-mono .glass,.layout-mono .sp-hero,.layout-mono .sp-about,.layout-mono .sp-review-summary,.layout-mono .sp-review-list,.layout-mono .mwrap .mside,.layout-mono .mwrap .mmain,.layout-mono .detail .main,.layout-mono .detail .req,.layout-mono .detail .seller{background:#11151a;border-radius:14px;box-shadow:0 0 0 1px rgba(255,255,255,.06),0 18px 50px rgba(0,0,0,.45)}
.layout-mono .card::before,.layout-mono .card::after{display:none}
.layout-mono .tag,.layout-mono .count,.layout-mono .price,.layout-mono .sp-proof span{background:#0d1015;border-color:rgba(255,255,255,.12);box-shadow:none}
.layout-mono .abtn.pri,.layout-mono .sp-btn.sp-primary,.layout-mono .btn{background:linear-gradient(180deg,#f3f4f6,#bfc7d5);color:#0b0d10;box-shadow:none}
.layout-mono .ph-art-bg{background:linear-gradient(135deg,rgba(255,255,255,.12),transparent 55%),linear-gradient(180deg,#161a20,#0f1318)}
.layout-mono .more{color:#f1f5f9}
.layout-mono .sp-avatar,.layout-mono .seller .sav{background:#1b2027;color:#eef2f7}
.layout-editorial .sp-avatar,.layout-editorial .seller .sav{background:#ede7dc;color:#15181c}
.layout-neon .sp-avatar,.layout-neon .seller .sav{background:linear-gradient(135deg,#44f6ff,#9b4dff);color:#081018}
.layout-market .sp-avatar,.layout-market .seller .sav,.layout-signature .sp-avatar,.layout-signature .seller .sav{background:linear-gradient(135deg,var(--a),var(--b));color:var(--on)}
.layout-neon .moffer,.layout-market .moffer,.layout-mono .moffer,.layout-editorial .moffer{border-radius:16px}
@media(max-width:820px){.layout-neon .detail,.layout-market .detail{grid-template-columns:1fr}}
${layoutLookCss(layout)}`;
}

const sentTrack = (u) => u._track ? ` <a href="/track/${u._track}" style="color:var(--a);font-weight:700">Track your request &rarr;</a>` : '';
function pageShell(user, { title, desc, body, cls, page }) {
  const t = THEMES[user.theme] || THEMES.gold;
  const f = FONTS[user.font] || FONTS.sans;
  page = page || 'home';
  const D = user._gd !== undefined ? user._gd : user.design; const studio = !!user._studio;
  const dFonts = GD.fontLinks(D).map(g => `<link href="https://fonts.googleapis.com/css2?family=${g}&display=swap" rel="stylesheet">`).join('');
  return `<!DOCTYPE html>
<html lang="${esc(/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$/.test(user.siteLang || '') ? user.siteLang : 'en')}"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta name="theme-color" content="#05070b">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=${f.gf}&display=swap" rel="stylesheet">
${dFonts}<style>${siteCss(t, f)}</style><style>${layoutGlobalCss(safeLayout(user.layout))}</style><style id="go-design-css">${GD.css(D, page)}</style></head><body class="${cls || ''} layout-${esc(safeLayout(user.layout))}" data-page="${esc(page)}" data-slug="${esc(user.slug)}" data-seller="${esc(sellerName(user))}">
${user.announcementText ? `<aside class="go-public-announcement">${esc(user.announcementText)}</aside><style>.go-public-announcement{position:relative;z-index:2;margin:70px auto -60px;width:min(100% - 36px,1180px);padding:12px 20px;border-radius:12px;background:color-mix(in srgb,var(--a) 13%,var(--panel));border:1px solid color-mix(in srgb,var(--a) 30%,transparent);color:inherit;text-align:center;font-size:14px}</style>` : ''}
${body}
${GD.freeHtml(D, page)}
<script type="application/json" id="go-design">${JSON.stringify(D || {}).replace(/</g, '\\u003c')}</script><script>${GO_APPLY_JS}</script>${studio ? `<script>(${goStudioClient.toString()})(${goDesignCore.toString()})</script>` : ''}
${studio ? '' : `<script>(function(){try{var p=location.pathname.split('/');if(p[1]==='site'&&p[2]){fetch('/api/storefront/'+encodeURIComponent(p[2])+'/track',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind:p[3]==='offer'?'offer':'view',offerId:p[3]==='offer'?p[4]:undefined}),keepalive:true}).catch(function(){})}}catch(e){}})()</script>`}
<script>(function(){var d=document.getElementById('bkDate');if(!d)return;var slug=document.body.getAttribute('data-slug'),box=document.getElementById('bkSlots'),hid=document.getElementById('bkStart'),off=document.getElementById('bkOffer');var t=new Date();d.min=t.toISOString().slice(0,10);function load(){hid.value='';if(!d.value)return;box.textContent='Loading...';fetch('/site/'+encodeURIComponent(slug)+'/slots?date='+d.value+(off&&off.value?'&offerId='+off.value:''),{cache:'no-store'}).then(function(r){return r.json()}).then(function(j){box.textContent='';if(!j.slots||!j.slots.length){box.textContent='No free times on this day. Try another day.';return}j.slots.forEach(function(s){var b=document.createElement('button');b.type='button';b.textContent=s.time;b.style.cssText='padding:9px 14px;border-radius:10px;border:1px solid var(--line);background:transparent;color:inherit;font-weight:700;cursor:pointer';b.onclick=function(){hid.value=s.iso;[].forEach.call(box.children,function(x){x.style.background='transparent';x.style.color='inherit'});b.style.background='var(--a)';b.style.color='var(--on)'};box.appendChild(b)})}).catch(function(){box.textContent='Could not load times.'})}d.addEventListener('change',load);if(off)off.addEventListener('change',load);var f=d.form;if(f)f.addEventListener('submit',function(e){if(!hid.value){e.preventDefault();box.textContent='Please pick a time first.'}})})();</script>
<script>(function(){var form=document.querySelector('#book form');if(form)form.addEventListener('submit',function(){var x=form.querySelector('[name="startsAt"]');if(x){var d=new Date(x.value);if(Number.isFinite(d.getTime())){x.type='hidden';x.value=d.toISOString()}}})})();</script>
<script>${SITE_JS}</script>
${!studio && user.siteLang === 'bg' ? `<script>${SITE_I18N_JS}</script>` : !studio && user.siteTranslations && user.siteTranslations[user.siteLang] ? `<script>(${goI18nClient.toString()})(${JSON.stringify(user.siteTranslations[user.siteLang]).replace(/</g,'\\u003c')},[])</script>` : ''}
${studio ? '' : `<script>(function(){
  var slug = document.body.getAttribute('data-slug');
  var token = null;
  try { token = localStorage.getItem('token'); } catch(e) {}
  if (!slug || !token) return;
  fetch('/api/auth/me', {headers:{Authorization:'Bearer '+token},cache:'no-store'})
    .then(function(r){return r.ok?r.json():null;})
    .then(function(d){
      if (!d || !d.user || d.user.slug!==slug) return;
      var vis=false;try{vis=sessionStorage.getItem('goVisitor')==='1';}catch(e){}
      if(location.search.indexOf('visitor=1')>-1){vis=true;try{sessionStorage.setItem('goVisitor','1');}catch(e){}}
      if(vis){var vb=document.createElement('div');vb.className='go-owner-banner';vb.innerHTML='<span>Visitor test mode — you can write and order like a customer.</span><a href="#" id="goOwnerBack">Back to owner mode</a>';document.body.appendChild(vb);document.getElementById('goOwnerBack').onclick=function(e){e.preventDefault();try{sessionStorage.removeItem('goVisitor');}catch(x){}location.href=location.pathname;};return;}
      document.body.classList.add('go-site-owner');
      var prefix='/site/'+encodeURIComponent(slug);
      document.querySelectorAll('a[href^="'+prefix+'/messages"]').forEach(function(a){a.setAttribute('title','Open your business inbox here');a.setAttribute('aria-label','Business inbox');if(a.textContent.trim())a.textContent='Business inbox';});
      document.querySelectorAll('a[href^="'+prefix+'/offer/"]').forEach(function(a){a.setAttribute('data-owner-offer','true');});
      document.querySelectorAll('form[action="'+prefix+'/order"]').forEach(function(f){
        f.addEventListener('submit',function(e){e.preventDefault();window.location.assign('/dashboard');});
        f.style.display='none';
        var wrap=f.closest('.req');if(wrap){var h=wrap.querySelector('h2');if(h)h.textContent='Your own offer';var note=document.createElement('p');note.textContent='You are viewing your own website. Customers can send requests here; manage them in your Dashboard.';note.style.cssText='color:var(--soft);margin:10px 0 18px;line-height:1.6';wrap.appendChild(note);var a=document.createElement('a');a.href='/dashboard';a.className='abtn pri';a.textContent='Open Dashboard';wrap.appendChild(a);}
      });
      var note=document.createElement('div');note.className='go-owner-banner';note.setAttribute('role','status');note.innerHTML='<span>Owner preview — you are viewing your own website.</span><a href="'+prefix+'?visitor=1">Test as visitor</a><a href="'+prefix+'/messages">Business inbox</a><a href="/dashboard">Dashboard</a>';
      document.body.appendChild(note);
      if(location.pathname===prefix+'/messages'){
        var wrap=document.querySelector('.mwrap');if(wrap){wrap.style.display='none';}
        var landing=document.createElement('section');landing.className='go-owner-landing';landing.innerHTML='<h1>Business inbox</h1><p>Reply to your customers directly from your own storefront.</p><iframe title="Your business messages" src="/messages" loading="eager" allow="microphone"></iframe>';
        document.body.insertBefore(landing,document.querySelector('footer'));document.body.classList.remove('mpage');document.documentElement.style.overflowY='auto';document.body.style.overflowY='auto';document.body.style.height='auto';
      }
    }).catch(function(){});
})();</script>`}
<style>.go-owner-banner{position:fixed;z-index:80;left:12px;right:12px;bottom:12px;display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:12px;padding:11px 16px;border-radius:13px;background:rgba(15,21,32,.96);border:1px solid rgba(255,255,255,.15);color:#ecf0f7;box-shadow:0 16px 40px #0008;font:600 13px system-ui}.go-owner-banner a{color:var(--a);text-decoration:none}body.go-site-owner,body.go-site-owner.mpage{overflow-y:auto!important;height:auto!important}.go-owner-landing{padding-bottom:96px!important;max-width:1180px!important;min-height:50vh;margin:115px auto 45px;padding:32px 24px;text-align:center}.go-owner-landing h1{font-size:clamp(30px,5vw,52px)}.go-owner-landing p{color:var(--soft);margin:18px 0 25px}.go-owner-landing iframe{display:block;width:100%;height:calc(100vh - 150px);min-height:560px;border:1px solid var(--line);border-radius:18px;background:#080c13}.go-owner-landing{max-width:1200px;text-align:left}.go-owner-landing a{display:inline-block;border-radius:12px;padding:13px 22px;background:var(--a);color:var(--on);font-weight:700;text-decoration:none}@media(max-width:650px){.go-owner-banner{font-size:11px;gap:8px;padding:10px}}</style>
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
  return `<section class="about">
<div class="glass"><h3>${esc(user.siteName)}</h3><div class="cat">${cat}</div>${rows || '<div class="row"><small>Info</small><div>Contact details will appear here soon.</div></div>'}</div>
${q ? `<div><div class="map"><iframe title="Map" loading="lazy" referrerpolicy="no-referrer-when-downgrade" src="https://www.google.com/maps?q=${encodeURIComponent(q)}&output=embed"></iframe></div><a class="mapbtn" href="https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}" target="_blank" rel="noopener">Open in Google Maps &rarr;</a></div>` : ''}
</section>`;
}

function offerCard(user, o, i) {
  const g = galleryOf(o);
  const tracked=user._stockMap&&Object.prototype.hasOwnProperty.call(user._stockMap,String(o._id));
  const stock=tracked?Number(user._stockMap[String(o._id)]):null;
  return `<a class="card rv" style="--d:${(i % 6) * 70}ms" href="/site/${esc(user.slug)}/offer/${o._id}">
  <div class="pic">${g.length ? `<img src="${esc(g[0])}" alt="${esc(o.title)}" loading="lazy">` : artPlaceholder(o.title, user.categoryLabel || user.category || user.siteName)}
    <span class="tag">${eur(o.price)}</span>${stock===0?'<span class="count" style="top:auto;bottom:12px;background:#6b1723">Sold out</span>':''}${HEART_SMALL(o._id)}${g.length > 1 ? `<span class="count">${g.length} photos</span>` : ''}</div>
  <div class="in"><h3>${esc(o.title)}</h3><p>${esc(o.description)}</p><span class="more">View details</span></div>
</a>`;
}


function renderSellerProfile(user, offers) {
  const slug=esc(user.slug), name=esc(sellerName(user));
  const phone=String(user.phone||'').replace(/[^\d+]/g,'');
  const intro=[user.categoryLabel||user.category,user.city].filter(Boolean).join(' · ');
  const contact=`<a class="sp-btn sp-primary" href="/site/${slug}/messages">${MSG_SVG} Message</a>${phone?`<a class="sp-btn" href="tel:${esc(phone)}">${PHONE_SVG} Call</a>`:''}`;
  const cards=offers.map((o,i)=>offerCard(user,o,i)).join('');
  const body=`${siteBar(user,'profile')}
  <main class="sp-wrap">
    <a class="sp-back" href="/site/${slug}">← Back to website</a>
    <section class="sp-hero">
      <div class="sp-identity"><div class="sp-avatar">${user.logoUrl?`<img src="${esc(user.logoUrl)}" alt="">`:esc(initials(sellerName(user)))}</div><div class="sp-intro"><span class="sp-eyebrow">SELLER PROFILE</span><h1>${name}</h1><p>${esc(intro||user.siteName||'Independent seller')}</p><div class="sp-proof"><span>📍 ${esc(user.city||'Location not specified')}</span><span>◉ ${offers.length} offers</span><span id="spRating">★ No ratings yet</span>${user.verificationStatus==='approved'?'<span>✓ Verified seller</span>':''}<span>Joined ${esc(new Date(user.createdAt||Date.now()).getFullYear())}</span></div></div></div>
      <div class="sp-buttons">${contact}<button id="spFollow" class="sp-btn" type="button" aria-pressed="false">♡ Save seller</button><button id="spShare" class="sp-btn" type="button">↗ Share</button></div>
    </section>
    <nav class="sp-tabs" aria-label="Seller profile sections"><a href="#offers">Offers</a><a href="#about-seller">About</a><a href="#reviews">Reviews <span id="spReviewCount"></span></a></nav>
    <section id="offers" class="sp-section"><div class="sp-section-head"><div><span class="sp-eyebrow">EXPLORE</span><h2>Offers from ${name}</h2></div><span class="sp-subtle">${offers.length} listings</span></div>${offers.length?`<div class="grid">${cards}</div>`:'<p>No offers published yet.</p>'}</section>
    <section id="about-seller" class="sp-section"><div class="sp-section-head"><div><span class="sp-eyebrow">GET TO KNOW</span><h2>About ${name}</h2></div></div><div class="sp-about"><div><h3>${esc(user.siteName||sellerName(user))}</h3><p>${esc(user.sellerBio || [user.categoryLabel||user.category,user.city].filter(Boolean).join(' in ') || 'Explore the offers or send a message to learn more.')}</p><div class="sp-proof">${user.address?`<span>📍 ${esc(user.address)}</span>`:''}${user.hours?`<span>◷ ${esc(String(user.hours).split('\n')[0])}</span>`:''}</div></div><div class="sp-about-actions">${contact}</div></div></section>
    <section id="reviews" class="sp-section"><div class="sp-section-head"><div><span class="sp-eyebrow">COMMUNITY FEEDBACK</span><h2>Reviews of ${name}</h2><p class="sp-subtle">Visitor feedback. Purchase verification is not available yet.</p></div><button type="button" class="sp-btn sp-primary" id="spLeave">☆ Leave a review</button></div><div class="sp-review-box"><div class="sp-review-summary"><strong id="spAvg">—</strong><span id="spStars">☆☆☆☆☆</span><small id="spCount">No reviews yet</small><div id="spBars"></div></div><div id="spReviewList" class="sp-review-list" aria-live="polite">Loading feedback…</div></div></section>
  </main>
  <div class="sp-overlay" id="spModal" hidden><div class="sp-dialog" role="dialog" aria-modal="true" aria-labelledby="spModalTitle"><div class="sp-modal-head"><h2 id="spModalTitle">Review ${name}</h2><button id="spClose" type="button" aria-label="Close">✕</button></div><p class="sp-subtle">Your review is about this seller. Reviews are submitted by visitors and are not purchase-verified.</p><form id="spForm"><label>Your name<input name="name" required minlength="2" maxlength="60" autocomplete="name" placeholder="Your name"></label><label>Email (not shown publicly)<input type="email" name="email" required autocomplete="email" placeholder="you@example.com"></label><label>Your rating<select name="rating" required><option value="5">★★★★★ Excellent</option><option value="4">★★★★☆ Good</option><option value="3">★★★☆☆ Average</option><option value="2">★★☆☆☆ Fair</option><option value="1">★☆☆☆☆ Poor</option></select></label><label>Share your experience<textarea name="comment" rows="3" maxlength="600" placeholder="What should other visitors know?"></textarea></label><button type="submit" class="sp-btn sp-primary">Submit review</button><p role="status" id="spStatus"></p></form></div></div>
  <div class="sp-mobile-actions">${contact}<a class="sp-btn" href="#reviews">★ Reviews</a></div>
  <footer><b>${esc(user.siteName)}</b><span>Built with <a href="${PUBLIC_BASE}">GoldOffer Studio</a></span></footer>
  <style>
  .sp-update{background:#253224;border:1px solid #719a56;color:#e7ffdd;border-radius:12px;padding:12px 18px;margin-bottom:16px;font-size:14px}
  .sp-wrap{max-width:1120px;width:min(100% - 36px,1120px);margin:auto;padding:38px 0 110px;min-width:0}.sp-back{display:inline-block;color:#aeb5c2;margin-bottom:20px;text-decoration:none;font-size:14px}.sp-hero{padding:clamp(22px,4vw,42px);border:1px solid #29303b;border-radius:26px;background:linear-gradient(128deg,#1b212c,#10151d);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:24px}.sp-identity{display:flex;align-items:center;gap:20px;min-width:0}.sp-avatar{flex:none;width:88px;height:88px;border-radius:22px;background:linear-gradient(135deg,rgba(255,255,255,.14),rgba(255,255,255,.04));color:#f4f5f7;display:grid;place-items:center;font-size:26px;font-weight:800;letter-spacing:.04em;overflow:hidden;border:1px solid rgba(255,255,255,.12)}.sp-avatar img{width:100%;height:100%;object-fit:cover}.sp-intro{min-width:0}.sp-intro h1{font-size:clamp(28px,4.5vw,48px);margin:5px 0 8px;color:#f5f6f9;overflow-wrap:anywhere}.sp-intro p{color:#b5bdc9}.sp-eyebrow{color:#e6ba50;letter-spacing:.16em;font-size:11px;font-weight:800}.sp-proof{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px;color:#c9cfd9;font-size:12px}.sp-proof span{background:#242b36;padding:7px 10px;border:1px solid #353e4c;border-radius:30px}.sp-buttons,.sp-about-actions{display:flex;flex-wrap:wrap;gap:10px}.sp-btn{border:1px solid #394150;background:#242b37;color:#f5f6fa;padding:12px 17px;border-radius:12px;display:inline-flex;align-items:center;justify-content:center;gap:8px;text-decoration:none;font:700 14px Inter,sans-serif;cursor:pointer;min-height:46px}.sp-btn svg{width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.8}.sp-btn:hover{border-color:#d7aa33}.sp-btn.sp-primary{background:linear-gradient(110deg,#ffda00,#ff9900);color:#15120b;border-color:transparent}.sp-tabs{position:sticky;top:72px;z-index:12;display:flex;gap:24px;border-bottom:1px solid #2d3440;background:#0a0e15;padding-top:19px;margin-bottom:28px}.sp-tabs a{padding:12px 2px;color:#bac3d1;text-decoration:none;font-weight:650;font-size:14px}.sp-tabs a:hover,.sp-tabs a:focus{color:#ffcf35}.sp-section{scroll-margin-top:135px;padding:25px 0 46px;border-bottom:1px solid #272e39}.sp-section-head{display:flex;justify-content:space-between;align-items:end;gap:16px;flex-wrap:wrap;margin-bottom:24px}.sp-section-head h2{font-size:clamp(23px,3vw,34px);margin:6px 0;color:#f5f6fa}.sp-subtle{color:#aab2c0;font-size:14px}.sp-about{background:#151b25;border:1px solid #2f3745;border-radius:20px;padding:24px;display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap}.sp-about h3{font-size:21px;color:#fff;margin-bottom:8px}.sp-about p{color:#bdc4cf;max-width:700px}.sp-review-box{display:grid;grid-template-columns:minmax(180px,270px) minmax(0,1fr);gap:18px}.sp-review-summary,.sp-review-list{border-radius:20px;background:#171e29;border:1px solid #333d4b;padding:24px;min-width:0}.sp-review-summary{display:flex;flex-direction:column;gap:8px;align-self:start}.sp-review-summary strong{font-size:52px;color:#fff}.sp-review-summary>span{color:#ffca28;font-size:23px}.sp-review-summary small{color:#b9c2cf}.sp-review-list{min-height:130px;color:#c7cfda}.sp-review-item{padding:14px 0;border-bottom:1px solid #343c48}.sp-review-item:last-child{border:0}.sp-review-item>div{display:flex;justify-content:space-between;gap:10px}.sp-review-item strong{color:#fff}.sp-review-item span{color:#ffd13a}.sp-review-item p{margin:10px 0;overflow-wrap:anywhere;white-space:pre-wrap}.sp-review-item small{color:#9ca9bb}.sp-bar{height:7px;background:#323b47;border-radius:6px;overflow:hidden;margin:8px 0}.sp-bar i{display:block;height:100%;background:#ffb800}.sp-overlay:not([hidden]){position:fixed;z-index:300;inset:0;background:#05070bd9;display:flex;align-items:center;justify-content:center;padding:16px;overflow-y:auto}.sp-dialog{width:min(100%,470px);max-height:calc(100dvh - 40px);overflow:auto;border:1px solid #38414e;background:#171e28;border-radius:22px;padding:24px;color:#f7f7f7}.sp-modal-head{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:12px}.sp-modal-head h2{font-size:23px}.sp-modal-head button{border:1px solid #444c59;border-radius:10px;background:#252d38;color:white;padding:9px 13px;cursor:pointer}.sp-dialog label{display:block;margin:14px 0;color:#eef1f5;font-size:13px;font-weight:600}.sp-dialog input,.sp-dialog select,.sp-dialog textarea{display:block;width:100%;background:#222a36;color:#fff;border:1px solid #485261;border-radius:11px;padding:13px;margin-top:6px;box-sizing:border-box;font:inherit}.sp-dialog .sp-btn{width:100%}.sp-mobile-actions{display:none}
  @media(prefers-reduced-motion:no-preference){.sp-section{animation:spRise both;animation-timeline:view();animation-range:entry 0% entry 22%}@keyframes spRise{from{opacity:.68;transform:translateY(18px)}to{opacity:1;transform:none}}}
  @media(max-width:680px){.sp-wrap{width:calc(100% - 28px);padding:22px 0 95px}.sp-hero{padding:20px;border-radius:19px}.sp-avatar{width:66px;height:66px;border-radius:18px;font-size:30px}.sp-identity{gap:12px;align-items:start}.sp-intro h1{font-size:27px}.sp-buttons{width:100%}.sp-buttons .sp-btn{flex:1;font-size:13px}.sp-review-box{grid-template-columns:1fr}.sp-review-summary strong{font-size:38px}.sp-tabs{top:66px;gap:20px}.sp-about{padding:18px}.sp-mobile-actions{display:flex;position:fixed;z-index:90;left:0;right:0;bottom:0;padding:10px 12px calc(10px + env(safe-area-inset-bottom));gap:8px;background:#0d111a;border-top:1px solid #38414c;box-shadow:0 -8px 24px #0007}.sp-mobile-actions .sp-btn{flex:1;padding:10px 8px;font-size:12px;white-space:nowrap}.sp-section{padding-bottom:35px}}
  </style>
  <script>(function(){const slug=${JSON.stringify(user.slug)},api='/api/storefront/'+encodeURIComponent(slug)+'/reviews';const modal=document.getElementById('spModal'),form=document.getElementById('spForm'),stat=document.getElementById('spStatus');const escText=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const close=()=>{modal.hidden=true;document.body.style.overflow=''};document.getElementById('spLeave').onclick=()=>{modal.hidden=false;document.body.style.overflow='hidden'};document.getElementById('spClose').onclick=close;modal.addEventListener('click',e=>{if(e.target===modal)close()});document.addEventListener('keydown',e=>{if(e.key==='Escape')close()});const follow=document.getElementById('spFollow'),key='goldoffer-follow-'+slug;function updateFollow(){let ok=localStorage.getItem(key)==='1';follow.textContent=ok?'♥ Saved seller':'♡ Save seller';follow.setAttribute('aria-pressed',String(ok))}follow.onclick=async()=>{const willFollow=localStorage.getItem(key)!=='1';localStorage.setItem(key,willFollow?'1':'0');if(willFollow){try{const r=await fetch('/api/storefront/'+encodeURIComponent(slug)+'/updates');const d=await r.json();const newest=d.offers&&d.offers[0];if(newest)localStorage.setItem(key+'-latest',newest.id);}catch(e){}}updateFollow()};updateFollow();
  if(localStorage.getItem(key)==='1'){fetch('/api/storefront/'+encodeURIComponent(slug)+'/updates').then(r=>r.json()).then(d=>{const newest=d.offers&&d.offers[0];if(!newest)return;const prev=localStorage.getItem(key+'-latest');if(prev&&prev!==newest.id){const notice=document.createElement('div');notice.className='sp-update';notice.textContent='New offer from this seller: '+newest.title;document.querySelector('.sp-wrap').prepend(notice);}localStorage.setItem(key+'-latest',newest.id)}).catch(()=>{})} document.getElementById('spShare').onclick=async()=>{try{if(navigator.share)await navigator.share({title:document.title,url:location.href});else{await navigator.clipboard.writeText(location.href);alert('Profile link copied')}}catch(e){}};
  async function load(){try{const r=await fetch(api);if(!r.ok)throw Error('Failed');const d=await r.json();const avg=d.count?d.average.toFixed(1):'—';document.getElementById('spAvg').textContent=avg;document.getElementById('spRating').textContent=d.count?'★ '+avg+' ('+d.count+')':'★ No ratings yet';document.getElementById('spReviewCount').textContent=d.count?'('+d.count+')':'';document.getElementById('spStars').textContent=d.count?'★'.repeat(Math.round(d.average))+'☆'.repeat(5-Math.round(d.average)):'☆☆☆☆☆';document.getElementById('spCount').textContent=d.count?d.count+' visitor reviews':'No reviews yet';let bins=[0,0,0,0,0];for(const r of d.reviews)bins[r.rating-1]++;document.getElementById('spBars').innerHTML=d.count?[5,4,3,2,1].map(i=>'<div style="font-size:12px;color:#bfc8d5">'+i+' stars <div class="sp-bar"><i style="width:'+(bins[i-1]/d.count*100)+'%"></i></div></div>').join(''):'';document.getElementById('spReviewList').innerHTML=d.reviews.length?d.reviews.map(x=>'<article class="sp-review-item"><div><strong>'+escText(x.name)+'</strong><span>'+ '★'.repeat(x.rating)+'☆'.repeat(5-x.rating)+'</span></div><p>'+escText(x.comment)+'</p><small>'+new Date(x.createdAt).toLocaleDateString('en-GB')+'</small></article>').join(''):'No visitor reviews yet. Be the first to share your experience.';}catch(e){document.getElementById('spReviewList').textContent='Unable to load reviews right now.'}}form.onsubmit=async e=>{e.preventDefault();stat.textContent='Submitting…';let d=Object.fromEntries(new FormData(form));d.rating=Number(d.rating);try{let r=await fetch(api,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)}),out=await r.json();if(!r.ok)throw Error(out.message||'Could not submit');form.reset();close();load()}catch(e){stat.textContent=e.message}};load()})()</script>`;
  return pageShell(user,{title:`${sellerName(user)} — Seller profile`,desc:`View offers and visitor feedback for ${sellerName(user)}`,body,cls:'sellerprofile',page:'profile'});
}

// AI-specific page composition, independent from the eight template home layouts.
// Dynamic content is escaped; never execute AI-supplied HTML, JS or CSS.
function renderAiHome(user, offers, sent) {
  const a = user.aiPage || {};
  const allowed = ['hero','about','offers','contact'];
  const order = Array.isArray(a.order) ? [...new Set(a.order.filter(x => allowed.includes(x)))].slice(0,4) : allowed;
  for (const k of allowed) if (!order.includes(k)) order.push(k);
  const d = user.design && user.design.v || {};
  const hex = (v, fallback) => /^#[0-9a-f]{6}$/i.test(String(v||'')) ? v : fallback;
  const accent = hex(d.accent,'#7957ff'), bg = hex(d.bg,'#0c101c'), panel = hex(d.panel,'#191e32'), ink = hex(d.text,'#f4f4fc');
  const radius = Math.max(0,Math.min(35,parseInt(d.radius,10)||16));
  const slug = encodeURIComponent(user.slug||'');
  const text = (v, fallback, n=240) => esc(String(v||fallback).slice(0,n));
  const oCards = offers.map(o => `<article class="ai-card"><a href="/site/${slug}/offer/${o._id}">${o.imageUrl?`<img loading="lazy" src="${esc(o.imageUrl)}" alt="${esc(o.title)}">`:'<div class="ai-pattern"></div>'}<h3>${esc(o.title||'Offer')}</h3></a><p>${esc((o.description||'').slice(0,180))}</p>${Number(o.price)>0?`<strong>${Number(o.price).toFixed(2)}</strong>`:''}</article>`).join('');
  const sections = {
    hero:`<section class="ai-hero"><span class="ai-kicker">${text(a.eyebrow,user.category||'Independent business',100)}</span><h1>${text(a.headline,user.siteName,150)}</h1><p>${text(a.subheading,user.sellerBio||'',360)}</p><a class="ai-btn" href="#ai-offers">${text(a.cta,'Explore offers',60)}</a></section>`,
    about:`<section class="ai-about"><span class="ai-kicker">${text(a.aboutEyebrow,'Our story',70)}</span><h2>${text(a.aboutTitle,'Why choose us',140)}</h2><p>${text(user.sellerBio,a.aboutText||'Discover our work.',650)}</p></section>`,
    offers:`<section id="ai-offers" class="ai-offers"><span class="ai-kicker">${text(a.offersEyebrow,'Collection',70)}</span><h2>${text(a.offersTitle,'Explore our offers',140)}</h2><div class="ai-grid">${oCards||'<p>New offers coming soon.</p>'}</div></section>`,
    contact:`<section class="ai-contact"><h2>${text(a.contactTitle,'Get in touch',140)}</h2><p>${text(a.contactText,'Questions? Contact us to learn more.',300)}</p><div class="ai-actions">${user.phone?`<a class="ai-btn" href="tel:${esc(String(user.phone).replace(/[^0-9+]/g,''))}">${text(a.contactAction,'Call us',60)}</a>`:''}<a class="ai-btn ai-secondary" href="/site/${slug}/messages">${text(a.messageAction,'Send a message',60)}</a><a class="ai-btn ai-secondary" href="/site/${slug}/profile">${text(a.profileAction,'Seller profile',60)}</a></div></section>`
  };
  const align = ['left','center'].includes(a.align)?a.align:'left';
  const grid = [2,3,4].includes(Number(a.columns))?Number(a.columns):3;
  const style=`<style>.ai-root{--a:${accent};--bg:${bg};--panel:${panel};--ink:${ink};--r:${radius}px;background:var(--bg);color:var(--ink);min-height:100vh;font-family:Inter,system-ui,sans-serif}.ai-top{display:flex;align-items:center;justify-content:space-between;padding:24px max(5vw,20px);gap:16px;border-bottom:1px solid #ffffff26}.ai-top a{color:inherit;text-decoration:none}.ai-brand{font-size:1.2rem;font-weight:800}.ai-root section{padding:clamp(55px,7vw,115px) max(5vw,24px);max-width:1440px;margin:auto}.ai-root h1{font-size:clamp(3rem,7vw,7.5rem);line-height:1.02;letter-spacing:-.055em;max-width:13ch;margin:18px 0 22px}.ai-root h2{font-size:clamp(2rem,4vw,4rem);line-height:1.1;margin:12px 0 24px}.ai-root p{opacity:.82;line-height:1.75;max-width:65ch}.ai-kicker{text-transform:uppercase;letter-spacing:.2em;color:var(--a);font-size:.75rem;font-weight:900}.ai-hero{min-height:65vh;display:flex;flex-direction:column;justify-content:center;text-align:${align};align-items:${align==='center'?'center':'start'};background:radial-gradient(ellipse at 85% 30%,color-mix(in srgb,var(--a) 28%,transparent),transparent 65%)}.ai-btn{display:inline-flex;padding:12px 22px;background:var(--a);color:#fff!important;border-radius:var(--r);text-decoration:none;font-weight:800;margin-top:25px}.ai-secondary{background:var(--panel);border:1px solid #ffffff36}.ai-grid{display:grid;grid-template-columns:repeat(${grid},minmax(0,1fr));gap:18px}.ai-card{overflow:hidden;background:var(--panel);border:1px solid #ffffff24;border-radius:var(--r);padding:0 0 24px}.ai-card img,.ai-pattern{width:100%;height:220px;object-fit:cover;background:linear-gradient(135deg,var(--a),var(--panel))}.ai-card a{color:inherit;text-decoration:none}.ai-card h3,.ai-card p,.ai-card strong{display:block;padding:0 22px}.ai-card h3{font-size:1.3rem;margin:18px 0 6px}.ai-about{border-top:1px solid #ffffff24;border-bottom:1px solid #ffffff24}.ai-contact{background:var(--panel);border-radius:var(--r);margin-bottom:70px!important}.ai-actions{display:flex;flex-wrap:wrap;gap:12px}@media(max-width:850px){.ai-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:540px){.ai-grid{grid-template-columns:1fr}.ai-card img,.ai-pattern{height:180px}.ai-root section{padding:55px 20px}.ai-hero{min-height:60vh}}</style>`;
  const body=`${style}<div class="ai-root"><header class="ai-top"><a class="ai-brand" href="/site/${slug}">${esc(user.siteName)}</a><a href="/site/${slug}/profile">${text(a.profileAction,'Profile',50)}</a></header>${order.map(x=>sections[x]).join('')}<footer style="padding:26px;text-align:center;opacity:.6">${esc(user.siteName)} · GoldOffer Studio</footer></div>`;
  return pageShell(user,{title:user.siteName||'Website',desc:user.sellerBio||'',body,cls:'ai-generated',page:'home'});
}

function renderSite(user, offers, sent) {
  if (user.aiGenerated && user.aiPage) return renderAiHome(user, offers, sent);
  const meta = [user.categoryLabel || user.category, user.city].filter(Boolean).map(esc);
  const sub = meta.length === 2 ? `${meta[0]} in ${meta[1]}` : meta.join('');
  const hours = String(user.hours || '').split('\n')[0].trim();
  const q = mapQuery(user);
  const phoneRaw = String(user.phone || '').replace(/[^\d+]/g, '');
  const seller = sellerName(user);
  const story = user.sellerBio || [user.categoryLabel || user.category, user.city].filter(Boolean).join(' in ') || 'Independent business built with GoldOffer.';
  const layout = layoutPack(user.layout);
  const fallbackGallery = layout.fallback;

  const visualOffers = offers.filter(o => galleryOf(o).length);
  const leadOffer = visualOffers[0] || offers[0] || null;
  const secondOffer = visualOffers[1] || visualOffers[0] || offers[1] || leadOffer;
  const thirdOffer = visualOffers[2] || visualOffers[1] || offers[2] || leadOffer;
  const fourthOffer = visualOffers[3] || visualOffers[2] || offers[3] || leadOffer;
  const leadMedia = leadOffer ? galleryOf(leadOffer)[0] : '';
  const sideMediaA = secondOffer ? galleryOf(secondOffer)[0] : '';
  const sideMediaB = thirdOffer ? galleryOf(thirdOffer)[0] : '';
  const sideMediaC = fourthOffer ? galleryOf(fourthOffer)[0] : '';
  const isVideo = (u) => /\.(mp4|webm|ogg)(?:$|[?#])/i.test(String(u || ''));
  const renderMedia = (u, alt, extra = '', fallbackUrl = '') => {
    const src = u || fallbackUrl;
    if (!src) return `<div class="cine-fallback ${extra}"><span>${esc(String((alt || user.siteName || '?')).charAt(0).toUpperCase())}</span></div>`;
    return isVideo(src)
      ? `<video class="${extra}" src="${esc(src)}" autoplay muted loop playsinline preload="metadata"></video>`
      : `<img class="${extra}" src="${esc(src)}" alt="${esc(alt || '')}" loading="lazy">`;
  };
  const heroMediaA = leadMedia || fallbackGallery[0];
  const heroMediaB = sideMediaA || fallbackGallery[1];
  const heroMediaC = sideMediaB || fallbackGallery[2];
  const heroMediaD = sideMediaC || fallbackGallery[3];
  const offerPills = offers.slice(0, 3).map(o => `<a href="/site/${esc(user.slug)}/offer/${o._id}">${esc(o.title)}</a>`).join('');
  const heroTiles = offers.slice(0, 3).map((o, i) => {
    const g = galleryOf(o);
    const cls = ['t2', 't1', 't3'][i] || 't2';
    return `<a class="tile ${cls}" href="/site/${esc(user.slug)}/offer/${o._id}" aria-label="${esc(o.title)}">${renderMedia(g[0], o.title, '', fallbackGallery[(i + 1) % fallbackGallery.length])}<span class="tg"><span>${esc(o.title)}</span><b>${eur(o.price)}</b></span></a>`;
  }).join('');
  const cards = offers.length === 0 ? '<p class="none">No offers yet. Please check back soon.</p>' : offers.map((o, i) => offerCard(user, o, i)).join('');
  const body = `<div class="prog" id="prog"></div>${siteBar(user, 'home')}
<section class="cine-hero">
  <div class="cine-noise"></div>
  <div class="cine-wrap">
    <div class="cine-copy rv in-view" style="--d:80ms">
      <span class="cine-eyebrow">${esc(((layout.eyebrow || user.categoryLabel || user.category || 'GoldOffer site')).toUpperCase())}</span>
      <h1>${esc(user.siteName)}</h1>
      <p class="cine-sub">${esc(story)}</p>
      <div class="cine-meta">${sub ? `<span>${sub}</span>` : ''}${hours ? `<span>${esc(hours)}</span>` : ''}<span>${offers.length} offers live</span></div>
      <div class="actions">
        <a class="abtn pri" href="/site/${esc(user.slug)}/messages">${MSG_SVG}Message us</a>
        ${phoneRaw ? `<a class="abtn" href="tel:${esc(phoneRaw)}">${PHONE_SVG}Call</a>` : ''}
        ${q ? `<a class="abtn" href="https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(q)}" target="_blank" rel="noopener">${PIN_SVG}Directions</a>` : ''}
      </div>
      ${offerPills ? `<div class="offer-pills">${offerPills}</div>` : ''}
    </div>
    <div class="cine-visual rv in-view" style="--d:180ms" data-cine-stack>
      <div class="stack-outline s1"></div>
      <div class="stack-outline s2"></div>
      <div class="stack-outline s3"></div>
      <div class="main-screen">${renderMedia(heroMediaA, leadOffer ? leadOffer.title : user.siteName)}</div>
      <div class="float-card fc-a">${renderMedia(heroMediaB, secondOffer ? secondOffer.title : user.siteName)}</div>
      <div class="float-card fc-b">${renderMedia(heroMediaC, thirdOffer ? thirdOffer.title : user.siteName)}</div>
      <div class="float-card fc-c">${renderMedia(heroMediaD, fourthOffer ? fourthOffer.title : user.siteName)}</div>
      <div class="screen-caption"><strong>${esc(leadOffer ? leadOffer.title : user.siteName)}</strong><span>${leadOffer ? eur(leadOffer.price) : esc(sub || 'Explore the website')}</span></div>
    </div>
  </div>
  <div class="hero-fade"></div>
</section>

<section class="story-shell" data-story-shell>
  <div class="story-stick">
    <div class="story-canvas" data-story-canvas>
      <div class="story-media">${renderMedia(heroMediaB, secondOffer ? secondOffer.title : user.siteName, 'story-main')}</div>
      <div class="story-panel">
        <span class="cine-eyebrow">THE STORY BEHIND THE BUSINESS</span>
        <h2>${esc(layout.storyHeading || (user.siteName + ' — made to stand out.'))}</h2>
        <p>${esc(story)}</p>
        <div class="story-stats"><div><b>${offers.length}</b><span>Offers</span></div><div><b>${esc(user.city || 'Global')}</b><span>Location</span></div><div><b>${phoneRaw ? 'Telephone' : 'Message'}</b><span>Contact</span></div></div>
      </div>
    </div>
  </div>
</section>

<section class="reveal-band wrap">
  <div class="sec-head"><h2>${esc(layout.discoverTitle || ('Discover ' + user.siteName))}</h2><span>${esc(layout.discoverText || 'A closer look at what we offer.')}</span></div>
  <div class="copylines">
    <p class="copyline">${esc(story)}</p>
    <p class="copyline">${esc(user.categoryLabel || user.category || 'Explore the collection')} ${user.city ? 'in ' + esc(user.city) : 'for you'}.</p>
    <p class="copyline">Explore our work, and get in touch when you find something you like.</p>
  </div>
</section>

<section class="cine-feature wrap">
  <div class="feature-grid">
    <div class="feature-card dark rv"><span class="cine-eyebrow">DISCOVER</span><h3>${esc(layout.discoverTitle || 'Discover our latest offers')}</h3><p>${esc(layout.tilesText || 'Find something that suits you. Explore the collection, ask questions and connect directly.')}</p></div>
    <div class="feature-card media rv">${heroTiles ? `<div class="pics three">${heroTiles}</div>` : `<div class="feature-fallback">Publish offers to see your visual layout here.</div>`}</div>
    <div class="feature-card light rv"><span class="cine-eyebrow">SELLER PROFILE</span><h3>Meet ${esc(seller)}</h3><p>${esc(layout.profileText || 'Learn about the person behind this site, read feedback and get in touch directly.')}</p><a class="feature-link" href="/site/${esc(user.slug)}/profile">View seller profile →</a></div>
  </div>
</section>

<main class="wrap top" id="offers">
  <div class="sec-head"><h2>Offers</h2><span>${offers.length} available · <a href="/site/${esc(user.slug)}/profile#reviews" style="color:inherit;text-decoration:underline">Seller reviews</a></span></div>
  <div class="go-shop-search"><input id="goOfferSearch" type="search" autocomplete="off" aria-label="Search offers" placeholder="Search offers by name or description..."><span id="goFound">${offers.length} offers</span></div>
  ${sent ? `<div class="ok">Thank you. Your request was sent and the business will contact you.${sentTrack(user)}</div>` : ''}
  <div class="grid" id="goOfferGrid">${cards}</div><p id="goNoResults" style="display:none;padding:28px 0;color:#707781">No matching offers.</p>
</main>

<section class="wrap" style="padding-top:42px"><a href="/site/${esc(user.slug)}/profile" style="display:flex;gap:15px;align-items:center;border:1px solid #364151;border-radius:18px;background:#161c25;padding:18px 20px;text-decoration:none"><span class="seller-pill" style="display:grid;place-items:center;width:52px;height:52px;color:inherit;font-size:18px;font-weight:800">${esc(initials(sellerName(user)))}</span><span style="flex:1;min-width:0"><b style="display:block;color:#fff">Meet ${esc(sellerName(user))}</b><small style="color:#b1bdcc">Seller profile · Offers · Reviews</small></span><strong style="color:#ffcb31">View profile →</strong></a></section>
${user.bookingEnabled ? `<section class="wrap" style="padding-top:35px" id="book"><div class="sec-head"><h2>Request an appointment</h2><span>Available when the business enables appointments.</span></div><form class="glass" method="POST" action="/site/${esc(user.slug)}/appointment" style="display:grid;gap:12px;max-width:620px"><input name="customer" placeholder="Your name" required maxlength="80"><input name="contact" placeholder="Your contact details" required maxlength="140"><label style="font-size:13px">Service (optional)</label><select name="offerId" id="bkOffer"><option value="">Any</option>${(user._offerOpts||[]).map(o=>`<option value="${esc(o.id)}">${esc(o.title)}</option>`).join('')}</select><label style="font-size:13px">Pick a day</label><input type="date" id="bkDate" required><div id="bkSlots" style="display:flex;flex-wrap:wrap;gap:8px;min-height:38px;color:var(--soft);font-size:13px">Choose a day to see free times.</div><input type="hidden" name="startsAt" id="bkStart" required><textarea name="note" rows="2" placeholder="What do you need? (optional)" maxlength="500"></textarea><label style="font-size:12px;display:flex;gap:9px;align-items:start"><input type="checkbox" name="consent" value="1" required style="width:auto;margin:3px 0"><span>I agree to be contacted about this booking. <a href="${PUBLIC_BASE}/privacy">Privacy Policy</a></span></label><button class="btn" type="submit">Send booking request</button></form>${sent ? '' : ''}</section>
` : ''}${user.faqItems && user.faqItems.length ? `<section class="wrap go-faq" id="faq"><div class="sec-head"><h2>Frequently asked questions</h2></div><div style="display:grid;gap:12px">${user.faqItems.map(x=>`<details class="glass" style="padding:18px 22px"><summary style="cursor:pointer;font-weight:700">${esc(x.question)}</summary><p style="padding-top:10px;color:var(--soft)">${esc(x.answer)}</p></details>`).join('')}</div></section>` : ''}
<section class="wrap findus" id="about" style="padding-top:60px"><div class="sec-head"><h2>Find us</h2></div>${aboutBlock(user)}</section>
<footer><b>${esc(user.siteName)}</b><span>Built with <a href="${PUBLIC_BASE}" target="_blank" rel="noopener">GoldOffer Studio</a></span></footer>
<style>
.cine-hero{position:relative;overflow:hidden;padding:108px 0 60px;background:radial-gradient(1200px circle at 78% 22%,rgba(255,200,32,.13),transparent 32%),radial-gradient(900px circle at 18% 10%,rgba(255,255,255,.06),transparent 28%),linear-gradient(180deg,#05070b 0%,#070b12 100%)}
.cine-noise,.hero-fade{position:absolute;inset:0;pointer-events:none}.cine-noise{opacity:.25;background-image:radial-gradient(rgba(255,255,255,.06) 1px,transparent 1px);background-size:12px 12px;mask-image:linear-gradient(180deg,rgba(0,0,0,.7),transparent)}.hero-fade{background:linear-gradient(180deg,transparent 68%,#070b12 100%)}
.cine-wrap{width:min(100% - 40px,1220px);margin:0 auto;display:grid;grid-template-columns:minmax(0,1fr) minmax(360px,560px);align-items:center;gap:44px;position:relative;z-index:2}.cine-copy{padding-right:10px}
.cine-copy h1{font-size:clamp(3rem,8vw,6.6rem);line-height:.92;letter-spacing:-.05em;margin:8px 0 18px;max-width:11ch}.cine-eyebrow{display:inline-flex;align-items:center;gap:10px;font-size:12px;font-weight:800;letter-spacing:.18em;color:#ffcb36}.cine-eyebrow::before{content:'';width:18px;height:1px;background:currentColor;opacity:.7}.cine-sub{max-width:660px;font-size:clamp(1rem,1.8vw,1.16rem);line-height:1.72;color:#c7ced8}.cine-meta{display:flex;flex-wrap:wrap;gap:10px;margin:24px 0 22px}.cine-meta span,.offer-pills a{display:inline-flex;align-items:center;gap:8px;padding:10px 14px;border-radius:999px;border:1px solid rgba(255,255,255,.12);background:rgba(255,255,255,.04);color:#f2f4f8;font-size:13px;text-decoration:none;backdrop-filter:blur(10px)}.offer-pills{display:flex;flex-wrap:wrap;gap:10px;margin-top:16px}.offer-pills a:hover{border-color:#ffcf35;color:#ffcf35}
.cine-visual{position:relative;min-height:500px;perspective:1600px}.stack-outline,.main-screen,.float-card{position:absolute;border-radius:34px}.stack-outline{inset:42px 28px 42px 34px;border:1px solid rgba(255,255,255,.28);opacity:.42;transform-origin:center;pointer-events:none}.stack-outline.s1{transform:rotate(-6deg) translate(-18px,10px)}.stack-outline.s2{transform:rotate(4deg) translate(18px,-14px)}.stack-outline.s3{transform:rotate(-1.5deg) translate(0,0)}.main-screen{inset:74px 52px 64px 62px;overflow:hidden;border:1px solid rgba(255,255,255,.12);background:#0d1219;box-shadow:0 28px 70px rgba(0,0,0,.5)}.main-screen img,.main-screen video,.float-card img,.float-card video,.story-main{width:100%;height:100%;object-fit:cover;display:block}.cine-fallback{display:grid;place-items:center;width:100%;height:100%;background:linear-gradient(135deg,#1a2230,#0c1118);color:#fff;font-size:68px;font-weight:900}.float-card{width:120px;height:120px;overflow:hidden;border:1px solid rgba(255,255,255,.16);box-shadow:0 18px 44px rgba(0,0,0,.4);background:#10151d}.fc-a{top:18px;left:26px}.fc-b{right:12px;top:120px}.fc-c{right:84px;bottom:22px;width:108px;height:108px}.screen-caption{position:absolute;left:84px;right:84px;bottom:20px;display:flex;justify-content:space-between;gap:18px;padding:14px 18px;border-radius:18px;background:linear-gradient(180deg,rgba(8,11,16,.24),rgba(8,11,16,.84));backdrop-filter:blur(16px);color:#fff}.screen-caption strong{font-size:14px}.screen-caption span{font-size:13px;color:#ffcb36}
.story-shell{position:relative;height:170vh}.story-stick{position:sticky;top:10vh;height:80vh;display:flex;align-items:center}.story-canvas{width:min(100% - 40px,1220px);margin:0 auto;display:grid;grid-template-columns:minmax(0,1.12fr) minmax(300px,.88fr);gap:0;border:1px solid rgba(255,255,255,.12);border-radius:34px;overflow:hidden;background:linear-gradient(135deg,#0e131b,#131924 55%,#0c1017);box-shadow:0 28px 90px rgba(0,0,0,.48);transform-origin:center top}.story-media{min-height:520px;background:#0e1219}.story-panel{padding:clamp(28px,4vw,42px);display:flex;flex-direction:column;justify-content:center}.story-panel h2{font-size:clamp(1.85rem,3vw,3.35rem);line-height:1.02;letter-spacing:-.04em;margin:12px 0 16px}.story-panel p{font-size:1rem;line-height:1.76;color:#c3c9d3;max-width:44ch}.story-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:20px}.story-stats div{padding:14px 14px 12px;border-radius:18px;background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.08)}.story-stats b{display:block;font-size:1.15rem;color:#fff}.story-stats span{font-size:.78rem;color:#98a1af}
.reveal-band{padding-top:22px;padding-bottom:10px}.copylines{display:grid;gap:16px;margin-top:20px;max-width:980px}.copyline{font-size:clamp(1.35rem,2.9vw,2.55rem);line-height:1.18;letter-spacing:-.04em;color:rgba(255,255,255,.22);transition:color .45s ease,text-shadow .45s ease,transform .45s ease;max-width:26ch}.copyline.on{color:#f3f6fb;text-shadow:0 0 18px rgba(255,204,54,.2);transform:translateX(8px)}
.cine-feature{padding-top:20px;padding-bottom:20px}.feature-grid{display:grid;grid-template-columns:1.05fr 1.2fr 1.05fr;gap:18px}.feature-card{border-radius:30px;padding:28px;min-height:300px;border:1px solid rgba(255,255,255,.1)}.feature-card.dark{background:linear-gradient(150deg,#131a23,#0c1118)}.feature-card.light{background:linear-gradient(155deg,#f1efe8,#ddd7cb);color:#111}.feature-card.media{padding:18px;background:linear-gradient(180deg,#f3f2ef,#dadad7)}.feature-card h3{font-size:clamp(1.5rem,2.4vw,2.35rem);line-height:1.08;margin:12px 0 14px}.feature-card p{line-height:1.72;color:inherit;opacity:.82}.feature-link{display:inline-block;margin-top:18px;font-weight:700;color:inherit;text-decoration:none}.feature-fallback{min-height:100%;display:grid;place-items:center;text-align:center;color:#2c3440}.feature-card.media .pics{height:100%}.feature-card.media .tile{min-height:100%}
.go-shop-search{display:flex;align-items:center;gap:16px;justify-content:space-between;flex-wrap:wrap;margin:18px 0 24px}.go-shop-search input{width:min(100%,430px);border-radius:14px;padding:13px 17px;background:#fff;color:#15191f;border:1px solid #dce0e4;font:inherit;box-shadow:0 3px 18px rgba(0,0,0,.035)}.go-shop-search input:focus{outline:2px solid #f7c42f}.go-shop-search span{font-size:13px;color:#707781}
/* Three true templates, independent from theme color and font settings. */

.layout-atelier .cine-hero{background:#eee9e0;color:#23221f}.layout-atelier .cine-wrap{grid-template-columns:.75fr 1.25fr;gap:78px}
.layout-atelier .cine-copy h1{font-family:Georgia,serif;font-weight:400;font-size:clamp(3.2rem,6vw,6rem);color:#25231f;line-height:1.02}
.layout-atelier .cine-sub{color:#54514c}.layout-atelier .cine-eyebrow{color:#8d7159}.layout-atelier .cine-meta span,.layout-atelier .offer-pills a{background:#fffaf2;border-color:#d8d0c5;color:#35312c}
.layout-atelier .hero-fade{background:linear-gradient(180deg,transparent 65%,#eee9e0)}.layout-atelier .stack-outline{display:none}.layout-atelier .main-screen{inset:0;border-radius:3px}.layout-atelier .float-card{border-radius:2px}
.layout-atelier .story-shell{height:auto;padding:20px 0 60px}.layout-atelier .story-stick{position:relative;top:auto;height:auto}.layout-atelier .story-canvas{transform:none!important;background:#fffdf9;grid-template-columns:.85fr 1.15fr;border-radius:3px;box-shadow:none}
.layout-atelier .story-panel h2,.layout-atelier .story-panel p,.layout-atelier .story-stats b{color:#292521}.layout-atelier .story-stats div{background:#f3eee7}
.layout-atelier .reveal-band,.layout-atelier .feature-card.dark{color:#292521}.layout-atelier .copyline.on{color:#292521}.layout-atelier .feature-grid{grid-template-columns:1.5fr 1fr}.layout-atelier .feature-card.media{grid-row:span 2}.layout-atelier .feature-card.light{background:#d8cdbc}
.layout-arcade .cine-hero{background:repeating-linear-gradient(90deg,rgba(219,255,54,.05) 0 1px,transparent 1px 90px),linear-gradient(140deg,#080910,#111426)}
.layout-arcade .cine-wrap{grid-template-columns:1fr 1fr}.layout-arcade .cine-copy h1{font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:-.09em;font-size:clamp(3rem,6.5vw,6rem)}
.layout-arcade .main-screen{inset:25px 0 40px 35px;border-radius:6px}.layout-arcade .float-card{border-radius:5px}.layout-arcade .stack-outline{border-color:#dbff36;border-radius:3px}
.layout-arcade .story-canvas{grid-template-columns:1fr 1fr;border-radius:6px;background:#141425}.layout-arcade .feature-grid{grid-template-columns:.8fr 1.5fr}.layout-arcade .feature-card.light{grid-column:1/-1;min-height:180px;background:#dbff36;color:#141414}
.layout-arcade .feature-card{border-radius:6px}.layout-arcade .copyline.on{text-shadow:0 0 16px rgba(219,255,54,.4);color:#efffbe}
.layout-aurora .cine-hero{background:radial-gradient(ellipse at 80% 15%,rgba(120,225,208,.22),transparent 42%),radial-gradient(ellipse at 16% 60%,rgba(181,172,255,.16),transparent 40%),#101524}
.layout-aurora .cine-wrap{grid-template-columns:1fr;gap:28px}.layout-aurora .cine-copy{text-align:center;max-width:900px;margin:auto}.layout-aurora .cine-copy h1{max-width:none;font-size:clamp(3.4rem,8vw,7rem)}
.layout-aurora .cine-sub{margin:auto}.layout-aurora .cine-meta,.layout-aurora .offer-pills,.layout-aurora .cine-copy .actions{justify-content:center}
.layout-aurora .cine-visual{width:min(100%,1020px);margin:auto;min-height:510px}.layout-aurora .main-screen{inset:18px 80px 40px;border-radius:38px}.layout-aurora .stack-outline{border-radius:44px}
.layout-aurora .story-canvas{background:#202844;border-radius:45px}.layout-aurora .feature-grid{grid-template-columns:1fr 1.6fr 1fr}.layout-aurora .feature-card{border-radius:36px}
@media(max-width:1080px){.layout-atelier .cine-wrap,.layout-arcade .cine-wrap,.layout-atelier .story-canvas,.layout-arcade .story-canvas,.layout-atelier .feature-grid,.layout-arcade .feature-grid,.layout-aurora .feature-grid{grid-template-columns:1fr}.layout-atelier .feature-card.media,.layout-arcade .feature-card.light{grid-row:auto;grid-column:auto}.layout-atelier .story-canvas{transform:none!important}}
@media(max-width:720px){.layout-atelier .cine-wrap,.layout-arcade .cine-wrap{gap:20px}.layout-atelier .main-screen{inset:30px 14px}.layout-arcade .main-screen{inset:35px 14px}.layout-aurora .cine-visual{min-height:340px}.layout-aurora .main-screen{inset:35px 18px}.layout-aurora .cine-hero{padding-top:100px}}

.layout-editorial .cine-hero{background:#ece9e2;color:#15171c;padding-top:120px}
.layout-editorial .cine-wrap{grid-template-columns:minmax(0,.88fr) minmax(0,1.12fr);gap:64px}
.layout-editorial .cine-copy h1,.layout-editorial .cine-copy .cine-sub{color:#17191e}
.layout-editorial .cine-copy h1{font-family:Georgia,serif;font-weight:500;letter-spacing:-.065em}
.layout-editorial .cine-eyebrow{color:#9b6a1a}
.layout-editorial .cine-meta span,.layout-editorial .offer-pills a{background:#ffffffb5;color:#222;border-color:#c9c6bf}
.layout-editorial .cine-noise{opacity:.08}.layout-editorial .hero-fade{background:linear-gradient(180deg,transparent 75%,#ece9e2)}
.layout-editorial .cine-visual{transform:none!important}.layout-editorial .stack-outline{display:none}
.layout-editorial .main-screen{inset:18px 12px 10px 12px;border-radius:8px}
.layout-editorial .float-card{border-radius:7px}.layout-editorial .fc-a{left:-30px;top:12px}.layout-editorial .fc-b{right:-18px;top:36%}
.layout-editorial .story-canvas{grid-template-columns:1fr 1fr;background:#efeee8;color:#141820}
.layout-editorial .story-panel h2,.layout-editorial .story-panel p{color:#20242c}
.layout-editorial .story-stats div{background:#ffffff;border:1px solid #d9d6cb}.layout-editorial .story-stats b{color:#141820}
.layout-editorial .feature-grid{grid-template-columns:1fr 1.6fr}.layout-editorial .feature-card.light{grid-column:1/-1;min-height:200px}
.layout-market .cine-hero{background:linear-gradient(145deg,#071b21,#0c1220 70%)}
.layout-market .cine-wrap{grid-template-columns:1fr;gap:20px}.layout-market .cine-copy{text-align:center;margin:auto;max-width:930px}
.layout-market .cine-copy h1{max-width:none}.layout-market .cine-sub{margin:auto}.layout-market .cine-meta,.layout-market .offer-pills,.layout-market .cine-copy .actions{justify-content:center}
.layout-market .cine-visual{width:min(100%,930px);margin:auto;min-height:430px}.layout-market .main-screen{inset:35px 120px 30px 120px;border-radius:26px}
.layout-market .stack-outline{inset:20px 90px}.layout-market .fc-a{top:12px;left:80px}.layout-market .fc-b{top:80px;right:65px}.layout-market .fc-c{right:100px}
.layout-market .story-canvas{background:#0a2028}.layout-market .feature-grid{grid-template-columns:1.5fr 1fr}.layout-market .feature-card.dark{grid-column:1/-1;min-height:200px}
.layout-neon .cine-hero{background:radial-gradient(900px circle at 80% 20%,rgba(68,246,255,.14),transparent 30%),radial-gradient(900px circle at 18% 12%,rgba(155,77,255,.12),transparent 30%),linear-gradient(180deg,#03040a,#050712)}
.layout-neon .cine-wrap{grid-template-columns:minmax(0,.95fr) minmax(380px,.95fr)}.layout-neon .cine-copy h1{text-shadow:0 0 20px rgba(68,246,255,.08)}
.layout-neon .stack-outline{border-color:rgba(86,95,255,.35);border-radius:20px}.layout-neon .screen-caption{background:rgba(6,8,17,.82);border-color:rgba(68,246,255,.22)}
.layout-neon .story-canvas{background:linear-gradient(130deg,#0a1120,#090b16)}.layout-neon .copyline.on{color:#d9f9ff}.layout-neon .feature-grid{grid-template-columns:1.25fr .75fr}.layout-neon .feature-card.media{grid-row:span 2}
.layout-mono .cine-hero{background:linear-gradient(180deg,#07090c,#0a0d11)}.layout-mono .cine-wrap{grid-template-columns:minmax(0,.92fr) minmax(380px,1.08fr)}
.layout-mono .cine-copy h1{max-width:13ch}.layout-mono .stack-outline{display:none}.layout-mono .main-screen{inset:14px;border-radius:16px}.layout-mono .float-card{border-radius:16px}
.layout-mono .story-canvas{grid-template-columns:1.1fr .9fr;background:#0d1015}.layout-mono .feature-grid{grid-template-columns:1fr 1fr 1fr}.layout-mono .feature-card{padding:24px;border-radius:18px}.layout-mono .feature-card.light{background:#101317}
@media(max-width:1080px){.layout-editorial .cine-wrap,.layout-editorial .story-canvas,.layout-editorial .feature-grid,.layout-market .feature-grid,.layout-neon .feature-grid,.layout-mono .feature-grid,.layout-mono .story-canvas{grid-template-columns:1fr}.layout-editorial .feature-card.light,.layout-market .feature-card.dark,.layout-neon .feature-card.media{grid-column:auto;grid-row:auto}}
@media(max-width:720px){.layout-editorial .cine-hero{padding-top:90px}.layout-editorial .main-screen{inset:24px 10px}.layout-editorial .fc-a{left:0}.layout-market .main-screen{inset:34px 24px}.layout-market .stack-outline{inset:22px 18px}.layout-market .fc-a{left:2px}.layout-market .fc-b{right:2px}.layout-market .fc-c{right:30px}.layout-neon .cine-wrap,.layout-mono .cine-wrap{grid-template-columns:1fr}}
@media(max-width:1080px){.cine-wrap,.story-canvas,.feature-grid{grid-template-columns:1fr}.cine-visual{min-height:430px}.feature-card{min-height:0}.story-shell{height:auto;padding:8px 0 0}.story-stick{position:relative;top:auto;height:auto}.story-canvas{width:min(100% - 32px,1220px)}.story-media{min-height:300px}.feature-grid{display:grid;gap:16px}.copylines{max-width:none}.copyline{max-width:30ch}}
@media(max-width:720px){.cine-hero{padding-top:92px}.cine-wrap{width:calc(100% - 24px);gap:24px}.cine-copy h1{font-size:clamp(2.7rem,16vw,4.2rem);max-width:12ch}.cine-sub{font-size:.98rem}.cine-visual{min-height:330px}.main-screen{inset:40px 14px 40px}.stack-outline{inset:26px 6px}.float-card{width:84px;height:84px;border-radius:20px}.fc-a{top:8px;left:2px}.fc-b{right:0;top:86px}.fc-c{right:36px;bottom:2px;width:74px;height:74px}.screen-caption{left:22px;right:22px;bottom:8px;padding:10px 12px;border-radius:14px}.story-canvas{width:calc(100% - 24px);border-radius:24px}.story-panel{padding:22px}.story-panel h2{font-size:1.85rem}.story-stats{grid-template-columns:1fr}.copyline{font-size:1.4rem;max-width:100%}.go-shop-search input{width:100%}.feature-card{padding:22px;border-radius:24px}}
</style>
<script>(function(){var inp=document.getElementById('goOfferSearch'),grid=document.getElementById('goOfferGrid'),count=document.getElementById('goFound'),empty=document.getElementById('goNoResults');if(inp&&grid){var items=[].slice.call(grid.querySelectorAll('.card'));inp.addEventListener('input',function(){var q=inp.value.trim().toLocaleLowerCase(),n=0;items.forEach(function(el){var show=el.textContent.toLocaleLowerCase().includes(q);el.style.display=show?'':'none';if(show)n++;});count.textContent=n+' offers';empty.style.display=n?'none':'block';});}
var lines=[].slice.call(document.querySelectorAll('.copyline'));if(lines.length&&'IntersectionObserver' in window){var io=new IntersectionObserver(function(entries){entries.forEach(function(entry){if(entry.isIntersecting)entry.target.classList.add('on');})},{threshold:.45});lines.forEach(function(el){io.observe(el)})}else{lines.forEach(function(el){el.classList.add('on')})}
var shell=document.querySelector('[data-story-shell]'),canvas=document.querySelector('[data-story-canvas]');if(shell&&canvas&&window.matchMedia('(min-width: 801px)').matches&&!window.matchMedia('(prefers-reduced-motion: reduce)').matches){var ticking=false;var run=function(){ticking=false;var rect=shell.getBoundingClientRect(),vh=window.innerHeight||1,total=Math.max(1,shell.offsetHeight-vh),p=Math.min(1,Math.max(0,-rect.top/total));var scale=1-p*.12,shift=p*26;canvas.style.transform='translate3d(0,'+shift+'px,0) scale('+scale+')';canvas.style.borderRadius=(34+p*14)+'px';};addEventListener('scroll',function(){if(!ticking){ticking=true;requestAnimationFrame(run)}},{passive:true});run();}
var stack=document.querySelector('[data-cine-stack]');if(stack&&matchMedia('(pointer:fine)').matches&&!matchMedia('(prefers-reduced-motion: reduce)').matches){stack.addEventListener('pointermove',function(e){var r=stack.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;stack.style.transform='rotateY('+(x*7)+'deg) rotateX('+(-y*5)+'deg)'});stack.addEventListener('pointerleave',function(){stack.style.transform=''})}})()</script>`;
  const extraHtml = `<style>.go-steps{width:min(100% - 28px,1100px);margin:50px auto;display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.go-steps div{padding:22px;border-radius:20px;background:color-mix(in srgb,var(--a) 8%,var(--panel));border:1px solid color-mix(in srgb,var(--a) 22%,transparent)}.go-steps b{display:grid;place-items:center;width:34px;height:34px;border-radius:50%;background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);margin-bottom:10px}.go-steps h3{margin:0 0 6px;font-size:1.05rem}.go-steps p{margin:0;opacity:.75;font-size:.92rem}.go-stick{display:none}@media(max-width:720px){.go-steps{grid-template-columns:1fr}.go-stick{display:flex;position:fixed;left:10px;right:10px;bottom:calc(10px + env(safe-area-inset-bottom));z-index:80;gap:8px}.go-stick a{flex:1;text-align:center;padding:13px;border-radius:999px;font-weight:800;text-decoration:none;background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);box-shadow:0 8px 24px #0006}.go-stick a.sec{background:var(--panel);color:inherit;border:1px solid var(--line)}body{padding-bottom:80px}}</style><section class="go-steps"><div><b>1</b><h3>Choose</h3><p>Browse the offers and pick what fits you.</p></div><div><b>2</b><h3>Request</h3><p>Send a short request or book a time.</p></div><div><b>3</b><h3>Get it done</h3><p>We reply fast and take care of the rest.</p></div></section><nav class="go-stick">${phoneRaw ? `<a class="sec" href="tel:${esc(phoneRaw)}">Call</a>` : ''}${user.bookingEnabled ? '<a href="#book">Request an appointment</a>' : ''}</nav>`;
  return pageShell(user, { title: user.siteName, desc: `${user.siteName} - ${user.category || ''} in ${user.city || ''}`, body: user._studio ? body : body + extraHtml, page: 'home' });
}

function renderOfferPage(user, offer, others, sent) {
  const g = galleryOf(offer);
  const soldOut=!!(user._stockMap&&Object.prototype.hasOwnProperty.call(user._stockMap,String(offer._id))&&Number(user._stockMap[String(offer._id)])===0);
  const thumbs = g.length > 1 ? `<div class="thumbs">${g.map((u, i) => `<button type="button" class="${i === 0 ? 'on' : ''}" aria-label="Photo ${i + 1}"><img src="${esc(u)}" alt="" loading="lazy"></button>`).join('')}</div>` : '';
  const main = g.length
    ? `<div class="main" id="mainPic" data-imgs="${esc(JSON.stringify(g))}"><img id="mainImg" src="${esc(g[0])}" alt="${esc(offer.title)}">${g.length > 1 ? '<button class="nav p" id="prev" aria-label="Previous photo">&#8249;</button><button class="nav n" id="next" aria-label="Next photo">&#8250;</button>' : ''}</div>${thumbs}`
    : `<div class="main">${artPlaceholder(offer.title, user.categoryLabel || user.category || 'Offer preview')}</div>`;
  const more = others.length ? `<h2 class="rv" style="font-size:1.8rem;margin:70px 0 26px">More from ${esc(sellerName(user))}</h2><div class="grid">${others.map((o, i) => offerCard(user, o, i)).join('')}</div>` : '';
  const phoneRaw = String(user.phone || '').replace(/[^\d+]/g, '');
  const ld = JSON.stringify({ '@context': 'https://schema.org', '@type': 'Product', name: offer.title, description: String(offer.description || offer.title), image: g, offers: { '@type': 'Offer', price: Number(offer.price || 0).toFixed(2), priceCurrency: 'EUR', availability: 'https://schema.org/InStock', seller: { '@type': 'Organization', name: user.siteName } } }).replace(/</g, '\\u003c');
  const body = `<script type="application/ld+json">${ld}</script><div class="prog" id="prog"></div>${siteBar(user, 'offer')}
<main class="wrap">
<a class="crumb" href="/site/${esc(user.slug)}#offers">&larr; Back to all offers</a>
<div class="detail">
  <div class="gal">${main}</div>
  <div class="info">
    <h1>${esc(offer.title)}</h1>
    <div class="price">${eur(offer.price)}</div>${soldOut?'<p role="status" style="color:#ff9292;font-weight:700;margin-bottom:15px">Currently sold out — contact the seller for details.</p>':''}
    <div class="actions">
      <a class="abtn pri" href="/site/${esc(user.slug)}/messages?offer=${offer._id}">${MSG_SVG}Message</a>
      ${phoneRaw ? `<a class="abtn" href="tel:${esc(phoneRaw)}">${PHONE_SVG}<span class="t2">Call</span></a>` : ''}
      <button type="button" class="heart lg" data-id="${offer._id}" aria-pressed="false" aria-label="Save">${HEART_PATH}<span class="t"></span></button>
      <button type="button" class="share abtn" id="shareBtn" aria-label="Share">${SHARE_SVG}<span class="t2">Share</span></button>
    </div>
    <a class="seller" href="/site/${esc(user.slug)}/profile"><span class="sav">${esc(initials(sellerName(user)))}</span><div><b>${esc(sellerName(user))}</b><small>${[user.siteName, user.city].filter(Boolean).map(esc).join(' &middot; ')}</small></div><em>View profile →</em></a>
    ${offer.description ? `<p class="short">${esc(offer.description)}</p>` : ''}
    ${offer.longDescription ? `<p class="long">${esc(offer.longDescription)}</p>` : ''}
    <div class="glass req" id="request">
      <h2>Request this offer</h2>
      ${sent ? `<div class="ok" style="margin-bottom:14px">Thank you. Your request was sent and the business will contact you.${sentTrack(user)}</div>` : ''}
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
  </div>
</div>
<div style="margin-top:80px">${aboutBlock(user)}</div>
${more}
</main>
<div class="lb" id="lb"><img id="lbImg" alt=""></div>
<div class="stick"><b>${eur(offer.price)}</b><a class="alt" href="#request">Request</a><a href="/site/${esc(user.slug)}/messages?offer=${offer._id}">Message</a></div>
<footer><b>${esc(user.siteName)}</b><span>Built with <a href="${PUBLIC_BASE}" target="_blank" rel="noopener">GoldOffer Studio</a></span></footer>`;
  return pageShell(user, { title: `${offer.title} - ${user.siteName}`, desc: String(offer.description || offer.title).slice(0, 160), body, cls: 'offerpage', page: 'offer' });
}

function renderFavoritesPage(user) {
  const body = `<div class="prog" id="prog"></div>${siteBar(user, 'fav')}
<main class="wrap">
<a class="crumb" href="/site/${esc(user.slug)}#offers">&larr; Back to all offers</a>
<h2>Your favorites</h2><p class="sub">Offers you saved with the heart. They are kept in this browser only, so no account is needed.</p>
<div class="grid" id="favList"><p class="none">Loading...</p></div>
</main>
<footer><b>${esc(user.siteName)}</b>${[user.category, user.city].filter(Boolean).map(esc).join(' &middot; ')}<div style="margin-top:18px">Built with GoldOffer Studio</div></footer>`;
  return pageShell(user, { title: `Favorites - ${user.siteName}`, desc: `Offers you saved at ${user.siteName}`, body, page: 'favorites' });
}

// ---------- Header bar shared by all public pages: brand + icon buttons (Saved, Messages) ----------
const MSG_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>';
const PHONE_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>';
const PIN_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 10c0 7-9 13-9 13S3 17 3 10a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>';
const SHARE_SVG = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 12v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7"/><polyline points="16 6 12 2 8 6"/><line x1="12" y1="2" x2="12" y2="15"/></svg>';
function siteBar(user, kind) {
  const s = esc(user.slug);
  const first = kind === 'home'
    ? '<a class="hide-m" href="#offers">Offers</a><a class="hide-m" href="#about">About</a>'
    : `<a class="hide-m" href="/site/${s}#offers">All offers</a>`;
  return `<header class="bar"><b>${esc(user.siteName)}</b><nav>${first}<a class="hide-m" href="/site/${s}/profile">Seller profile</a><a class="navi" href="/site/${s}/favorites" aria-label="Saved offers">${HEART_PATH}<span class="lab">Saved</span><span class="nbadge" id="favCount"></span></a><a class="navi" href="/site/${s}/messages" aria-label="Messages">${MSG_SVG}<span class="lab">Messages</span><span class="nbadge" id="msgBadge"></span></a></nav></header>`;
}

// ---------- Messages page (opens from the Messages button): list of chats + the open chat, photos/files and voice calls ----------
// This function runs in the visitor's browser (it is sent as text), so it must not use anything from the server.
function messengerClient() {
  var root = document.getElementById('msgr');
  var slug = root.getAttribute('data-slug');
  var biz = root.getAttribute('data-biz');
  var KEY = 'chats:' + slug, NKEY = 'vname:' + slug, EKEY = 'vmail:' + slug;
  var $ = function (id) { return document.getElementById(id); };
  var P = {
    clip: '<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>',
    phone: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/>',
    send: '<line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>',
    back: '<line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/>',
    file: '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/>',
    chat: '<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>',
    mic: '<path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/>',
    micoff: '<path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="1" y1="1" x2="23" y2="23"/>'
  };
  function ic(n) { return '<svg viewBox="0 0 24 24" aria-hidden="true">' + P[n] + '</svg>'; }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (m) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]; }); }
  function saved() { try { return JSON.parse(localStorage.getItem(KEY) || '[]'); } catch (e) { return []; } }
  function putSaved(a) { try { localStorage.setItem(KEY, JSON.stringify(a.slice(0, 20))); } catch (e) {} }
  function jfetch(url, opts) {
    return fetch(url, opts).then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, d: d }; }); });
  }
  function post(url, body) { return jfetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); }
  var tt;
  function toast(m) { var t = $('toast'); t.textContent = m; t.style.display = 'block'; clearTimeout(tt); tt = setTimeout(function () { t.style.display = 'none'; }, 3500); }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function hhmm(d) { return pad(d.getHours()) + ':' + pad(d.getMinutes()); }
  function fmtTime(v) { var x = new Date(v), n = new Date(); return x.toDateString() === n.toDateString() ? hhmm(x) : pad(x.getDate()) + '.' + pad(x.getMonth() + 1); }
  function dayLabel(d) {
    var n = new Date(), y = new Date(Date.now() - 864e5);
    if (d.toDateString() === n.toDateString()) return 'Today';
    if (d.toDateString() === y.toDateString()) return 'Yesterday';
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long' });
  }
  function size(n) { return n < 1024 ? n + ' B' : n < 1048576 ? Math.round(n / 1024) + ' KB' : (n / 1048576).toFixed(1) + ' MB'; }
  function preview(m) {
    if (!m) return '';
    if (m.from === 'system') return m.text;
    var who = m.from === 'customer' ? 'You: ' : '';
    if (m.att && m.att.name && !m.text) return who + '📎 ' + m.att.name;
    return who + (m.text || '');
  }
  function fitBar() { var bar = document.querySelector('.bar'); if (bar) document.querySelector('.mwrap').style.top = bar.offsetHeight + 'px'; }
  fitBar(); addEventListener('resize', fitBar);
  document.querySelectorAll('[data-ic]').forEach(function (b) { b.innerHTML = ic(b.getAttribute('data-ic')); });

  var convs = [], cur = null, count = -1, pollT = null, newOffer = null, CALL = null, ICE = null;

  // ----- list of conversations -----
  function badge() {
    var n = 0; convs.forEach(function (c) { n += c.unread || 0; });
    var b = $('msgBadge'); if (b) b.textContent = n || '';
  }
  function renderList() {
    var box = $('mList');
    if (!convs.length) { box.innerHTML = '<p class="none" style="padding:18px">No conversations yet. Open an offer and tap Message to write to ' + esc(biz) + '.</p>'; return; }
    box.innerHTML = convs.map(function (c) {
      var av = c.offerImage ? '<img src="' + esc(c.offerImage) + '" alt="">' : esc(String(c.offerTitle || '?').charAt(0).toUpperCase());
      var on = cur && String(cur.id) === String(c.id) ? ' on' : '';
      return '<button type="button" class="citem' + on + '" data-id="' + esc(c.id) + '"><span class="cav">' + av + '</span>' +
        '<span class="cmid"><small>' + esc(biz) + '</small><b>' + esc(c.offerTitle) + '</b><span>' + esc(preview(c.last)) + '</span></span>' +
        '<span class="cend"><span>' + (c.lastAt ? esc(fmtTime(c.lastAt)) : '') + '</span>' + (c.unread ? '<i class="nbadge" style="font-style:normal">' + c.unread + '</i>' : '') + '</span></button>';
    }).join('');
  }
  function loadList(cb) {
    var s = saved();
    if (!s.length) { convs = []; renderList(); badge(); if (cb) cb(); return; }
    post('/site/' + slug + '/chat/list', { chats: s }).then(function (x) {
      if (x.ok) convs = x.d.conversations || [];
      convs.forEach(function (c) { if (cur && String(c.id) === String(cur.id)) c.unread = 0; });
      renderList(); badge();
      var r = convs.filter(function (c) { return c.ringing; })[0];
      if (r && !CALL) { if (!cur || String(cur.id) !== String(r.id)) openConv(r.id); startIncoming(); }
      if (cb) cb();
    }).catch(function () { if (cb) cb(); });
  }

  // ----- the open chat -----
  function showPane(title, img, price, offerId) {
    $('mEmpty').style.display = 'none'; $('mPane').style.display = 'flex';
    $('mAv').textContent = biz.charAt(0).toUpperCase(); $('mName').textContent = biz;
    var o = $('mOffer'); o.href = '/site/' + slug + '/offer/' + offerId;
    o.innerHTML = (img ? '<img src="' + esc(img) + '" alt="">' : '<span class="ph2">' + esc(String(title || '?').charAt(0).toUpperCase()) + '</span>') +
      '<div><b>' + esc(title) + '</b>' + (price != null ? '<span>&euro;' + Number(price).toFixed(2) + '</span>' : '') + '</div>';
  }
  function showList() {
    cur = null; newOffer = null; clearInterval(pollT);
    root.setAttribute('data-view', 'list');
    $('mPane').style.display = 'none'; $('mEmpty').style.display = 'flex';
    renderList();
  }
  function openConv(id, fromUser) {
    var s = saved().filter(function (x) { return String(x.id) === String(id); })[0];
    if (!s) return;
    cur = { id: String(id), token: s.token, offerId: s.offerId };
    newOffer = null; count = -1;
    var c = convs.filter(function (x) { return String(x.id) === String(id); })[0] || {};
    showPane(c.offerTitle || '', c.offerImage, c.offerPrice, c.offerId || s.offerId);
    $('mNew').style.display = 'none'; $('mSend').style.display = 'flex'; $('mCall').style.display = '';
    $('mBody').innerHTML = '';
    root.setAttribute('data-view', 'thread');
    if (fromUser) { try { history.pushState({ t: 1 }, ''); } catch (e) {} }
    renderList(); pull();
    clearInterval(pollT); pollT = setInterval(function () { if (!document.hidden) pull(); }, 3000);
  }
  function openNew(offerId) {
    cur = null; count = -1; clearInterval(pollT);
    fetch('/site/' + slug + '/offers.json?ids=' + encodeURIComponent(offerId)).then(function (r) { return r.json(); }).then(function (d) {
      var o = (d.offers || [])[0];
      if (!o) { toast('This offer is no longer available.'); showList(); return; }
      newOffer = o; showPane(o.title, o.image, o.price, o.id);
      $('mBody').innerHTML = '<p class="hint">Write your first message to ' + esc(biz) + '. Their reply will show up right here.</p>';
      $('mSend').style.display = 'none'; $('mNew').style.display = 'grid'; $('mCall').style.display = 'none';
      try { $('nName').value = localStorage.getItem(NKEY) || ''; $('nMail').value = localStorage.getItem(EKEY) || ''; } catch (e) {}
      root.setAttribute('data-view', 'thread');
    }).catch(function () { toast('Could not open the offer.'); });
  }
  function forget(id) {
    putSaved(saved().filter(function (x) { return String(x.id) !== String(id); }));
    convs = convs.filter(function (c) { return String(c.id) !== String(id); });
    showList(); badge();
  }
  function pull() {
    if (!cur) return;
    var c = cur;
    jfetch('/site/' + slug + '/chat/' + c.id + '?token=' + encodeURIComponent(c.token)).then(function (x) {
      if (cur !== c) return;
      if (x.status === 404) { forget(c.id); return; }
      if (!x.ok) return;
      var m = x.d.messages || [];
      if (m.length !== count) draw(m);
      if (x.d.call && x.d.call.status === 'ringing' && x.d.call.caller === 'seller' && !CALL) startIncoming();
    }).catch(function () {});
  }
  function draw(msgs) {
    var box = $('mBody');
    var stick = count < 0 || box.scrollHeight - box.scrollTop - box.clientHeight < 100;
    var html = '', lastDay = '';
    msgs.forEach(function (m) {
      var d = new Date(m.at), day = d.toDateString();
      if (day !== lastDay) { lastDay = day; html += '<div class="dsep">' + esc(dayLabel(d)) + '</div>'; }
      var t = hhmm(d);
      if (m.from === 'system') { html += '<div class="bub sys">' + esc(m.text) + '<small>' + t + '</small></div>'; return; }
      var inner = '';
      if (m.att && m.att.url) {
        if (/^image\//.test(m.att.mime || '')) inner += '<a href="' + esc(m.att.url) + '" target="_blank" rel="noopener"><img class="att-img" src="' + esc(m.att.url) + '" alt="' + esc(m.att.name) + '"></a>';
        else inner += '<a class="att-file" href="' + esc(m.att.url) + '" target="_blank" rel="noopener">' + ic('file') + '<span>' + esc(m.att.name) + '<small>' + esc(size(m.att.size || 0)) + '</small></span></a>';
      }
      if (m.text) inner += '<div>' + esc(m.text) + '</div>';
      html += '<div class="bub ' + (m.from === 'customer' ? 'me' : 'them') + '">' + inner + '<small>' + t + '</small></div>';
    });
    box.innerHTML = html || '<p class="hint">No messages yet.</p>';
    count = msgs.length;
    if (stick) {
      box.scrollTop = box.scrollHeight;
      box.querySelectorAll('img.att-img').forEach(function (im) { im.addEventListener('load', function () { box.scrollTop = box.scrollHeight; }); });
    }
  }

  // ----- sending: text, photos and files -----
  var ta = $('mText');
  function grow(el) { el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 130) + 'px'; }
  ta.addEventListener('input', function () { grow(ta); });
  ta.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !e.shiftKey && matchMedia('(pointer:fine)').matches) { e.preventDefault(); $('mSend').requestSubmit(); }
  });
  $('mSend').addEventListener('submit', function (e) {
    e.preventDefault();
    var t = ta.value.trim(); if (!t || !cur) return;
    var c = cur; ta.value = ''; grow(ta);
    post('/site/' + slug + '/chat/' + c.id + '/send', { token: c.token, text: t }).then(function (x) {
      if (x.ok && x.d.messages) { if (cur === c) draw(x.d.messages); loadList(); }
      else { ta.value = t; toast(x.d.message || 'Could not send.'); }
    }).catch(function () { ta.value = t; toast('Connection problem. Please try again.'); });
  });
  function upload(c, f, caption) {
    if (f.size > 8 * 1024 * 1024) { toast('"' + f.name + '" is too big (max 8 MB).'); return Promise.resolve(); }
    var fd = new FormData(); fd.append('token', c.token); fd.append('text', caption || ''); fd.append('file', f, f.name || 'photo.png');
    var h = $('mHint'); h.textContent = 'Sending ' + (f.name || 'photo') + '...'; h.style.display = 'block';
    return fetch('/site/' + slug + '/chat/' + c.id + '/attach', { method: 'POST', body: fd })
      .then(function (r) { return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) { h.style.display = 'none'; if (x.ok && x.d.messages) { if (cur === c) draw(x.d.messages); } else toast(x.d.message || 'Could not send the file.'); })
      .catch(function () { h.style.display = 'none'; toast('Connection problem. Please try again.'); });
  }
  function sendFiles(files) {
    if (!cur || !files.length) return;
    var c = cur, cap = ta.value.trim(); ta.value = ''; grow(ta);
    var chain = Promise.resolve();
    files.slice(0, 5).forEach(function (f, i) { chain = chain.then(function () { return upload(c, f, i === 0 ? cap : ''); }); });
    chain.then(function () { loadList(); });
  }
  $('mAtt').addEventListener('click', function () { $('mFile').click(); });
  $('mFile').addEventListener('change', function () { var fs = [].slice.call(this.files); this.value = ''; sendFiles(fs); });
  ta.addEventListener('paste', function (e) {
    var fs = e.clipboardData && e.clipboardData.files ? [].slice.call(e.clipboardData.files) : [];
    if (fs.length) { e.preventDefault(); sendFiles(fs); }
  });

  // ----- first message of a new conversation -----
  document.querySelectorAll('#mNew .chips button').forEach(function (b) { b.addEventListener('click', function () { $('nText').value = b.textContent; }); });
  $('mNew').addEventListener('submit', function (e) {
    e.preventDefault();
    var err = $('nErr'), btn = $('nBtn'); err.textContent = '';
    var name = $('nName').value.trim(), text = $('nText').value.trim(), mail = $('nMail').value.trim();
    if (!newOffer) return;
    if (!name) { err.textContent = 'Please enter your name.'; return; }
    if (!text) { err.textContent = 'Please write a message.'; return; }
    btn.disabled = true;
    var offerId = String(newOffer.id);
    post('/site/' + slug + '/chat/start', { offerId: offerId, name: name, email: mail, text: text }).then(function (x) {
      btn.disabled = false;
      if (!x.ok) { err.textContent = x.d.message || 'Could not send.'; return; }
      try { localStorage.setItem(NKEY, name); localStorage.setItem(EKEY, mail); } catch (e2) {}
      var a = saved().filter(function (c) { return String(c.offerId) !== offerId; });
      a.unshift({ offerId: offerId, id: x.d.id, token: x.d.token }); putSaved(a);
      $('nText').value = '';
      try { history.replaceState(null, '', '/site/' + slug + '/messages'); } catch (e3) {}
      loadList(function () { openConv(x.d.id); });
    }).catch(function () { btn.disabled = false; err.textContent = 'Connection problem. Please try again.'; });
  });

  // ----- voice calls (WebRTC): the server only passes the setup messages, the audio goes directly between the two browsers -----
  var ov = $('callOv'), ring = null;
  function callSupported() { return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia && window.RTCPeerConnection); }
  function getIce(cb) {
    if (ICE) return cb();
    fetch('/api/ice').then(function (r) { return r.json(); }).then(function (d) { ICE = d.iceServers || []; if(!d.relayConfigured) toast('Calls may fail across mobile networks until TURN is configured.'); cb(); })
      .catch(function () { ICE = [{ urls: 'stun:stun.l.google.com:19302' }]; cb(); });
  }
  function ringtone(on, mode) {
    if (ring) { clearInterval(ring.t); try { ring.ctx.close(); } catch (e) {} ring = null; }
    if (!on) return;
    try {
      var AC = window.AudioContext || window.webkitAudioContext, ctx = new AC();
      var beep = function () { var o = ctx.createOscillator(), g = ctx.createGain(); o.frequency.value = mode === 'in' ? 880 : 440; g.gain.value = 0.06; o.connect(g); g.connect(ctx.destination); o.start(); o.stop(ctx.currentTime + 0.35); };
      beep(); ring = { ctx: ctx, t: setInterval(beep, mode === 'in' ? 1500 : 3000) };
    } catch (e) {}
  }
  function setState(t) { $('callState').textContent = t; }
  function setPhase(p) {
    if (CALL) CALL.phase = p;
    $('cMute').style.display = p === 'in' ? 'none' : '';
    $('cAccept').style.display = p === 'in' ? '' : 'none';
  }
  function newCall(role) {
    return { conv: cur, role: role, id: null, after: 0, pc: null, stream: null, queue: [], pending: [], remoteSet: false, offer: null, t0: 0, muted: false, timer: null, tick: null, busy: false, ended: false, phase: role };
  }
  function ovOpen(c, text, phase) {
    CALL = c; $('callName').textContent = biz; $('callAv').textContent = biz.charAt(0).toUpperCase();
    $('cMute').classList.remove('on'); $('cMute').innerHTML = ic('mic'); $('cAccept').disabled = false;
    setState(text); setPhase(phase); ov.classList.remove('live'); ov.classList.add('open');
  }
  function cUrl(c, tail) { return '/site/' + slug + '/chat/' + c.conv.id + '/call' + tail; }
  function signal(c, type, data) { return post(cUrl(c, '/signal'), { token: c.conv.token, callId: c.id, type: type, data: data }); }
  function closeCall(c) {
    if (c.ended) return; c.ended = true;
    clearInterval(c.timer); clearInterval(c.tick); ringtone(false);
    try { if (c.pc) c.pc.close(); } catch (e) {}
    if (c.stream) c.stream.getTracks().forEach(function (t) { t.stop(); });
    $('remoteAudio').srcObject = null;
    ov.classList.remove('open', 'live');
    if (CALL === c) CALL = null;
    pull(); loadList();
  }
  function endRemote(c, reason) {
    if (c.ended) return;
    toast(reason === 'declined' ? 'Call declined' : (reason === 'missed' || reason === 'cancelled') ? (c.role === 'in' ? 'Missed call' : 'No answer') : 'Call ended');
    closeCall(c);
  }
  function makePc(c) {
    var pc = new RTCPeerConnection({ iceServers: ICE }); c.pc = pc;
    c.stream.getTracks().forEach(function (t) { pc.addTrack(t, c.stream); });
    pc.onicecandidate = function (e) {
      if (!e.candidate) return;
      var cd = e.candidate.toJSON ? e.candidate.toJSON() : e.candidate;
      if (c.id) signal(c, 'candidate', cd); else c.queue.push(cd);
    };
    pc.ontrack = function (e) { var a = $('remoteAudio'); a.srcObject = e.streams[0]; var p = a.play(); if (p && p.catch) p.catch(function () {}); };
    pc.onconnectionstatechange = function () {
      if (pc.connectionState === 'connected') connected(c);
      else if (pc.connectionState === 'failed') { toast('Audio connection failed. Check microphone permissions and configure TURN in Render.'); if (c.id) signal(c, 'hangup'); closeCall(c); }
    };
    return pc;
  }
  function connected(c) {
    if (c.t0 || c.ended) return;
    c.t0 = Date.now(); ringtone(false); setPhase('live'); ov.classList.add('live'); setState('00:00');
    c.tick = setInterval(function () { var s = Math.floor((Date.now() - c.t0) / 1000); setState(pad(Math.floor(s / 60)) + ':' + pad(s % 60)); }, 1000);
  }
  function addCand(c, d) {
    if (c.pc && c.remoteSet) c.pc.addIceCandidate(new RTCIceCandidate(d)).catch(function () {}); else c.pending.push(d);
  }
  function flush(c) { c.pending.splice(0).forEach(function (d) { c.pc.addIceCandidate(new RTCIceCandidate(d)).catch(function () {}); }); }
  function onSignal(c, s) {
    if (s.type === 'offer' && c.role === 'in') { c.offer = s.data; $('cAccept').disabled = false; }
    else if (s.type === 'answer' && c.role === 'out' && c.pc) {
      setState('Connecting...');
      c.pc.setRemoteDescription(new RTCSessionDescription(s.data)).then(function () { c.remoteSet = true; flush(c); }).catch(function () {});
    } else if (s.type === 'candidate') addCand(c, s.data);
  }
  function pollCall(c) {
    if (c.busy || c.ended) return; c.busy = true;
    jfetch(cUrl(c, '?after=' + c.after + '&token=' + encodeURIComponent(c.conv.token))).then(function (x) {
      c.busy = false; if (c.ended || !x.ok) return;
      var k = x.d.call;
      if (!k) { if (c.id || c.role === 'in') endRemote(c, 'ended'); return; }
      if (c.role === 'in' && !c.id && k.status === 'ringing') c.id = k.id;
      if (c.id && k.id !== c.id) { endRemote(c, 'ended'); return; }
      (x.d.signals || []).forEach(function (s) { c.after = Math.max(c.after, s.n); onSignal(c, s); });
      if (k.status === 'ended') endRemote(c, k.reason);
    }).catch(function () { c.busy = false; });
  }
  function startPoll(c) { c.timer = setInterval(function () { pollCall(c); }, 1000); pollCall(c); }

  function startOutgoing() {
    if (CALL || !cur) return;
    if (!callSupported()) { toast('Calls are not supported in this browser.'); return; }
    var c = newCall('out'); ovOpen(c, 'Calling...', 'out');
    getIce(function () {
      navigator.mediaDevices.getUserMedia({ audio: true }).then(function (stream) {
        if (c.ended) { stream.getTracks().forEach(function (t) { t.stop(); }); return; }
        c.stream = stream; var pc = makePc(c);
        return pc.createOffer().then(function (o) { return pc.setLocalDescription(o); })
          .then(function () { return post(cUrl(c, '/signal'), { token: c.conv.token, type: 'offer', data: pc.localDescription }); })
          .then(function (x) {
            if (c.ended) return;
            if (!x.ok) { toast(x.d.message || 'Could not start the call.'); closeCall(c); return; }
            c.id = x.d.callId; c.queue.splice(0).forEach(function (cd) { signal(c, 'candidate', cd); });
            ringtone(true, 'out'); startPoll(c);
          });
      }, function () { toast('Allow the microphone to make calls.'); closeCall(c); })
        .catch(function () { toast('The call failed. Please try again.'); closeCall(c); });
    });
  }
  function startIncoming() {
    if (CALL || !cur) return;
    var c = newCall('in'); ovOpen(c, 'Incoming call', 'in'); $('cAccept').disabled = true; ringtone(true, 'in'); startPoll(c);
  }
  $('mCall').addEventListener('click', startOutgoing);
  $('cAccept').addEventListener('click', function () {
    var c = CALL; if (!c || c.role !== 'in' || !c.offer || !c.id) return;
    if (!callSupported()) { toast('Calls are not supported in this browser.'); signal(c, 'decline'); closeCall(c); return; }
    ringtone(false); $('cAccept').disabled = true; setState('Connecting...');
    getIce(function () {
      navigator.mediaDevices.getUserMedia({ audio: true }).then(function (stream) {
        if (c.ended) { stream.getTracks().forEach(function (t) { t.stop(); }); return; }
        c.stream = stream; var pc = makePc(c);
        return pc.setRemoteDescription(new RTCSessionDescription(c.offer))
          .then(function () { c.remoteSet = true; flush(c); return pc.createAnswer(); })
          .then(function (a) { return pc.setLocalDescription(a); })
          .then(function () { return signal(c, 'answer', pc.localDescription); })
          .then(function (x) { if (!x.ok) { toast(x.d.message || 'Could not answer.'); closeCall(c); } else setPhase('live'); });
      }, function () { toast('Allow the microphone to answer calls.'); signal(c, 'decline'); closeCall(c); })
        .catch(function () { toast('The call failed.'); closeCall(c); });
    });
  });
  $('cDecline').addEventListener('click', function () {
    var c = CALL; if (!c) return;
    if (c.id) signal(c, c.phase === 'in' ? 'decline' : 'hangup');
    closeCall(c);
  });
  $('cMute').addEventListener('click', function () {
    var c = CALL; if (!c || !c.stream) return;
    c.muted = !c.muted;
    c.stream.getAudioTracks().forEach(function (t) { t.enabled = !c.muted; });
    this.classList.toggle('on', c.muted); this.innerHTML = ic(c.muted ? 'micoff' : 'mic');
  });

  // ----- navigation and start -----
  $('mList').addEventListener('click', function (e) { var b = e.target.closest('.citem'); if (b) openConv(b.getAttribute('data-id'), true); });
  $('mBack').addEventListener('click', function () { if (history.state && history.state.t) history.back(); else showList(); });
  addEventListener('popstate', function () { showList(); });
  document.addEventListener('visibilitychange', function () { if (!document.hidden) { pull(); loadList(); } });
  setInterval(function () { if (!document.hidden) loadList(); }, 3000);
  var want = new URLSearchParams(location.search).get('offer');
  loadList(function () {
    if (want) {
      var ex = convs.filter(function (c) { return String(c.offerId) === want; })[0];
      if (ex) { if (!cur) openConv(ex.id); } else if (!cur) openNew(want);
    } else if (convs.length && !cur && matchMedia('(min-width:861px)').matches) openConv(convs[0].id);
  });
}
const MSG_JS = '(' + messengerClient.toString() + ')();';

function renderMessagesPage(user) {
  const phoneRaw = String(user.phone || '').replace(/[^\d+]/g, '');
  const body = `${siteBar(user, 'msg')}
<div class="mwrap"><div class="msgr" id="msgr" data-view="list" data-slug="${esc(user.slug)}" data-biz="${esc(sellerName(user))}" data-phone="${esc(phoneRaw)}">
  <aside class="mside"><div class="mside-h"><h2>Messages</h2></div><div class="mlist" id="mList"><p class="none" style="padding:18px">Loading...</p></div></aside>
  <section class="mmain">
    <div class="mempty" id="mEmpty"><div class="bigico">${MSG_SVG}</div><p>Select a conversation to see it.<br>Open an offer and tap <b>Message</b> to start a new one.</p></div>
    <div class="mpane" id="mPane" style="display:none">
      <div class="mhead">
        <button type="button" class="ibtn mback" id="mBack" data-ic="back" aria-label="Back to messages"></button>
        <span class="cav" id="mAv">G</span>
        <div class="mtitle"><b id="mName"></b></div>
        <button type="button" class="ibtn go" id="mCall" data-ic="phone" aria-label="Call ${esc(sellerName(user))}"></button>
      </div>
      <a class="moffer" id="mOffer" href="#"></a>
      <div class="mbody" id="mBody"></div>
      <div class="mhint" id="mHint" style="display:none"></div>
      <form class="mcomposer" id="mSend">
        <input type="file" id="mFile" multiple hidden>
        <button type="button" class="ibtn" id="mAtt" data-ic="clip" aria-label="Attach a photo or file"></button>
        <textarea id="mText" rows="1" maxlength="1500" placeholder="Write a message..."></textarea>
        <button type="submit" class="ibtn go" data-ic="send" aria-label="Send"></button>
      </form>
      <form class="mnew" id="mNew" style="display:none">
        <div class="two"><input id="nName" placeholder="Your name" required maxlength="60"><input id="nMail" type="email" placeholder="Email (optional)" maxlength="120"></div>
        <textarea id="nText" placeholder="Write your message..." required maxlength="1500"></textarea>
        <div class="chips"><button type="button">Is this available?</button><button type="button">Can you customize it for me?</button><button type="button">What is the delivery or pickup time?</button></div>
        <div class="err" id="nErr"></div>
        <button class="btn" type="submit" id="nBtn">Send message</button>
      </form>
    </div>
  </section>
</div></div>
<div class="callov" id="callOv"><div class="callbox"><div class="callav" id="callAv">G</div><h3 id="callName"></h3><p id="callState"></p>
  <div class="callbtns">
    <button type="button" class="cbtn" id="cMute" data-ic="mic" aria-label="Mute"></button>
    <button type="button" class="cbtn red" id="cDecline" data-ic="phone" aria-label="End call"></button>
    <button type="button" class="cbtn green" id="cAccept" data-ic="phone" aria-label="Answer"></button>
  </div></div></div>
<audio id="remoteAudio" autoplay playsinline></audio>
<div class="toast" id="toast" style="display:none"></div>
<script>${MSG_JS}</script>`;
  return pageShell(user, { title: `Messages - ${user.siteName}`, desc: `Your conversations with ${user.siteName}`, body, cls: 'mpage', page: 'messages' });
}

const SITE_CSP = [
  "default-src 'self'",
  "script-src 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data: https:",
  "frame-src 'self' https://www.google.com",
  "form-action 'self'",
  "base-uri 'self'"
].join('; ');


// Public storefront feedback. No purchase verification is implied.
// Public offer update feed for browser-local followed shops. No account tracking.
app.get('/api/storefront/:slug/updates', async(req,res)=>{
  try{
    const seller=await User.findOne({slug:req.params.slug,published:true}).select('_id siteName').lean();
    if(!seller)return res.status(404).json({message:'Website not found'});
    const offers=await Offer.find({userId:seller._id}).select('_id title createdAt').sort({createdAt:-1}).limit(10).lean();
    res.set('Cache-Control','no-store');
    res.json({seller:seller.siteName,offers:offers.map(x=>({id:x._id,title:x.title,createdAt:x.createdAt}))});
  }catch(e){res.status(500).json({message:'Cannot check updates'});}
});
app.get('/api/storefront/:slug/reviews', async (req, res) => {
  try {
    const seller = await User.findOne({ slug: req.params.slug, published: true }).select('_id');
    if (!seller) return res.status(404).json({ message: 'Website not found' });
    const [reviews, stats] = await Promise.all([
      Review.find({ sellerId: seller._id }).select('name rating comment createdAt').sort({createdAt:-1}).limit(60).lean(),
      Review.aggregate([{ $match:{sellerId:seller._id} }, {$group:{_id:null, count:{$sum:1}, avg:{$avg:'$rating'}}}])
    ]);
    res.json({ reviews, count:stats[0]?.count||0, average:Math.round((stats[0]?.avg||0)*10)/10, verified:false });
  } catch(e) { res.status(500).json({message:'Cannot load reviews'}); }
});
app.post('/api/storefront/:slug/reviews', publicLimiter, async (req, res) => {
  try {
    const seller = await User.findOne({ slug:req.params.slug, published:true }).select('_id');
    if (!seller) return res.status(404).json({message:'Website not found'});
    const {name,email,comment,rating} = req.body||{};
    const n=String(name||'').trim(), mail=String(email||'').trim().toLowerCase(), c=String(comment||'').trim();
    const r=Number(rating);
    if(n.length<2||n.length>60||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(mail)||c.length>600||!Number.isInteger(r)||r<1||r>5)
      return res.status(400).json({message:'Check your name, email, rating and comment.'});
    const emailHash=crypto.createHash('sha256').update(String(seller._id)+':'+mail).digest('hex');
    await Review.create({sellerId:seller._id,name:n,emailHash,rating:r,comment:c});
    res.status(201).json({message:'Thanks for sharing your feedback.'});
  } catch(e) {
    if(e.code===11000)return res.status(409).json({message:'You have already reviewed this website.'});
    res.status(500).json({message:'Unable to save review'});
  }
});
app.get('/api/my/reviews', authenticateToken, async(req,res)=>{
  try {
    const id=new mongoose.Types.ObjectId(req.user.id);
    const [reviews,stats]=await Promise.all([
      Review.find({sellerId:id}).select('name rating comment createdAt').sort({createdAt:-1}).limit(100).lean(),
      Review.aggregate([{$match:{sellerId:id}},{$group:{_id:null,count:{$sum:1},avg:{$avg:'$rating'}}}])
    ]);
    res.json({reviews,count:stats[0]?.count||0,average:Math.round((stats[0]?.avg||0)*10)/10});
  }catch(e){res.status(500).json({message:'Unable to load feedback'});}
});


// ----- Studio mode: the owner's editor frame loads the real pages with a short-lived ticket -----
function studioOk(req, user) {
  try { const t = jwt.verify(String(req.query.studio || ''), process.env.JWT_SECRET); return !!(t && t.studio && user && String(t.id) === String(user._id)); } catch (e) { return false; }
}
app.use((req, res, next) => {
  if (req.query && req.query.studio && String(req.path).startsWith('/site/')) {
    const orig = res.setHeader.bind(res);
    res.setHeader = (k, v) => (/^content-security-policy$/i.test(k) ? orig(k, String(v) + '; frame-ancestors ' + FRONTEND_URL + ' ' + PUBLIC_BASE + ' http://localhost:*') : orig(k, v));
    res.removeHeader('X-Frame-Options'); res.setHeader('Cache-Control', 'no-store');
  }
  next();
});
// sets the design the page should show (draft inside the editor, live for visitors); returns false if the page must be hidden
function prepSite(req, user) {
  if (!user) return false;
  const studio = !!(req.query && req.query.studio) && studioOk(req, user);
  if (!user.published && !studio) return false;
  user._studio = studio; user._gd = studio ? (user.designDraft || user.design) : user.design;
  user._track = /^[a-f0-9]{24}$/.test(String(req.query.track || '')) ? String(req.query.track) : '';
  return true;
}

app.get('/site/:slug', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!prepSite(req, user)) return res.status(404).send('Site not found.');
    const offers = await Offer.find({ userId: user._id }).sort({ createdAt: -1 });
    res.setHeader('Content-Security-Policy', SITE_CSP); res.setHeader('Cache-Control', 'no-store, max-age=0');
    const inv=await ShopSetting.findOne({sellerId:user._id}).select('stock').lean();user._stockMap=inv?.stock?Object.fromEntries(Object.entries(inv.stock)):{};user._offerOpts=offers.map(o=>({id:String(o._id),title:o.title}));res.send(renderSite(user, offers, req.query.sent === '1'));
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/site/:slug/profile', async(req,res)=>{
  try { const user=await User.findOne({slug:req.params.slug}); if(!prepSite(req,user))return res.status(404).send('Site not found');const offers=await Offer.find({userId:user._id}).sort({createdAt:-1});res.setHeader('Content-Security-Policy',SITE_CSP);const inv=await ShopSetting.findOne({sellerId:user._id}).select('stock').lean();user._stockMap=inv?.stock?Object.fromEntries(Object.entries(inv.stock)):{};res.send(renderSellerProfile(user,offers)); }
  catch(e){console.error('Seller profile error',e);res.status(500).send('Unable to load seller profile')}
});
app.get('/site/:slug/reviews',(req,res)=>res.redirect(302,'/site/'+encodeURIComponent(req.params.slug)+'/profile#reviews'));

app.get('/site/:slug/messages', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!prepSite(req, user)) return res.status(404).send('Site not found.');
    res.setHeader('Content-Security-Policy', SITE_CSP);
    res.setHeader('Permissions-Policy', 'microphone=(self)');
    res.setHeader('Cache-Control', 'no-store');
    res.send(renderMessagesPage(user));
  } catch (err) { res.status(500).send('Server error'); }
});

app.get('/site/:slug/favorites', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!prepSite(req, user)) return res.status(404).send('Site not found.');
    res.setHeader('Content-Security-Policy', SITE_CSP); res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.send(renderFavoritesPage(user));
  } catch (err) { res.status(500).send('Server error'); }
});

// One page per offer: opened by the offer ID from the card link
app.get('/site/:slug/offer/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).send('Offer not found.');
    const user = await User.findOne({ slug: req.params.slug });
    if (!prepSite(req, user)) return res.status(404).send('Site not found.');
    const offer = await Offer.findOne({ _id: req.params.id, userId: user._id });
    if (!offer) return res.status(404).send('Offer not found.');
    const others = await Offer.find({ userId: user._id, _id: { $ne: offer._id } }).sort({ createdAt: -1 }).limit(3);
    res.setHeader('Content-Security-Policy', SITE_CSP); res.setHeader('Cache-Control', 'no-store, max-age=0');
    const inv=await ShopSetting.findOne({sellerId:user._id}).select('stock').lean();user._stockMap=inv?.stock?Object.fromEntries(Object.entries(inv.stock)):{};res.send(renderOfferPage(user, offer, others, req.query.sent === '1'));
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/site/:slug/order', publicLimiter, rejectOwnerSelfAction, async (req, res) => {
  try {
    if (req.body.consent !== '1') return res.status(400).send('Please accept the privacy notice and go back.');
    const user = await User.findOne({ slug: req.params.slug, published: true });
    if (!user || !mongoose.isValidObjectId(req.body.offerId)) return res.status(404).send('Not found');
    const offer = await Offer.findOne({ _id: req.body.offerId, userId: user._id });
    if (!offer) return res.status(404).send('Offer not found');
    const inventory = await ShopSetting.findOne({sellerId:user._id}).select('stock').lean();
    const qty = inventory?.stock?.get ? inventory.stock.get(String(offer._id)) : inventory?.stock?.[String(offer._id)];
    if (qty === 0) return res.status(409).send('This offer is currently sold out. Please contact the seller.');
    const parsed = parseContacts(req.body);
    if (parsed.error) return res.status(400).send(`${esc(parsed.error)} Please go back and try again.`);
    const trackToken = crypto.randomBytes(12).toString('hex');
    const newOrder = await Order.create({
      trackToken, history: [{ status: 'Pending', at: new Date() }],
      userId: user._id, offerId: offer._id, offerTitle: offer.title, amount: offer.price,
      customerName: String(req.body.customerName || '').slice(0, 80),
      customerContact: parsed.text.slice(0, 400),
      contacts: parsed.contacts,
      note: String(req.body.note || '').replace(/\r/g, '').trim().slice(0, 1000),
      status: 'Pending'
    });
    await pushNote(user._id, 'order', String(newOrder._id), 'New request', `${String(req.body.customerName || 'A customer').slice(0, 60)} · ${offer.title}`, '/orders');
    const mailC = (parsed.contacts || []).find(c => c.type === 'email' && isEmail(c.value));
    if (mailC) void sendMail({ to: mailC.value, subject: `We received your request: ${offer.title}`, text: `Thank you! Track your request any time:\n${PUBLIC_BASE}/track/${trackToken}` });
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
    if (req.body.from === 'offer') return res.redirect(303, `/site/${user.slug}/offer/${offer._id}?sent=1&track=${trackToken}#request`);
    res.redirect(303, `/site/${user.slug}?sent=1&track=${trackToken}`);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

// ---------- Public-site language (Bulgarian translation of the fixed texts) ----------
const SITE_BG = {
  'Available when the business enables appointments.':'Достъпно, когато бизнесът включи резервации.','Choose a day to see free times.':'Избери ден, за да видиш свободните часове.',
  'Contact':'Контакти','DISCOVER':'ОТКРИЙ','Explore our work, and get in touch when you find something you like.':'Разгледай работата ни и се свържи, когато откриеш нещо, което харесваш.',
  'Find us':'Намери ни','Frequently asked questions':'Често задавани въпроси','I agree to be contacted about this booking.':'Съгласен съм да се свържете с мен за тази резервация.',
  'Location':'Локация','No matching offers.':'Няма съвпадащи оферти.','No offers yet. Please check back soon.':'Все още няма оферти. Заповядай отново скоро.','Offers':'Оферти',
  'Pick a day':'Избери ден','Privacy Policy':'Политика за поверителност','Request an appointment':'Заяви час','SELLER PROFILE':'ПРОФИЛ НА ПРОДАВАЧА','Seller reviews':'Отзиви за продавача',
  'Send booking request':'Изпрати заявка за час','THE STORY BEHIND THE BUSINESS':'ИСТОРИЯТА ЗАД БИЗНЕСА','About':'За нас','All offers':'Всички оферти','Call':'Обади се',
  'How can we reach you?':'Как да се свържем с теб?','Loading...':'Зареждане...','Message':'Съобщение','Messages':'Съобщения','Request this offer':'Заяви тази оферта','Request':'Заяви',
  'Saved':'Запазени','Seller profile':'Профил на продавача','Send request':'Изпрати заявка','Share':'Сподели','Your favorites':'Любимите ти','Built with':'Създадено с',
  'Hours':'Работно време','Price':'Цена','Reviews':'Отзиви','Send':'Изпрати','Home':'Начало','Favorites':'Любими','Track your request':'Следи заявката си','Back':'Назад',
  'Your name':'Твоето име','Your contact details':'Твоите данни за контакт','What do you need? (optional)':'От какво имаш нужда? (по избор)','Search offers by name or description...':'Търси оферти по име или описание...',
  'Your message':'Твоето съобщение','Write a message...':'Напиши съобщение...','View offer':'Виж офертата','Learn more':'Научи повече','Book now':'Запази час','Get in touch':'Свържи се',
  'Thoughtful details. Beautifully presented.':'Внимание към детайла. Красиво представено.','The curated selection':'Подбраната селекция','Next level storefront':'Магазин от ново ниво','The art of the everyday':'Изкуството на ежедневието',
  'Free times':'Свободни часове','No free times on this day. Try another day.':'Няма свободни часове този ден. Опитай друг.','Could not load times.':'Не успяхме да заредим часовете.','Please pick a time first.':'Първо избери час.',
  'Published':'Публикуван','Share this page':'Сподели страницата','Contact us':'Свържи се с нас','Our story':'Нашата история','Gallery':'Галерия','Name':'Име','Phone':'Телефон','Email':'Имейл',
  'Choose':'Избери','Browse the offers and pick what fits you.':'Разгледай офертите и избери подходящата за теб.','Send a short request or book a time.':'Изпрати кратка заявка или запази час.','Get it done':'Готово','We reply fast and take care of the rest.':'Отговаряме бързо и се грижим за останалото.','Thank you!':'Благодарим!','Your request was sent.':'Заявката ти е изпратена.','Visitor test mode — you can write and order like a customer.':'Режим на посетител — можеш да пишеш и поръчваш като клиент.','Back to owner mode':'Обратно към режим на собственик'
};
const SITE_BG_PAT = [
  ['^Messages - (.+)$','Съобщения - $1'],['^Favorites - (.+)$','Любими - $1'],['^(.+) — Seller profile$','$1 — Профил на продавача'],
  ['^(\\d+) offers?$','$1 оферти'],['^(\\d+) reviews?$','$1 отзива'],['^From (.+)$','От $1']
];
function goI18nClient(DICT, PAT) {
  var map = {}; Object.keys(DICT).forEach(function (k) { map[k.toLowerCase()] = DICT[k]; });
  var pats = PAT.map(function (p) { return [new RegExp(p[0], 'i'), p[1]]; });
  function tr(s) {
    var t = s.replace(/\s+/g, ' ').trim(); if (!t || t.length > 200) return null;
    var m = map[t.toLowerCase()]; if (m) return s.replace(t, m);
    for (var i = 0; i < pats.length; i++) if (pats[i][0].test(t)) return s.replace(t, t.replace(pats[i][0], pats[i][1]));
    return null;
  }
  function node(n) {
    if (n.nodeType === 3) { var p = n.parentNode; if (p && /^(SCRIPT|STYLE|TEXTAREA|CODE)$/.test(p.nodeName)) return; if (p && p.closest && p.closest('[data-notr],#go-free')) return; var r = tr(n.nodeValue); if (r !== null && r !== n.nodeValue) n.nodeValue = r; return; }
    if (n.nodeType !== 1) return;
    if (/^(SCRIPT|STYLE)$/.test(n.nodeName) || (n.closest && n.closest('[data-notr]'))) return;
    ['placeholder', 'title', 'aria-label', 'alt'].forEach(function (a) { if (n.hasAttribute && n.hasAttribute(a)) { var v = n.getAttribute(a), r = tr(v); if (r !== null && r !== v) n.setAttribute(a, r); } });
    for (var c = n.firstChild; c; c = c.nextSibling) node(c);
  }
  var busy = false;
  function run() { busy = true; try { node(document.body); document.title = tr(document.title) || document.title; } catch (e) {} busy = false; }
  run();
  try { new MutationObserver(function (ms) { if (busy) return; busy = true; try { ms.forEach(function (m) { m.addedNodes.forEach(node); if (m.type === 'characterData') node(m.target); }); } catch (e) {} busy = false; }).observe(document.body, { childList: true, subtree: true, characterData: true }); } catch (e) {}
}
const SITE_I18N_JS = `(${goI18nClient.toString()})(${JSON.stringify(SITE_BG)},${JSON.stringify(SITE_BG_PAT)});`;

// Translate fixed public interface phrases for the current website without touching customer content.
const siteTranslateLimiter = rateLimit({windowMs:60*60*1000,max:6});
app.post('/api/site/translate', authenticateToken, siteTranslateLimiter, async (req,res)=>{
 try {
  const u=await User.findById(req.user.id); if(!u)return res.status(404).json({message:'Site not found.'});
  const lang=String(req.body&&req.body.lang||u.siteLang||'en');
  if(!/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$/.test(lang))return res.status(400).json({message:'Invalid language.'});
  if(lang==='bg'||lang==='en') {u.siteLang=lang;await u.save();return res.json({ok:true,language:lang});}
  const key=process.env.OPENROUTER_API_KEY; if(!key)return res.status(503).json({message:'Set OPENROUTER_API_KEY on Render to translate this site.'});
  const keys=Object.keys(SITE_BG).filter(k=>k.length<=100).slice(0,160);
  const r=await axios.post('https://openrouter.ai/api/v1/chat/completions',{model:process.env.OPENROUTER_MODEL||'openrouter/free',messages:[{role:'system',content:'Translate these website UI labels into language '+lang+'. Return only one JSON object mapping every original English phrase exactly to its translation. Preserve placeholders and avoid adding commentary.'},{role:'user',content:JSON.stringify(keys)}],temperature:0.15},{headers:{Authorization:'Bearer '+key},timeout:70000});
  const translated=extractJson(r.data?.choices?.[0]?.message?.content);
  if(!translated||typeof translated!=='object'||Array.isArray(translated))return res.status(502).json({message:'Translation response was incomplete. Try again.'});
  const dictionary={}; for(const k of keys)if(typeof translated[k]==='string' && translated[k].length<=240) dictionary[k]=translated[k];
  if(Object.keys(dictionary).length<20)return res.status(502).json({message:'Translation response did not contain enough phrases.'});
  u.siteTranslations=u.siteTranslations||{};u.siteTranslations[lang]=dictionary;u.markModified('siteTranslations');u.siteLang=lang;await u.save();
  res.json({ok:true,language:lang,translated:Object.keys(dictionary).length});
 }catch(e){console.error('Site translation error:',e.response?.status||e.message);res.status(502).json({message:e.response?.status===402?'AI provider has no credits. Select a free model or add credits.':'Translation failed. Check OPENROUTER_MODEL and server logs.'});}
});

// ---------- Several websites under one account + AI site generator ----------
const aiSiteLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 12, message: { message: 'Too many generations. Try again later.' } });
const familyOf = async (userId) => {
  const me = await User.findById(userId);
  if (!me) return null;
  return me.ownerId ? await User.findById(me.ownerId) : me;
};
const SITE_CAP = (root) => (root.subscriptionStatus === 'active' ? 20 : 5);
const cleanStr = (v, n) => String(v == null ? '' : v).replace(/[<>]/g, '').trim().slice(0, n);
function extractJson(text) {
  const t = String(text || '');
  const a = t.indexOf('{'), b = t.lastIndexOf('}');
  if (a < 0 || b <= a) return null;
  try { return JSON.parse(t.slice(a, b + 1)); } catch (e) { return null; }
}

app.get('/api/my-sites', authenticateToken, async (req, res) => {
  try {
    const root = await familyOf(req.user.id);
    if (!root) return res.status(404).json({ message: 'Account not found.' });
    const subs = await User.find({ ownerId: root._id }).sort({ _id: 1 });
    const all = [root, ...subs];
    res.json({
      currentId: String(req.user.id), rootId: String(root._id), cap: SITE_CAP(root), aiReady: !!process.env.OPENROUTER_API_KEY,
      sites: all.map(u => ({ id: String(u._id), siteName: u.siteName || 'Untitled', slug: u.slug, published: !!u.published, aiGenerated: !!u.aiGenerated, isMain: String(u._id) === String(root._id), siteUrl: u.slug ? `${PUBLIC_BASE}/site/${u.slug}` : null }))
    });
  } catch (e) { res.status(500).json({ message: 'Could not load your sites.' }); }
});

app.post('/api/my-sites/:id/token', authenticateToken, async (req, res) => {
  try {
    const root = await familyOf(req.user.id);
    const target = await User.findById(req.params.id);
    if (!root || !target || (String(target._id) !== String(root._id) && String(target.ownerId) !== String(root._id))) return res.status(403).json({ message: 'Not allowed.' });
    res.json({ token: signToken(target), user: publicUser(target) });
  } catch (e) { res.status(500).json({ message: 'Could not switch site.' }); }
});

app.delete('/api/my-sites/:id', authenticateToken, async (req, res) => {
  try {
    const root = await familyOf(req.user.id);
    const target = await User.findById(req.params.id);
    if (!root || !target || !target.ownerId || String(target.ownerId) !== String(root._id)) return res.status(403).json({ message: 'Only extra sites can be deleted.' });
    await Offer.deleteMany({ userId: target._id });
    await User.deleteOne({ _id: target._id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ message: 'Could not delete the site.' }); }
});

app.post('/api/ai/site-generate', authenticateToken, aiSiteLimiter, async (req, res) => {
  try {
    const key = process.env.OPENROUTER_API_KEY;
    if (!key) return res.status(503).json({ message: 'AI is not set up yet. Add OPENROUTER_API_KEY on the server.' });
    const root = await familyOf(req.user.id);
    if (!root) return res.status(404).json({ message: 'Account not found.' });
    const count = await User.countDocuments({ ownerId: root._id });
    if (count + 1 >= SITE_CAP(root)) return res.status(400).json({ message: 'You reached the website limit for your plan.' });
    const name = cleanStr(req.body.name, 60), desc = cleanStr(req.body.description, 1500);
    const lang = (typeof req.body.lang === 'string' && /^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}$/.test(req.body.lang)) ? req.body.lang : 'en';
    const languageName = (() => { try { return new Intl.DisplayNames(['en'], { type: 'language' }).of(lang) || lang; } catch (e) { return lang; } })();
    if (!name || desc.length < 10) return res.status(400).json({ message: 'Give a name and describe the business (at least a sentence).' });
    const sys = `You create small-business websites. Reply with ONE JSON object only, no markdown. Fields: siteName (string), category (string), city (string or ""), bio (2-3 sentences), announcement (short string or ""), theme (one of ${Object.keys(THEMES).join(', ')}), layout (one of ${Object.keys(LAYOUTS).join(', ')}), font (one of ${Object.keys(FONTS).join(', ')}), offers (array of 3-6 objects {title, price (number, 0 if unknown), description}), faq (array of 3 objects {question, answer}), page (object with order array containing hero/about/offers/contact in an original order, headline, subheading, eyebrow, cta, aboutTitle, offersTitle, contactTitle, contactText, contactAction, messageAction, profileAction, align left/center, columns 2/3/4), translations (object mapping standard English UI words like Home, Offers, Contact, Message, Messages, Request, Book now, Send, Search, All offers, Seller profile, Reviews, Share, Back, Price, Saved, Favorites, About, Hours, Email, Phone, Call to natural translations in the chosen language), visual (object with accent, background, panel, text colors as 6-digit hex strings, font from inter/poppins/montserrat/raleway/space/playfair/dmserif/lora/oswald/anton/bebas/archivo/orbitron/righteous/pacifico/lobster/dancing/caveat/marker/jetbrains/comfortaa and radius number between 0 and 35). Create a unique visual identity derived from the business description rather than copying a preset color scheme. Write all user-facing texts in ${languageName} (language code ${lang}). Use only facts the owner gave; do not invent addresses, phone numbers or reviews. Prices only if the owner mentioned them, otherwise 0.`;
    const r = await axios.post('https://openrouter.ai/api/v1/chat/completions', {
      model: process.env.OPENROUTER_MODEL || 'openai/gpt-4o-mini',
      messages: [{ role: 'system', content: sys }, { role: 'user', content: `Business name: ${name}\nDescription: ${desc}` }],
      temperature: 0.7
    }, { headers: { Authorization: 'Bearer ' + key }, timeout: 60000 });
    const j = extractJson(r.data && r.data.choices && r.data.choices[0] && r.data.choices[0].message && r.data.choices[0].message.content);
    if (!j) return res.status(502).json({ message: 'AI answered in an unexpected way. Please try again.' });
    const email = `site-${root._id}-${Date.now().toString(36)}@sites.goldoffer.local`;
    const pick = (v, obj, d) => (Object.keys(obj).includes(v) ? v : d);
    const sub = new User({
      firstName: root.firstName, lastName: root.lastName, email, password: root.password,
      subscriptionStatus: root.subscriptionStatus, ownerId: root._id, aiGenerated: true, emailVerified: true,
      siteName: name, sellerBio: cleanStr(j.bio, 650), category: cleanStr(j.category, 80), city: cleanStr(j.city, 80),
      theme: pick(j.theme, THEMES, 'gold'), layout: pick(j.layout, LAYOUTS, 'signature'), font: pick(j.font, FONTS, 'sans'),
      announcementText: cleanStr(j.announcement, 200), lang: root.lang || 'bg', siteLang: lang, published: true,
      notifyEmail: root.notifyEmail || root.email,
      faqItems: (Array.isArray(j.faq) ? j.faq : []).slice(0, 6).map(f => ({ question: cleanStr(f && f.question, 160), answer: cleanStr(f && f.answer, 500) })).filter(f => f.question && f.answer)
    });
    // AI-specific design tokens, independently generated and validated by the Studio design engine.
    // The core storefront routes / offers / booking remain shared for functional compatibility.
    const vis = j.visual && typeof j.visual === 'object' ? j.visual : {};
    sub.design = sanitizeDesign({ v: {
      accent: vis.accent, bg: vis.background, panel: vis.panel, text: vis.text,
      font: vis.font, headFont: vis.font, radius: vis.radius
    }});
    sub.designDraft = sub.design;
    const pg = j.page && typeof j.page === 'object' ? j.page : {};
    const aiText = (v,n=250)=>cleanStr(v,n);
    sub.aiPage = {order:Array.isArray(pg.order)?pg.order.filter(x=>['hero','about','offers','contact'].includes(x)).slice(0,4):undefined, headline:aiText(pg.headline,150),subheading:aiText(pg.subheading,360),eyebrow:aiText(pg.eyebrow,100),cta:aiText(pg.cta,60),aboutTitle:aiText(pg.aboutTitle,140),offersTitle:aiText(pg.offersTitle,140),contactTitle:aiText(pg.contactTitle,140),contactText:aiText(pg.contactText,300),contactAction:aiText(pg.contactAction,60),messageAction:aiText(pg.messageAction,60),profileAction:aiText(pg.profileAction,60),align:pg.align==='center'?'center':'left',columns:[2,3,4].includes(Number(pg.columns))?Number(pg.columns):3};
    if (j.translations && typeof j.translations === 'object' && !Array.isArray(j.translations)) sub.siteTranslations = {[lang]:Object.fromEntries(Object.entries(j.translations).filter(([k,v])=>typeof k==='string' && k.length<=100 && typeof v==='string').slice(0,110).map(([k,v])=>[k,cleanStr(v,140)]))};
    sub.slug = await uniqueSlug(req.body.slug || name, sub._id);
    await sub.save();
    const offers = (Array.isArray(j.offers) ? j.offers : []).slice(0, 6);
    for (let i = 0; i < offers.length; i++) {
      const o = offers[i] || {};
      if (!cleanStr(o.title, 120)) continue;
      await Offer.create({ userId: sub._id, title: cleanStr(o.title, 120), price: Math.max(0, Number(o.price) || 0), description: cleanStr(o.description, 400), order: i });
    }
    res.json({ site: { id: String(sub._id), slug: sub.slug, siteName: sub.siteName, siteUrl: `${PUBLIC_BASE}/site/${sub.slug}` }, token: signToken(sub), user: publicUser(sub) });
  } catch (e) {
    console.error('AI generate error', e.response ? JSON.stringify(e.response.data) : e.message);
    if (e.response) {
      const status = e.response.status;
      if (status === 401 || status === 403) return res.status(502).json({ message: 'AI provider rejected the API key. Check OPENROUTER_API_KEY on Render.' });
      if (status === 402) return res.status(502).json({ message: 'AI provider account has insufficient credits. Check OpenRouter billing.' });
      if (status === 429) return res.status(503).json({ message: 'AI provider rate limit reached. Please try again later.' });
      return res.status(502).json({ message: 'AI provider returned HTTP ' + status + '. Check OPENROUTER_MODEL and Render logs.' });
    }
    if (e.code === 'ECONNABORTED') return res.status(504).json({ message: 'AI provider timed out. Please retry.' });
    if (e.code === 'ENOTFOUND' || e.code === 'ECONNRESET') return res.status(503).json({ message: 'Could not reach AI provider. Check connectivity and retry.' });
    res.status(500).json({ message: 'Could not finish website generation. Check the Render server logs for the cause.' });
  }
});

// ---------- Stripe checkout ----------
app.post('/api/stripe/create-checkout', authenticateToken, async (req, res) => {
  try {
    let user = await User.findById(req.user.id);
    if (user && user.ownerId) user = await User.findById(user.ownerId);
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

const PAGE_ROUTES = ['/business', '/analytics', '/settings', '/', '/how-it-works', '/features', '/professions', '/pricing', '/about', '/contact', '/build', '/dashboard', '/messages', '/reviews', '/privacy', '/terms', '/reset', '/studio', '/customers', '/calendar', '/orders', '/system', '/releases', '/ai-sites'];
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
app.get('/manifest.webmanifest',(req,res)=>res.type('application/manifest+json').json({name:'GoldOffer Studio',short_name:'GoldOffer',start_url:'/',scope:'/',display:'standalone',background_color:'#05070b',theme_color:'#ffcf00',icons:[{src:'/favicon.svg',sizes:'any',type:'image/svg+xml',purpose:'any'}]}));
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