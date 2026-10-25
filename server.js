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
  buttonStyle: { type: String, default: 'pill' },
  cardStyle: { type: String, default: 'glass' },
  navStyle: { type: String, default: 'outline' },
  heroStyle: { type: String, default: 'cinematic' },
  spacingStyle: { type: String, default: 'balanced' },

  heroHeadline: {type:String,default:''},
  heroSubtitle: {type:String,default:''},
  primaryCta: {type:String,default:''},
  offersHeading: {type:String,default:''},
  storyHeading: {type:String,default:''},
  catalogStyle: {type:String,enum:['grid2','grid3','list'],default:'grid2'},
  backdropStyle: {type:String,enum:['default','mesh','clean','grid'],default:'default'},
  motionStyle: {type:String,enum:['full','subtle','none'],default:'full'},
  sectionOrder: {type:[String],default:['story','discover','highlights','offers','booking','faq','about']},
  hiddenSections: {type:[String],default:[]},

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
  faqItems:{type:[{question:String,answer:String,_id:false}],default:[]},
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
  offerId: {type:mongoose.Schema.Types.ObjectId,ref:'Offer'},
  customerName: String,
  customerContact: String,
  contacts: [{ type: { type: String }, value: String, _id: false }],
  note: String,
  amount: Number,
  status: { type: String, default: 'Pending' }, // Pending, Completed, Cancelled
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
    storyHeading:'Pixel energy, scoreboard structure and retro-console attitude.',discoverTitle:'Jump into the drops',
    discoverText:'A punchier, block-based storefront inspired by arcades, tournament boards and gaming rooms.',
    tilesText:'Cards feel more like level select panels, with bold separation and a sharper UI.',
    profileText:'Meet the seller in a page that feels closer to a gaming setup than a classic shop.',
    fallback:[
      'https://images.unsplash.com/photo-1511512578047-dfb367046420?auto=format&fit=crop&w=1400&q=80',
      'https://images.unsplash.com/photo-1542751371-adc38448a05e?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1593305841991-05c297ba4575?auto=format&fit=crop&w=1200&q=80',
      'https://images.unsplash.com/photo-1550745165-9bc0b252726f?auto=format&fit=crop&w=1200&q=80'
    ]
  },
  aurora: {
    name:'Aurora', eyebrow:'Fresh perspectives',
    storyHeading:'Soft gradients, glass panels and a calmer premium atmosphere.',discoverTitle:'A more fluid presentation',
    discoverText:'A luminous, airy site for creators and services that want elegance without looking generic.',
    tilesText:'Floating panels, softer motion and a more immersive story-led rhythm.',
    profileText:'The seller profile feels refined, open and more editorial than commercial.',
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
    storyHeading: 'Cyberpunk contrast, asymmetry and a more high-tech personality.',
    discoverTitle: 'Enter the signal',
    discoverText: 'Ideal for tech, gaming and digital brands that want a more futuristic split-screen identity.',
    tilesText: 'Offset panels, glowing actions and a bolder high-tech interface across the whole public link.',
    profileText: 'The seller profile feels like a futuristic creator hub, not just a standard store page.',
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
const safePick = (value, allowed, fallback) => allowed.includes(value) ? value : fallback;
const safeButtonStyle = (v) => safePick(v, ['pill','sharp','glow','soft'], 'pill');
const safeCardStyle = (v) => safePick(v, ['glass','soft','outline','solid'], 'glass');
const safeNavStyle = (v) => safePick(v, ['outline','floating','minimal','glass'], 'outline');
const safeHeroStyle = (v) => safePick(v, ['cinematic','split','compact','immersive'], 'cinematic');
const safeSpacingStyle = (v) => safePick(v, ['compact','balanced','airy'], 'balanced');
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
  category: u.category, city: u.city, theme: u.theme, layout: u.layout || 'signature', font: u.font, buttonStyle: u.buttonStyle || 'pill', cardStyle: u.cardStyle || 'glass', navStyle: u.navStyle || 'outline', heroStyle: u.heroStyle || 'cinematic', spacingStyle: u.spacingStyle || 'balanced', heroHeadline:u.heroHeadline||'', heroSubtitle:u.heroSubtitle||'', primaryCta:u.primaryCta||'', offersHeading:u.offersHeading||'', storyHeading:u.storyHeading||'', catalogStyle:u.catalogStyle||'grid2', backdropStyle:u.backdropStyle||'default', motionStyle:u.motionStyle||'full', sectionOrder:u.sectionOrder||[], hiddenSections:u.hiddenSections||[], published: u.published,
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
    const allowedButtonStyle = ['pill','sharp','glow','soft'];
    const allowedCardStyle = ['glass','soft','outline','solid'];
    const allowedNavStyle = ['outline','floating','minimal','glass'];
    const allowedHeroStyle = ['cinematic','split','compact','immersive'];
    const allowedSpacingStyle = ['compact','balanced','airy'];
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
    if (b.notifyEmail !== undefined) user.notifyEmail = isEmail(b.notifyEmail) ? String(b.notifyEmail).trim() : '';
    if (typeof b.notifyOn === 'boolean') user.notifyOn = b.notifyOn;
    if (Object.keys(THEMES).includes(theme)) user.theme = theme;
    if (['signature','editorial','market','neon','mono','atelier','arcade','aurora'].includes(b.layout)) user.layout = b.layout;
    if (Object.keys(FONTS).includes(font)) user.font = font;
    if (allowedButtonStyle.includes(b.buttonStyle)) user.buttonStyle = b.buttonStyle;
    if (allowedCardStyle.includes(b.cardStyle)) user.cardStyle = b.cardStyle;
    if (allowedNavStyle.includes(b.navStyle)) user.navStyle = b.navStyle;
    if (allowedHeroStyle.includes(b.heroStyle)) user.heroStyle = b.heroStyle;
    if (allowedSpacingStyle.includes(b.spacingStyle)) user.spacingStyle = b.spacingStyle;

    for (const key of ['heroHeadline','heroSubtitle','primaryCta','offersHeading','storyHeading']) {
      if (typeof b[key] === 'string') user[key] = b[key].trim().slice(0,key==='heroSubtitle'?240:100);
    }
    if (['grid2','grid3','list'].includes(b.catalogStyle)) user.catalogStyle=b.catalogStyle;
    if (['default','mesh','clean','grid'].includes(b.backdropStyle)) user.backdropStyle=b.backdropStyle;
    if (['full','subtle','none'].includes(b.motionStyle)) user.motionStyle=b.motionStyle;
    const sectionKeys=['story','discover','highlights','offers','booking','faq','about'];
    if(Array.isArray(b.sectionOrder)) {
      const proposed=b.sectionOrder.filter(x=>typeof x==='string'&&sectionKeys.includes(x));
      user.sectionOrder=[...new Set([...proposed,...sectionKeys])];
    }
    if(Array.isArray(b.hiddenSections)) user.hiddenSections=[...new Set(b.hiddenSections.filter(x=>typeof x==='string'&&sectionKeys.includes(x)&&x!=='offers'))];

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
  try {
    const old = await Order.findOne({_id:req.params.id,userId:req.user.id});
    if(!old)return res.status(404).json({message:'Order not found'});
    if(old.status===status)return res.json({order:old});
    // Only a completed, offer-linked order consumes one item. Do not decrement on a request.
    if(status==='Completed'&&old.status!=='Completed'&&old.offerId){
      const key='stock.'+String(old.offerId);
      const setting=await ShopSetting.findOne({sellerId:req.user.id}).lean();
      if(setting&&setting.stock&&setting.stock[key.slice(6)]!==undefined){
        const reserved=await ShopSetting.findOneAndUpdate({sellerId:req.user.id,[key]:{$gt:0}},{$inc:{[key]:-1}});
        if(!reserved)return res.status(409).json({message:'Not enough stock to complete this order.'});
      }
    }
    // Completed order cannot be silently reversed in stock accounting.
    if(old.status==='Completed'&&status!=='Completed'&&old.offerId){
      const key='stock.'+String(old.offerId);
      await ShopSetting.updateOne({sellerId:req.user.id,[key]:{$exists:true}},{$inc:{[key]:1}});
    }
    old.status=status;await old.save();res.json({order:old});
  }catch(e){res.status(500).json({message:'Could not change order status'})}
});

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
 startsAt:{type:Date,required:true},note:{type:String,maxlength:500},
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
app.post('/api/business/appointments',authenticateToken,async(req,res)=>{
 try{const b=req.body||{};const d=new Date(b.startsAt);if(!Number.isFinite(d.valueOf())||d<Date.now()-86400000||d>Date.now()+366*86400000)return res.status(400).json({message:'Invalid appointment date'});
 const row=await Appointment.create({sellerId:req.user.id,startsAt:d,customer:String(b.customer||'').trim().slice(0,80)||'Manual booking',contact:String(b.contact||'').slice(0,140)||'Created by owner',note:String(b.note||'').slice(0,500)});res.status(201).json({appointment:row})}catch(e){res.status(500).json({message:'Could not save booking'})}
});
app.post('/site/:slug/appointment',publicLimiter,rejectOwnerSelfAction,async(req,res)=>{
 try{const owner=await User.findOne({slug:req.params.slug,published:true}).select('_id siteName email notifyEmail');if(!owner)return res.sendStatus(404);
 const b=req.body||{};if(b.consent!=='1')return res.status(400).send('Please accept the privacy notice.');const d=new Date(b.startsAt);const customer=String(b.customer||'').trim().slice(0,80),contact=String(b.contact||'').trim().slice(0,140);
 if(!customer||contact.length<5||!Number.isFinite(d.valueOf())||d<Date.now()+3600000||d>Date.now()+180*86400000)return res.status(400).send('Check the date and contact details.');
 if(await Appointment.exists({sellerId:owner._id,startsAt:d,status:{$in:['Pending','Confirmed']}}))return res.status(409).send('This slot has already been requested. Please pick another time.');
 const setting=await ShopSetting.findOne({sellerId:owner._id}).lean();if(!setting?.slotsEnabled)return res.status(403).send('Booking is not enabled for this business.');
 if(mongoose.isValidObjectId(b.offerId)){if(!await Offer.exists({_id:b.offerId,userId:owner._id}))return res.sendStatus(404)}
 await Appointment.create({sellerId:owner._id,offerId:mongoose.isValidObjectId(b.offerId)?b.offerId:undefined,startsAt:d,customer,contact,note:String(b.note||'').slice(0,500)});
 if(owner.email)void sendMail({to:owner.notifyEmail||owner.email,subject:'New booking request',text:`${customer} requested ${d.toISOString()}. Contact: ${contact}`});
 res.redirect(303,`/site/${encodeURIComponent(req.params.slug)}?booking=1`);
 }catch(e){if(e.code===11000)return res.status(409).send('This slot is already taken. Please choose another time.');res.status(500).send('Booking could not be saved')}
});
app.patch('/api/business/appointments/:id',authenticateToken,async(req,res)=>{
 if(!mongoose.isValidObjectId(req.params.id)||!['Pending','Confirmed','Cancelled','Completed'].includes(req.body?.status))return res.sendStatus(400);
 try{const row=await Appointment.findOneAndUpdate({_id:req.params.id,sellerId:req.user.id},{$set:{status:req.body.status}},{new:true});return row?res.json({appointment:row}):res.sendStatus(404);}catch(e){if(e.code===11000)return res.status(409).json({message:'The requested time is no longer available.'});return res.sendStatus(500)}
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
`;
}


function customizationCss() {
  return `.btn-pill .btn,.btn-pill .abtn,.btn-pill .sp-btn,.btn-pill .bar nav a,.btn-pill .cta{border-radius:999px}
.btn-sharp .btn,.btn-sharp .abtn,.btn-sharp .sp-btn,.btn-sharp .bar nav a,.btn-sharp .cta{border-radius:10px}
.btn-soft .btn,.btn-soft .abtn,.btn-soft .sp-btn,.btn-soft .bar nav a,.btn-soft .cta{border-radius:18px;box-shadow:none}
.btn-glow .btn,.btn-glow .abtn.pri,.btn-glow .sp-btn.sp-primary,.btn-glow .cta{box-shadow:0 0 0 1px color-mix(in srgb,var(--a) 28%,transparent),0 0 26px color-mix(in srgb,var(--a) 28%,transparent),0 12px 36px rgba(0,0,0,.25)}
.card-soft .card,.card-soft .glass,.card-soft .sp-hero,.card-soft .sp-about,.card-soft .sp-review-summary,.card-soft .sp-review-list,.card-soft .detail .main,.card-soft .detail .req,.card-soft .detail .seller,.card-soft .feature-card{border-radius:28px!important}
.card-outline .card,.card-outline .glass,.card-outline .sp-hero,.card-outline .sp-about,.card-outline .sp-review-summary,.card-outline .sp-review-list,.card-outline .detail .main,.card-outline .detail .req,.card-outline .detail .seller,.card-outline .feature-card{background:transparent!important;box-shadow:none!important;border-style:dashed!important}
.card-solid .card,.card-solid .glass,.card-solid .sp-hero,.card-solid .sp-about,.card-solid .sp-review-summary,.card-solid .sp-review-list,.card-solid .detail .main,.card-solid .detail .req,.card-solid .detail .seller,.card-solid .feature-card{background:rgba(255,255,255,.06)!important;box-shadow:0 18px 46px rgba(0,0,0,.28)!important}
.nav-floating .bar{top:14px;left:14px;right:14px;border:1px solid rgba(255,255,255,.1);border-radius:24px}
.nav-floating .bar nav a{background:rgba(255,255,255,.04)}
.nav-minimal .bar{background:rgba(5,7,11,.38);border-bottom-color:transparent}
.nav-minimal .bar nav a{border-color:transparent;background:transparent;padding-inline:10px}
.nav-glass .bar{background:rgba(255,255,255,.06);box-shadow:0 10px 40px rgba(0,0,0,.22)}
.hero-split .cine-wrap{grid-template-columns:1.06fr .94fr;gap:44px;align-items:center}.hero-split .cine-copy{text-align:left;margin:0}.hero-split .cine-copy h1{max-width:11ch}.hero-split .cine-sub,.hero-split .cine-meta,.hero-split .actions{justify-content:flex-start}.hero-split .cine-visual{min-height:520px}
.hero-compact .cine-hero{padding-top:94px;padding-bottom:46px}.hero-compact .cine-copy h1{font-size:clamp(2.6rem,7vw,4.8rem)}.hero-compact .cine-sub{max-width:54ch}.hero-compact .cine-visual{min-height:360px}
.hero-immersive .cine-hero{padding-top:130px;padding-bottom:110px}.hero-immersive .cine-copy h1{font-size:clamp(3.6rem,9vw,7.6rem)}.hero-immersive .cine-visual{min-height:620px;transform:scale(1.04)}.hero-immersive .main-screen{box-shadow:0 30px 90px rgba(0,0,0,.36)}
.space-compact .wrap,.space-compact .story-shell,.space-compact main.wrap.top,.space-compact .sp-section{padding-top:44px;padding-bottom:44px}.space-compact .grid,.space-compact .feature-grid{gap:18px}.space-compact .story-canvas{padding:18px}.space-compact .card{padding:12px}
.space-airy .wrap,.space-airy .story-shell,.space-airy main.wrap.top,.space-airy .sp-section{padding-top:86px;padding-bottom:86px}.space-airy .grid,.space-airy .feature-grid{gap:34px}.space-airy .story-canvas{padding:36px}.space-airy .card{padding:20px}
.catalog-grid3 #goOfferGrid{grid-template-columns:repeat(3,minmax(0,1fr))}
.catalog-list #goOfferGrid{display:grid;grid-template-columns:1fr;max-width:100%}
.catalog-list #goOfferGrid .card{display:grid;grid-template-columns:minmax(180px,34%) minmax(0,1fr);min-height:200px}
.catalog-list #goOfferGrid .card .pic{height:100%;min-height:200px}
.catalog-list #goOfferGrid .card .in{padding:22px 28px}
.backdrop-mesh{background:radial-gradient(70vw 50vw at 5% 20%,color-mix(in srgb,var(--a) 8%,transparent),transparent),radial-gradient(60vw 70vw at 90% 70%,color-mix(in srgb,var(--b) 7%,transparent),transparent),var(--bg)}
.backdrop-clean{background:var(--bg)}.backdrop-clean .cine-noise{display:none}
.backdrop-grid{background-image:linear-gradient(color-mix(in srgb,var(--a) 6%,transparent) 1px,transparent 1px),linear-gradient(90deg,color-mix(in srgb,var(--a) 6%,transparent) 1px,transparent 1px);background-size:50px 50px;background-color:var(--bg)}
.motion-none *, .motion-none *::before,.motion-none *::after{animation:none!important;transition:none!important;scroll-behavior:auto!important}
.motion-none [data-story-canvas],.motion-none [data-cine-stack]{transform:none!important}
.motion-subtle .rv{transition-duration:.2s!important}.motion-subtle [data-story-canvas]{transform:none!important}
@media(max-width:900px){.catalog-grid3 #goOfferGrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:650px){.catalog-grid3 #goOfferGrid,.catalog-list #goOfferGrid{grid-template-columns:1fr}.catalog-list #goOfferGrid .card{grid-template-columns:1fr}.catalog-list #goOfferGrid .card .pic{height:210px}}
@media(max-width:900px){.hero-split .cine-wrap{grid-template-columns:1fr}.hero-split .cine-copy{text-align:center}.hero-split .cine-copy h1{max-width:none}.hero-split .cine-sub,.hero-split .cine-meta,.hero-split .actions{justify-content:center}.nav-floating .bar{top:8px;left:8px;right:8px}}
`;
}

function pageShell(user, { title, desc, body, cls }) {
  const t = THEMES[user.theme] || THEMES.gold;
  const f = FONTS[user.font] || FONTS.sans;
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${esc(title)}</title>
<meta name="description" content="${esc(desc)}">
<meta name="theme-color" content="#05070b">
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=${f.gf}&display=swap" rel="stylesheet">
<style>${siteCss(t, f)}</style><style>${layoutGlobalCss(safeLayout(user.layout))}</style><style>${customizationCss()}</style></head><body class="${cls || ''} layout-${esc(safeLayout(user.layout))} btn-${esc(safeButtonStyle(user.buttonStyle))} card-${esc(safeCardStyle(user.cardStyle))} nav-${esc(safeNavStyle(user.navStyle))} hero-${esc(safeHeroStyle(user.heroStyle))} space-${esc(safeSpacingStyle(user.spacingStyle))} catalog-${esc(safePick(user.catalogStyle,['grid2','grid3','list'],'grid2'))} backdrop-${esc(safePick(user.backdropStyle,['default','mesh','clean','grid'],'default'))} motion-${esc(safePick(user.motionStyle,['full','subtle','none'],'full'))}" data-slug="${esc(user.slug)}" data-seller="${esc(sellerName(user))}">
${user.announcementText ? `<aside class="go-public-announcement">${esc(user.announcementText)}</aside><style>.go-public-announcement{position:relative;z-index:2;margin:70px auto -60px;width:min(100% - 36px,1180px);padding:12px 20px;border-radius:12px;background:color-mix(in srgb,var(--a) 13%,var(--panel));border:1px solid color-mix(in srgb,var(--a) 30%,transparent);color:inherit;text-align:center;font-size:14px}</style>` : ''}
${body}
<script>(function(){try{var p=location.pathname.split('/');if(p[1]==='site'&&p[2]){fetch('/api/storefront/'+encodeURIComponent(p[2])+'/track',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind:p[3]==='offer'?'offer':'view',offerId:p[3]==='offer'?p[4]:undefined}),keepalive:true}).catch(function(){})}}catch(e){}})()</script>
<script>(function(){var form=document.querySelector('#book form');if(form)form.addEventListener('submit',function(){var x=form.querySelector('[name="startsAt"]');if(x){var d=new Date(x.value);if(Number.isFinite(d.getTime())){x.type='hidden';x.value=d.toISOString()}}})})();</script>
<script>${SITE_JS}</script>
<script>(function(){
  var slug = document.body.getAttribute('data-slug');
  var token = null;
  try { token = localStorage.getItem('token'); } catch(e) {}
  if (!slug || !token) return;
  fetch('/api/auth/me', {headers:{Authorization:'Bearer '+token},cache:'no-store'})
    .then(function(r){return r.ok?r.json():null;})
    .then(function(d){
      if (!d || !d.user || d.user.slug!==slug) return;
      document.body.classList.add('go-site-owner');
      var prefix='/site/'+encodeURIComponent(slug);
      document.querySelectorAll('a[href^="'+prefix+'/messages"]').forEach(function(a){a.setAttribute('title','Open your business inbox here');a.setAttribute('aria-label','Business inbox');if(a.textContent.trim())a.textContent='Business inbox';});
      document.querySelectorAll('a[href^="'+prefix+'/offer/"]').forEach(function(a){a.setAttribute('data-owner-offer','true');});
      document.querySelectorAll('form[action="'+prefix+'/order"]').forEach(function(f){
        f.addEventListener('submit',function(e){e.preventDefault();window.location.assign('/dashboard');});
        f.style.display='none';
        var wrap=f.closest('.req');if(wrap){var h=wrap.querySelector('h2');if(h)h.textContent='Your own offer';var note=document.createElement('p');note.textContent='You are viewing your own website. Customers can send requests here; manage them in your Dashboard.';note.style.cssText='color:var(--soft);margin:10px 0 18px;line-height:1.6';wrap.appendChild(note);var a=document.createElement('a');a.href='/dashboard';a.className='abtn pri';a.textContent='Open Dashboard';wrap.appendChild(a);}
      });
      var note=document.createElement('div');note.className='go-owner-banner';note.setAttribute('role','status');note.innerHTML='<span>Owner preview — you are viewing your own website.</span><a href="'+prefix+'/messages">Business inbox</a><a href="/dashboard">Dashboard</a>';
      document.body.appendChild(note);
      if(location.pathname===prefix+'/messages'){
        note.style.display='none';
        document.body.classList.add('go-owner-messages-page');
        var topBar=document.createElement('div');
        topBar.className='go-owner-topbar';
        topBar.innerHTML='<div><strong>Business inbox</strong><span>Answer customers directly without leaving your public link.</span></div><div class="go-owner-links"><a href="/messages" target="_blank" rel="noopener">Open full inbox</a><a href="/dashboard">Dashboard</a></div>';
        var wrap=document.querySelector('.mwrap');
        if(wrap){
          var host=document.createElement('section');
          host.className='go-owner-landing go-owner-landing--messages';
          host.innerHTML='<iframe title="Your business messages" src="/messages?embedded=1" loading="eager" allow="microphone"></iframe>';
          wrap.parentNode.insertBefore(topBar, wrap);
          wrap.parentNode.insertBefore(host, wrap);
          wrap.remove();
        }
      }
    }).catch(function(){});
})();</script>
<style>.go-owner-banner{position:fixed;z-index:80;left:12px;right:12px;bottom:12px;display:flex;align-items:center;justify-content:center;flex-wrap:wrap;gap:12px;padding:11px 16px;border-radius:13px;background:rgba(15,21,32,.96);border:1px solid rgba(255,255,255,.15);color:#ecf0f7;box-shadow:0 16px 40px #0008;font:600 13px system-ui}.go-owner-banner a{color:var(--a);text-decoration:none}.go-owner-topbar{width:min(100% - 36px,1240px);margin:108px auto 18px;padding:18px 22px;display:flex;align-items:center;justify-content:space-between;gap:14px;border-radius:20px;background:linear-gradient(135deg,rgba(255,255,255,.06),rgba(255,255,255,.02));border:1px solid var(--line);box-shadow:0 18px 50px rgba(0,0,0,.22)}.go-owner-topbar strong{display:block;font-size:1.05rem}.go-owner-topbar span{display:block;color:var(--soft);font-size:.92rem;margin-top:4px}.go-owner-links{display:flex;gap:10px;flex-wrap:wrap}.go-owner-links a{display:inline-flex;align-items:center;justify-content:center;min-height:44px;padding:0 16px;border-radius:999px;border:1px solid var(--line);text-decoration:none;color:#fff;background:rgba(255,255,255,.03)}.go-owner-links a:first-child{background:linear-gradient(135deg,var(--a),var(--b));color:var(--on);border-color:transparent;font-weight:800}.go-owner-landing{max-width:1200px;min-height:50vh;margin:0 auto 45px;padding:0 18px 34px;text-align:left}.go-owner-landing--messages iframe{display:block;width:100%;height:calc(100vh - 240px);min-height:680px;border:1px solid var(--line);border-radius:24px;background:#080c13;box-shadow:0 24px 80px rgba(0,0,0,.28)}.go-owner-messages-page footer{display:none}@media(max-width:760px){.go-owner-topbar{margin-top:90px;padding:16px;align-items:flex-start;flex-direction:column}.go-owner-links{width:100%}.go-owner-links a{flex:1}.go-owner-landing--messages iframe{height:calc(100vh - 250px);min-height:560px}.go-owner-banner{font-size:11px;gap:8px;padding:10px}}</style>
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
  return pageShell(user,{title:`${sellerName(user)} — Seller profile`,desc:`View offers and visitor feedback for ${sellerName(user)}`,body,cls:'sellerprofile'});
}

function renderSite(user, offers, sent) {
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
      <h1>${esc(user.heroHeadline || user.siteName)}</h1>
      <p class="cine-sub">${esc(user.heroSubtitle || story)}</p>
      <div class="cine-meta">${sub ? `<span>${sub}</span>` : ''}${hours ? `<span>${esc(hours)}</span>` : ''}<span>${offers.length} offers live</span></div>
      <div class="actions">
        <a class="abtn pri" href="/site/${esc(user.slug)}/messages">${MSG_SVG}${esc(user.primaryCta || 'Message us')}</a>
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

<section data-go-section="story" class="story-shell" data-story-shell>
  <div class="story-stick">
    <div class="story-canvas" data-story-canvas>
      <div class="story-media">${renderMedia(heroMediaB, secondOffer ? secondOffer.title : user.siteName, 'story-main')}</div>
      <div class="story-panel">
        <span class="cine-eyebrow">THE STORY BEHIND THE BUSINESS</span>
        <h2>${esc(user.storyHeading || layout.storyHeading || (user.siteName + ' — made to stand out.'))}</h2>
        <p>${esc(story)}</p>
        <div class="story-stats"><div><b>${offers.length}</b><span>Offers</span></div><div><b>${esc(user.city || 'Global')}</b><span>Location</span></div><div><b>${phoneRaw ? 'Telephone' : 'Message'}</b><span>Contact</span></div></div>
      </div>
    </div>
  </div>
</section>

<section data-go-section="discover" class="reveal-band wrap">
  <div class="sec-head"><h2>${esc(layout.discoverTitle || ('Discover ' + user.siteName))}</h2><span>${esc(layout.discoverText || 'A closer look at what we offer.')}</span></div>
  <div class="copylines">
    <p class="copyline">${esc(story)}</p>
    <p class="copyline">${esc(user.categoryLabel || user.category || 'Explore the collection')} ${user.city ? 'in ' + esc(user.city) : 'for you'}.</p>
    <p class="copyline">Explore our work, and get in touch when you find something you like.</p>
  </div>
</section>

<section data-go-section="highlights" class="cine-feature wrap">
  <div class="feature-grid">
    <div class="feature-card dark rv"><span class="cine-eyebrow">DISCOVER</span><h3>${esc(layout.discoverTitle || 'Discover our latest offers')}</h3><p>${esc(layout.tilesText || 'Find something that suits you. Explore the collection, ask questions and connect directly.')}</p></div>
    <div class="feature-card media rv">${heroTiles ? `<div class="pics three">${heroTiles}</div>` : `<div class="feature-fallback">Publish offers to see your visual layout here.</div>`}</div>
    <div class="feature-card light rv"><span class="cine-eyebrow">SELLER PROFILE</span><h3>Meet ${esc(seller)}</h3><p>${esc(layout.profileText || 'Learn about the person behind this site, read feedback and get in touch directly.')}</p><a class="feature-link" href="/site/${esc(user.slug)}/profile">View seller profile →</a></div>
  </div>
</section>

<main data-go-section="offers" class="wrap top" id="offers">
  <div class="sec-head"><h2>${esc(user.offersHeading || 'Offers')}</h2><span>${offers.length} available · <a href="/site/${esc(user.slug)}/profile#reviews" style="color:inherit;text-decoration:underline">Seller reviews</a></span></div>
  <div class="go-shop-search"><input id="goOfferSearch" type="search" autocomplete="off" aria-label="Search offers" placeholder="Search offers by name or description..."><span id="goFound">${offers.length} offers</span></div>
  ${sent ? '<div class="ok">Thank you. Your request was sent and the business will contact you.</div>' : ''}
  <div class="grid" id="goOfferGrid">${cards}</div><p id="goNoResults" style="display:none;padding:28px 0;color:#707781">No matching offers.</p>
</main>

<section data-go-section="seller-link" class="wrap" style="padding-top:42px"><a href="/site/${esc(user.slug)}/profile" style="display:flex;gap:15px;align-items:center;border:1px solid #364151;border-radius:18px;background:#161c25;padding:18px 20px;text-decoration:none"><span class="seller-pill" style="display:grid;place-items:center;width:52px;height:52px;color:inherit;font-size:18px;font-weight:800">${esc(initials(sellerName(user)))}</span><span style="flex:1;min-width:0"><b style="display:block;color:#fff">Meet ${esc(sellerName(user))}</b><small style="color:#b1bdcc">Seller profile · Offers · Reviews</small></span><strong style="color:#ffcb31">View profile →</strong></a></section>
${user.bookingEnabled ? `<section data-go-section="booking" class="wrap" style="padding-top:35px" id="book"><div class="sec-head"><h2>Request an appointment</h2><span>Available when the business enables appointments.</span></div><form class="glass" method="POST" action="/site/${esc(user.slug)}/appointment" style="display:grid;gap:12px;max-width:620px"><input name="customer" placeholder="Your name" required maxlength="80"><input name="contact" placeholder="Your contact details" required maxlength="140"><label style="font-size:13px">Preferred date and time</label><input type="datetime-local" name="startsAt" required><textarea name="note" rows="2" placeholder="What do you need? (optional)" maxlength="500"></textarea><label style="font-size:12px;display:flex;gap:9px;align-items:start"><input type="checkbox" name="consent" value="1" required style="width:auto;margin:3px 0"><span>I agree to be contacted about this booking. <a href="${PUBLIC_BASE}/privacy">Privacy Policy</a></span></label><button class="btn" type="submit">Send booking request</button></form>${sent ? '' : ''}</section>
` : ''}${user.faqItems && user.faqItems.length ? `<section data-go-section="faq" class="wrap go-faq" id="faq"><div class="sec-head"><h2>Frequently asked questions</h2></div><div style="display:grid;gap:12px">${user.faqItems.map(x=>`<details class="glass" style="padding:18px 22px"><summary style="cursor:pointer;font-weight:700">${esc(x.question)}</summary><p style="padding-top:10px;color:var(--soft)">${esc(x.answer)}</p></details>`).join('')}</div></section>` : ''}
<section data-go-section="about" class="wrap findus" id="about" style="padding-top:60px"><div class="sec-head"><h2>Find us</h2></div>${aboutBlock(user)}</section>
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
.layout-neon .bar nav a,.layout-neon .abtn,.layout-neon .btn{border-radius:14px;box-shadow:0 0 0 1px rgba(68,246,255,.18),0 0 22px rgba(68,246,255,.08)}
.layout-neon .cine-hero{background:radial-gradient(900px circle at 80% 20%,rgba(68,246,255,.14),transparent 30%),radial-gradient(900px circle at 18% 12%,rgba(155,77,255,.12),transparent 30%),linear-gradient(180deg,#03040a,#050712)}
.layout-neon .cine-wrap{grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr);align-items:end;gap:44px}.layout-neon .cine-copy{padding-bottom:32px}.layout-neon .cine-copy h1{text-shadow:0 0 20px rgba(68,246,255,.08);max-width:10ch}
.layout-neon .stack-outline{border-color:rgba(86,95,255,.35);border-radius:20px}.layout-neon .screen-caption{background:rgba(6,8,17,.82);border-color:rgba(68,246,255,.22)}
.layout-neon .story-canvas{background:linear-gradient(130deg,#0a1120,#090b16)}.layout-neon .story-media{order:2;min-height:420px}.layout-neon .story-panel{order:1}.layout-neon .copyline.on{color:#d9f9ff}.layout-neon .feature-grid{grid-template-columns:1.35fr .65fr}.layout-neon .feature-card.media{grid-row:span 2}.layout-neon .feature-card.light{align-self:end}.layout-neon .grid{grid-template-columns:repeat(3,minmax(0,1fr))}
.layout-arcade .bar nav a,.layout-arcade .abtn,.layout-arcade .btn{border-radius:7px;text-transform:uppercase;letter-spacing:.04em;font-family:'JetBrains Mono',monospace}
.layout-arcade .cine-hero{background:linear-gradient(145deg,#080910,#10131d)}
.layout-arcade .cine-wrap{grid-template-columns:1fr 1fr;gap:26px}.layout-arcade .cine-copy h1{max-width:none}.layout-arcade .offer-pills{gap:8px}.layout-arcade .offer-pills a{border-radius:8px;background:#111426}
.layout-arcade .story-canvas{grid-template-columns:.74fr 1.26fr;background:#12131f;border:1px solid rgba(219,255,54,.18)}.layout-arcade .story-media{order:2}.layout-arcade .story-panel{order:1}
.layout-arcade .feature-grid{grid-template-columns:.9fr 1.1fr 1fr}.layout-arcade .feature-card.media{grid-column:2/span 2}.layout-arcade .feature-card.dark{min-height:180px}.layout-arcade .feature-card.light{background:#dbff36;color:#131313}.layout-arcade .grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.layout-arcade .card{box-shadow:10px 10px 0 rgba(219,255,54,.08)}
.layout-aurora .bar nav a,.layout-aurora .abtn,.layout-aurora .btn{border-radius:999px}
.layout-aurora .cine-hero{background:radial-gradient(ellipse at 80% 15%,rgba(120,225,208,.22),transparent 42%),radial-gradient(ellipse at 16% 60%,rgba(181,172,255,.16),transparent 40%),#101524}
.layout-aurora .cine-wrap{grid-template-columns:1fr;gap:28px}.layout-aurora .cine-copy{text-align:center;max-width:900px;margin:auto}.layout-aurora .cine-copy h1{max-width:none;font-size:clamp(3.4rem,8vw,7rem)}
.layout-aurora .cine-sub{margin:auto}.layout-aurora .cine-meta,.layout-aurora .offer-pills,.layout-aurora .cine-copy .actions{justify-content:center}
.layout-aurora .cine-visual{width:min(100%,1020px);margin:auto;min-height:510px}.layout-aurora .main-screen{inset:18px 80px 40px;border-radius:38px}.layout-aurora .stack-outline{border-radius:44px}
.layout-aurora .story-canvas{background:#202844;border-radius:45px}.layout-aurora .feature-grid{grid-template-columns:1fr 1.6fr 1fr}.layout-aurora .feature-card{border-radius:36px}.layout-aurora .feature-card.media{transform:translateY(-24px)}.layout-aurora .feature-card.light{transform:translateY(18px)}
.layout-mono .cine-hero{background:linear-gradient(180deg,#07090c,#0a0d11)}.layout-mono .cine-wrap{grid-template-columns:minmax(0,.92fr) minmax(380px,1.08fr)}
.layout-mono .cine-copy h1{max-width:13ch}.layout-mono .stack-outline{display:none}.layout-mono .main-screen{inset:14px;border-radius:16px}.layout-mono .float-card{border-radius:16px}
.layout-mono .story-canvas{grid-template-columns:1.1fr .9fr;background:#0d1015}.layout-mono .feature-grid{grid-template-columns:1fr 1fr 1fr}.layout-mono .feature-card{padding:24px;border-radius:18px}.layout-mono .feature-card.light{background:#101317}
@media(max-width:1080px){.layout-editorial .cine-wrap,.layout-editorial .story-canvas,.layout-editorial .feature-grid,.layout-market .feature-grid,.layout-neon .feature-grid,.layout-mono .feature-grid,.layout-mono .story-canvas,.layout-arcade .feature-grid,.layout-arcade .story-canvas{grid-template-columns:1fr}.layout-editorial .feature-card.light,.layout-market .feature-card.dark,.layout-neon .feature-card.media,.layout-arcade .feature-card.media{grid-column:auto;grid-row:auto}.layout-neon .grid,.layout-arcade .grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:720px){.layout-editorial .cine-hero{padding-top:90px}.layout-editorial .main-screen{inset:24px 10px}.layout-editorial .fc-a{left:0}.layout-market .main-screen{inset:34px 24px}.layout-market .stack-outline{inset:22px 18px}.layout-market .fc-a{left:2px}.layout-market .fc-b{right:2px}.layout-market .fc-c{right:30px}.layout-neon .cine-wrap,.layout-mono .cine-wrap,.layout-arcade .cine-wrap{grid-template-columns:1fr}.layout-neon .grid,.layout-arcade .grid{grid-template-columns:1fr}.layout-aurora .feature-card.media,.layout-aurora .feature-card.light{transform:none}}
@media(max-width:1080px){.cine-wrap,.story-canvas,.feature-grid{grid-template-columns:1fr}.cine-visual{min-height:430px}.feature-card{min-height:0}.story-shell{height:auto;padding:8px 0 0}.story-stick{position:relative;top:auto;height:auto}.story-canvas{width:min(100% - 32px,1220px)}.story-media{min-height:300px}.feature-grid{display:grid;gap:16px}.copylines{max-width:none}.copyline{max-width:30ch}}
@media(max-width:720px){.cine-hero{padding-top:92px}.cine-wrap{width:calc(100% - 24px);gap:24px}.cine-copy h1{font-size:clamp(2.7rem,16vw,4.2rem);max-width:12ch}.cine-sub{font-size:.98rem}.cine-visual{min-height:330px}.main-screen{inset:40px 14px 40px}.stack-outline{inset:26px 6px}.float-card{width:84px;height:84px;border-radius:20px}.fc-a{top:8px;left:2px}.fc-b{right:0;top:86px}.fc-c{right:36px;bottom:2px;width:74px;height:74px}.screen-caption{left:22px;right:22px;bottom:8px;padding:10px 12px;border-radius:14px}.story-canvas{width:calc(100% - 24px);border-radius:24px}.story-panel{padding:22px}.story-panel h2{font-size:1.85rem}.story-stats{grid-template-columns:1fr}.copyline{font-size:1.4rem;max-width:100%}.go-shop-search input{width:100%}.feature-card{padding:22px;border-radius:24px}}
</style>
<script>(function(){try{
  var order=${JSON.stringify((Array.isArray(user.sectionOrder)?user.sectionOrder:[]).filter(x=>['story','discover','highlights','offers','booking','faq','about'].includes(x)))};
  var hidden=${JSON.stringify((Array.isArray(user.hiddenSections)?user.hiddenSections:[]).filter(x=>['story','discover','highlights','booking','faq','about'].includes(x)))};
  var hero=document.querySelector('.cine-hero'),footer=document.querySelector('footer');
  if(hero&&footer){var holder=document.createElement('div');holder.id='go-custom-sections';footer.parentNode.insertBefore(holder,footer);
    var keys=['story','discover','highlights','offers','booking','faq','about'];
    var rest=keys.filter(function(k){return order.indexOf(k)<0});order=order.concat(rest);
    order.forEach(function(k){var el=document.querySelector('[data-go-section="'+k+'"]');if(el){if(hidden.indexOf(k)>=0)el.style.display="none";holder.appendChild(el)}});
    var sellerLink=document.querySelector('[data-go-section="seller-link"]');if(sellerLink)holder.appendChild(sellerLink);
  }
}catch(e){console.error('Storefront section layout:',e)}})();</script>
<script>(function(){var inp=document.getElementById('goOfferSearch'),grid=document.getElementById('goOfferGrid'),count=document.getElementById('goFound'),empty=document.getElementById('goNoResults');if(inp&&grid){var items=[].slice.call(grid.querySelectorAll('.card'));inp.addEventListener('input',function(){var q=inp.value.trim().toLocaleLowerCase(),n=0;items.forEach(function(el){var show=el.textContent.toLocaleLowerCase().includes(q);el.style.display=show?'':'none';if(show)n++;});count.textContent=n+' offers';empty.style.display=n?'none':'block';});}
var lines=[].slice.call(document.querySelectorAll('.copyline'));if(lines.length&&'IntersectionObserver' in window){var io=new IntersectionObserver(function(entries){entries.forEach(function(entry){if(entry.isIntersecting)entry.target.classList.add('on');})},{threshold:.45});lines.forEach(function(el){io.observe(el)})}else{lines.forEach(function(el){el.classList.add('on')})}
var shell=document.querySelector('[data-story-shell]'),canvas=document.querySelector('[data-story-canvas]');if(shell&&canvas&&window.matchMedia('(min-width: 801px)').matches&&!window.matchMedia('(prefers-reduced-motion: reduce)').matches){var ticking=false;var run=function(){ticking=false;var rect=shell.getBoundingClientRect(),vh=window.innerHeight||1,total=Math.max(1,shell.offsetHeight-vh),p=Math.min(1,Math.max(0,-rect.top/total));var scale=1-p*.12,shift=p*26;canvas.style.transform='translate3d(0,'+shift+'px,0) scale('+scale+')';canvas.style.borderRadius=(34+p*14)+'px';};addEventListener('scroll',function(){if(!ticking){ticking=true;requestAnimationFrame(run)}},{passive:true});run();}
var stack=document.querySelector('[data-cine-stack]');if(stack&&matchMedia('(pointer:fine)').matches&&!matchMedia('(prefers-reduced-motion: reduce)').matches){stack.addEventListener('pointermove',function(e){var r=stack.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;stack.style.transform='rotateY('+(x*7)+'deg) rotateX('+(-y*5)+'deg)'});stack.addEventListener('pointerleave',function(){stack.style.transform=''})}})()</script>`;
  return pageShell(user, { title: user.siteName, desc: `${user.siteName} - ${user.category || ''} in ${user.city || ''}`, body });
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
  </div>
</div>
<div style="margin-top:80px">${aboutBlock(user)}</div>
${more}
</main>
<div class="lb" id="lb"><img id="lbImg" alt=""></div>
<div class="stick"><b>${eur(offer.price)}</b><a class="alt" href="#request">Request</a><a href="/site/${esc(user.slug)}/messages?offer=${offer._id}">Message</a></div>
<footer><b>${esc(user.siteName)}</b><span>Built with <a href="${PUBLIC_BASE}" target="_blank" rel="noopener">GoldOffer Studio</a></span></footer>`;
  return pageShell(user, { title: `${offer.title} - ${user.siteName}`, desc: String(offer.description || offer.title).slice(0, 160), body, cls: 'offerpage' });
}

function renderFavoritesPage(user) {
  const body = `<div class="prog" id="prog"></div>${siteBar(user, 'fav')}
<main class="wrap">
<a class="crumb" href="/site/${esc(user.slug)}#offers">&larr; Back to all offers</a>
<h2>Your favorites</h2><p class="sub">Offers you saved with the heart. They are kept in this browser only, so no account is needed.</p>
<div class="grid" id="favList"><p class="none">Loading...</p></div>
</main>
<footer><b>${esc(user.siteName)}</b>${[user.category, user.city].filter(Boolean).map(esc).join(' &middot; ')}<div style="margin-top:18px">Built with GoldOffer Studio</div></footer>`;
  return pageShell(user, { title: `Favorites - ${user.siteName}`, desc: `Offers you saved at ${user.siteName}`, body });
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
  return pageShell(user, { title: `Messages - ${user.siteName}`, desc: `Your conversations with ${user.siteName}`, body, cls: 'mpage' });
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

app.get('/site/:slug', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    const offers = await Offer.find({ userId: user._id }).sort({ createdAt: -1 });
    res.setHeader('Content-Security-Policy', SITE_CSP); res.setHeader('Cache-Control', 'no-store, max-age=0');
    const inv=await ShopSetting.findOne({sellerId:user._id}).select('stock').lean();user._stockMap=inv?.stock?Object.fromEntries(Object.entries(inv.stock)):{};res.send(renderSite(user, offers, req.query.sent === '1'));
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/site/:slug/profile', async(req,res)=>{
  try { const user=await User.findOne({slug:req.params.slug,published:true}); if(!user)return res.status(404).send('Site not found');const offers=await Offer.find({userId:user._id}).sort({createdAt:-1});res.setHeader('Content-Security-Policy',SITE_CSP);const inv=await ShopSetting.findOne({sellerId:user._id}).select('stock').lean();user._stockMap=inv?.stock?Object.fromEntries(Object.entries(inv.stock)):{};res.send(renderSellerProfile(user,offers)); }
  catch(e){console.error('Seller profile error',e);res.status(500).send('Unable to load seller profile')}
});
app.get('/site/:slug/reviews',(req,res)=>res.redirect(302,'/site/'+encodeURIComponent(req.params.slug)+'/profile#reviews'));

app.get('/site/:slug/messages', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    res.setHeader('Content-Security-Policy', SITE_CSP);
    res.setHeader('Permissions-Policy', 'microphone=(self)');
    res.setHeader('Cache-Control', 'no-store');
    res.send(renderMessagesPage(user));
  } catch (err) { res.status(500).send('Server error'); }
});

app.get('/site/:slug/favorites', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    res.setHeader('Content-Security-Policy', SITE_CSP); res.setHeader('Cache-Control', 'no-store, max-age=0');
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
    await Order.create({
      userId: user._id, offerId: offer._id, offerTitle: offer.title, amount: offer.price,
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

const PAGE_ROUTES = ['/business', '/analytics', '/settings', '/', '/how-it-works', '/features', '/professions', '/pricing', '/about', '/contact', '/build', '/dashboard', '/messages', '/reviews', '/privacy', '/terms', '/reset'];
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