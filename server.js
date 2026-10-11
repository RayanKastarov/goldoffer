require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
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
app.use(cors({ origin: [FRONTEND_URL, 'http://localhost:5500', 'http://127.0.0.1:5500', 'http://localhost:3000'] }));

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

const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\//.test(file.mimetype))
});

// ---------- Database ----------
mongoose.connect(process.env.MONGODB_URI).catch(err => console.error('MongoDB error', err));

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
  createdAt: { type: Date, default: Date.now }
});

const OfferSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  title: String,
  price: Number,
  description: String,
  imageUrl: String,
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

const User = mongoose.model('User', UserSchema);
const Offer = mongoose.model('Offer', OfferSchema);
const Order = mongoose.model('Order', OrderSchema);

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

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
const publicUser = (u) => ({
  id: u._id, firstName: u.firstName, lastName: u.lastName, email: u.email,
  subscriptionStatus: u.subscriptionStatus, siteName: u.siteName, slug: u.slug,
  category: u.category, city: u.city, theme: u.theme, font: u.font, published: u.published,
  siteUrl: u.slug && u.published ? `${PUBLIC_BASE}/site/${u.slug}` : null
});
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
    const { firstName, lastName, email, password } = req.body || {};
    if (!firstName || !email || !password) return res.status(400).json({ message: 'Please fill in all fields.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ message: 'Invalid email address.' });
    if (String(password).length < 8) return res.status(400).json({ message: 'Password must be at least 8 characters.' });

    const existing = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (existing) return res.status(400).json({ message: 'This email is already registered.' });

    const user = await User.create({
      firstName: String(firstName).trim(),
      lastName: String(lastName || '').trim(),
      email,
      password: await bcrypt.hash(password, 10)
    });
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ message: 'Registration failed. Please try again.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email: String(email || '').toLowerCase().trim() });
    if (!user || !(await bcrypt.compare(String(password || ''), user.password))) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }
    res.json({ token: signToken(user), user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ message: 'Login failed. Please try again.' });
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
    const { siteName, category, city, theme, font, publish } = req.body || {};
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (siteName !== undefined) user.siteName = String(siteName).trim().slice(0, 80);
    if (category !== undefined) user.category = String(category).slice(0, 80);
    if (city !== undefined) user.city = String(city).slice(0, 80);
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
  const offers = await Offer.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json({ offers });
});

app.post('/api/offers', authenticateToken, async (req, res) => {
  try {
    const { title, price, description, imageUrl } = req.body || {};
    if (!title || !String(title).trim()) return res.status(400).json({ message: 'Title is required.' });
    const p = Number(price);
    if (!isFinite(p) || p < 0) return res.status(400).json({ message: 'Invalid price.' });
    const offer = await Offer.create({
      userId: req.user.id,
      title: String(title).trim().slice(0, 120),
      price: p,
      description: String(description || '').slice(0, 500),
      imageUrl: /^https:\/\//.test(imageUrl || '') ? imageUrl : null
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
    console.error('AI price error:', err.message);
    res.status(502).json({ message: 'Market price lookup is unavailable right now. Please enter the price manually.' });
  }
});

// ---------- Image upload ----------
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'Please choose an image file.' });
  try {
    const result = await cloudinary.uploader.upload(req.file.path);
    res.json({ url: result.secure_url });
  } catch (err) {
    res.status(500).json({ message: 'Image upload failed.' });
  } finally {
    fs.unlink(req.file.path, () => {});
  }
});

// ---------- Public site ----------
app.get('/site/:slug', async (req, res) => {
  try {
    const user = await User.findOne({ slug: req.params.slug });
    if (!user || !user.published) return res.status(404).send('Site not found.');
    const offers = await Offer.find({ userId: user._id }).sort({ createdAt: -1 });
    const t = THEMES[user.theme] || THEMES.gold;
    const f = FONTS[user.font] || FONTS.sans;
    const sent = req.query.sent === '1';

    res.send(`<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(user.siteName)}</title>
<meta name="description" content="${esc(user.siteName)} - ${esc(user.category)} in ${esc(user.city)}">
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=${f.gf}&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:${f.css};background:#f5f6fa;color:#14161c;min-height:100vh}
.hero{background:linear-gradient(135deg,${t.a},${t.b});color:${t.on};text-align:center;padding:64px 20px 70px}
.hero h1{font-size:2.6rem;letter-spacing:-1px;margin-bottom:8px}
.hero .meta{opacity:.85;font-size:1rem}
.wrap{max-width:900px;margin:-34px auto 60px;padding:0 16px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:18px}
.card{background:#fff;border:1px solid #e6e8ef;border-radius:18px;overflow:hidden;box-shadow:0 12px 30px rgba(20,22,28,.08);display:flex;flex-direction:column}
.card img{width:100%;height:180px;object-fit:cover}
.card .in{padding:18px;display:flex;flex-direction:column;flex:1}
.card h3{font-size:1.1rem;margin-bottom:6px}
.card p{color:#6b7280;font-size:.9rem;line-height:1.5;margin-bottom:12px;flex:1}
.price{color:${t.ink};font-size:1.5rem;font-weight:800;margin-bottom:12px}
input{width:100%;padding:11px 12px;margin-bottom:8px;background:#fff;border:1px solid #e6e8ef;border-radius:10px;font-family:inherit;font-size:.9rem}
input:focus{outline:2px solid ${t.ink};border-color:transparent}
button{width:100%;background:linear-gradient(135deg,${t.a},${t.b});color:${t.on};border:0;border-radius:10px;padding:12px;font-weight:700;font-family:inherit;cursor:pointer}
.ok{background:#dcfce7;color:#15803d;padding:14px;border-radius:12px;margin-bottom:18px;text-align:center;font-weight:600}
.none{text-align:center;color:#6b7280;padding:40px}
footer{text-align:center;color:#9aa0ad;font-size:.8rem;padding:0 0 30px}
</style></head><body>
<div class="hero"><h1>${esc(user.siteName)}</h1>
<div class="meta">${esc(user.category)}${user.city ? ' &middot; ' + esc(user.city) : ''}</div></div>
<div class="wrap">
${sent ? '<div class="ok">Thank you. Your request was sent and the business will contact you.</div>' : ''}
<div class="grid">
${offers.length === 0 ? '<div class="none">No offers yet.</div>' : offers.map(o => `
<div class="card">
${/^https:\/\//.test(o.imageUrl || '') ? `<img src="${esc(o.imageUrl)}" alt="${esc(o.title)}">` : ''}
<div class="in"><h3>${esc(o.title)}</h3><p>${esc(o.description)}</p>
<div class="price">&euro;${Number(o.price || 0).toFixed(2)}</div>
<form method="POST" action="/site/${esc(user.slug)}/order">
<input type="hidden" name="offerId" value="${o._id}">
<input name="customerName" placeholder="Your name" required maxlength="80">
<input name="customerContact" placeholder="Phone or email" required maxlength="120">
<button type="submit">Request this offer</button></form></div></div>`).join('')}
</div></div>
<footer>Built with GoldOffer Studio</footer>
</body></html>`);
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.post('/site/:slug/order', publicLimiter, async (req, res) => {
  try {
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
      success_url: `${FRONTEND_URL}/?paid=1`,
      cancel_url: `${FRONTEND_URL}/`
    });
    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe Checkout Error:', err);
    res.status(500).json({ message: 'Could not start checkout.' });
  }
});

// ---------- Serve the builder page itself (so no separate Netlify hosting is needed) ----------
function findFile(name) {
  const candidates = [path.join(__dirname, name), path.join(__dirname, '..', name), path.join(process.cwd(), name)];
  return candidates.find(p => fs.existsSync(p));
}

app.get('/', (req, res) => {
  const file = findFile('index.html');
  if (!file) return res.send('GoldOffer API is running.');
  // The builder page uses inline scripts and a few external resources (fonts, chart library, photos)
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
    "script-src-attr 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https: blob:",
    "connect-src 'self' https://cdn.jsdelivr.net",
    "form-action 'self'"
  ].join('; '));
  res.sendFile(file);
});

app.get('/logo.jpg', (req, res) => {
  const file = findFile('logo.jpg');
  if (!file) return res.status(404).end();
  res.sendFile(file);
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));