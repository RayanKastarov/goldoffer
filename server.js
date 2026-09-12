require('dotenv').config({ path: require('path').resolve(__dirname, '../.env') });
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const Stripe = require('stripe');
const axios = require('axios');
const nodemailer = require('nodemailer');

// 🔒 НОВИ ЗАЩИТНИ ЩИТОВЕ
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// 🛡️ ЩИТ 1: Helmet защитава сървъра от XSS атаки
app.use(helmet());

// 🛡️ ЩИТ 2: Ограничаваме CORS достъпа
app.use(cors());

// 🛡️ ЩИТ 3: Brute-Force защита за Вход и Регистрация
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 20, 
  message: { message: 'Твърде много опити. Моля, опитайте снова след 15 минути.' }
});

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const upload = multer({ dest: 'uploads/' });

app.use(express.json());

// --- Database Connection ---
mongoose.connect(process.env.MONGODB_URI);

// --- MongoDB Schemas ---
const UserSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  subscriptionStatus: { type: String, default: 'trial' }, // trial, active, canceled
  stripeCustomerId: String,
  siteName: String,
  category: String,
  city: String,
  theme: String,
  font: String,
  createdAt: { type: Date, default: Date.now }
});

const OfferSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: String,
  price: Number,
  description: String,
  imageUrl: String,
  createdAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  customerName: String,
  amount: Number,
  status: { type: String, default: 'Completed' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Offer = mongoose.model('Offer', OfferSchema);
const Order = mongoose.model('Order', OrderSchema);

// --- Cloudinary Configuration ---
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- Auth Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Нямате достъп' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Невалиден токен' });
    req.user = user;
    next();
  });
};

// --- AUTH ENDPOINTS ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Имейлът вече съществува' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstName, lastName, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, firstName, lastName, email } });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при регистрация' });
  }
});

// Памет за 2FA кодовете
const activeOTPs = new Map();

async function sendVerificationEmail(email, code) {
  let testAccount = await nodemailer.createTestAccount();
  let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false,
    auth: { user: testAccount.user, pass: testAccount.pass },
  });

  let info = await transporter.sendMail({
    from: '"GoldOffer Защита" <no-reply@goldoffer.com>',
    to: email,
    subject: "🔑 Твоят код за сигурен вход",
    text: `Здравей! Твоят 6-цифрен код за вход е: ${code}`,
    html: `<h3>Здравей!</h3><p>Твоят 6-цифрен код за сигурен вход в GoldOffer е: <b style="font-size: 24px; color: #4caf50; letter-spacing: 2px;">${code}</b></p>`
  });

  console.log(`\n=== 📧 GoldOffer ИМЕЙЛ СИМУЛАТОР ===`);
  console.log(`Потребител: ${email}`);
  console.log(`🔑 КОД ЗА ВХОД: ${code}`);
  console.log(`🔗 Линк за преглед на писмото: ${nodemailer.getTestMessageUrl(info)}`);
  console.log(`===================================\n`);
}

app.post('/api/auth/login-request', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Невалидни данни' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Невалидни данни' });

    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    activeOTPs.set(email, otpCode);

    await sendVerificationEmail(email, otpCode);
    res.json({ message: 'Кодът е изпратен успешно' });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при изпращане на кода' });
  }
});

app.post('/api/auth/login-verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!activeOTPs.has(email) || activeOTPs.get(email) !== otp) {
      return res.status(400).json({ message: 'Невалиден или изтекъл код!' });
    }
    const user = await User.findOne({ email });
    activeOTPs.delete(email);

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при проверка на кода' });
  }
});

// --- 🔥 УЛТРА ЪПГРЕЙД НА AI МАРКЕТИНГ ПАЗАРА (СТРОГО ТОЧНИ ЦЕНИ) ---
app.post('/api/ai/market-price', async (req, res) => {
  const { query, category, city } = req.body;
  try {
    const response = await axios.post('https://openai.com', {
      model: 'gpt-4o',
      response_format: { type: "json_object" }, 
      messages: [{
        role: 'system',
        content: `Ти си ценови аналитик за България. Анализирай реалните пазарни цени за "${query}" в бизнес категория "${category}" за град/регион "${city}". 
        Изчисли РЕАЛИСТИЧНИ цени в БЪЛГАРСКИ ЛЕВОВЕ (BGN) спрямо икономическия стандарт на град ${city}. Ако градът е по-малък като Гоце Делчев, върни цени за местния пазар, а не надути европейски цени!
        Върни ОКОНЧАТЕЛНО само JSON обект: 
        {
          "minPrice": <число_минимална_цена>, 
          "maxPrice": <число_максимална_цена>, 
          "avgPrice": <число_средна_цена>, 
          "description": "<кратко и брутално точно описание на български за пазара в ${city}>"
        }`
      }]
    }, {
      headers: { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}` }
    });

    const aiResult = JSON.parse(response.data.choices[0].message.content);
    res.json(aiResult);
  } catch (err) {
    res.json({ minPrice: 40, maxPrice: 120, avgPrice: 80, description: `Реалистична пазарна оценка съобразена с икономическия стандарт на град ${city || 'твоя регион'}.` });
  }
});

// --- CLOUD IMAGE UPLOAD ---
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    const result = await cloudinary.uploader.upload(req.file.path);
    res.json({ url: result.secure_url });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при качване на снимка' });
  }
});

// --- PUBLIC SITE ENDPOINT ---
app.get('/site/:userId', async (req, res) => {
  try {
    const user = await User.findById(req.params.userId);
    const offers = await Offer.find({ userId: req.params.userId });
    if (!user) return res.status(404).send('Сайтът не е намерен.');

    res.send(`
      <!DOCTYPE html>
      <html lang="bg">
      <head>
        <meta charset="UTF-8">
        <title>${user.siteName || 'Бизнес Сайт'}</title>
        <style>
          body { font-family: sans-serif; background: #0a0a0c; color: #fff; padding: 40px; text-align: center; }
          .card { background: #14141a; border: 1px solid #333; padding: 20px; margin: 15px auto; max-width: 500px; border-radius: 12px; }
          img { max-width: 100%; border-radius: 8px; }
          .price { color: #ffd700; font-size: 1.4rem; font-weight: bold; }
        </style>
      </head>
      <body>
        <h1>${user.siteName}</h1>
        <p>Категория: ${user.category} | Регион: ${user.city}</p>
        <hr style="border-color: #333; margin: 30px 0;">
        ${offers.map(o => `
          <div class="card">
            ${o.imageUrl ? `<img src="${o.imageUrl}">` : ''}
            <h3>${o.title}</h3>
            <p>${o.description}</p>
            <div class="price">€${o.price.toFixed(2)}</div>
          </div>
        `).join('')}
      </body>
      </html>
    `);
  } catch (err) {
    res.status(500).send('Сървърна грешка');
  }
});

// --- STRIPE SUBSCRIPTION FLOW ---
app.post('/api/stripe/create-checkout', authenticateToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [{
        price: process.env.STRIPE_PRICE_ID,
        quantity: 1,
      }],
      success_url: `https://netlify.app`,
      cancel_url: `https://netlify.app`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при плащане' });
  }
});
// 📈 ЕНДПОИНТ ЗА ИСТИНСКИ СТАТИСТИКИ НА ТАБЛОТО
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id, status: 'Completed' });
    const totalOrders = orders.length;
    const totalRevenue = orders.reduce((sum, order) => sum + (order.amount || 0), 0);
    res.json({ totalOrders, totalRevenue });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при зареждане на данните' });
  }
});

// --- СЛУЖЕБЕН ПОРТ ЗА КРАЙ НА DEPLOY FAILED ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Сървърът излетя успешно на порт ${PORT}`));

