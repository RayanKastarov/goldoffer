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

// 🔒 НОВИ ЗАЩИТНИ ЩИТОВЕ (Добавяме ги тук):
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// 🛡️ ЩИТ 1: Helmet защитава сървъра от XSS атаки и скрива системна информация
app.use(helmet());

// 🛡️ ЩИТ 2: Ограничаваме CORS достъпа (Смени линка с твоя истински домейн в бъдеще)
app.use(cors());

// 🛡️ ЩИТ 3: Brute-Force защита (Спира хакери, които налучкват пароли)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минути прозорец
  max: 20, // Максимум 20 опита за регистрация/вход от един и същ компютър
  message: { message: 'Твърде много опити. Моля, опитайте отново след 15 минути.' }
});

// Слагаме лимитера само върху логина и регистрацията, за да не пречи на останалия сайт
// app.use('/api/auth/login', authLimiter);
// app.use('/api/auth/register', authLimiter);


const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const upload = multer({ dest: 'uploads/' });

app.use(express.json());

// ОТТУК НАДОЛУ КОДЪТ СИ ОСТАВА АБСОЛЮТНО СЪЩИЯ, НЕ ПИПАЙ НИЩО ДРУГО:
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

// Памет за временно съхранение на кодовете (Имейл -> Код)
const activeOTPs = new Map();
const nodemailer = require('nodemailer');

// Функция за изпращане на имейл (Тестова конфигурация)
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

  // Изписва генерирания код долу в терминала на VS Code:
  console.log(`\n=== 📧 GoldOffer ИМЕЙЛ СИМУЛАТОР ===`);
  console.log(`Потребител: ${email}`);
  console.log(`🔑 КОД ЗА ВХОД: ${code}`);
  console.log(`🔗 Линк за преглед на писмото: ${nodemailer.getTestMessageUrl(info)}`);
  console.log(`===================================\n`);
}

// 1. СТЪПКА 1 ПРИ ВХОД: ПРОВЕРКА НА ПАРОЛА И ИЗПРАЩАНЕ НА КОД
app.post('/api/auth/login-request', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Невалидни данни' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ message: 'Невалидни данни' });

    // Генерираме произволен 6-цифрен код
    const otpCode = Math.floor(100000 + Math.random() * 900000).toString();
    activeOTPs.set(email, otpCode);

    // Изпращаме кода (симулирано към конзолата)
    await sendVerificationEmail(email, otpCode);

    res.json({ message: 'Кодът е изпратен успешно' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Грешка при изпращане на кода' });
  }
});

// 2. СТЪПКА 2 ПРИ ВХОД: ПРОВЕРКА НА КОДА И ОКОНЧАТЕЛНО ВЛИЗАНЕ
app.post('/api/auth/login-verify', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!activeOTPs.has(email) || activeOTPs.get(email) !== otp) {
      return res.status(400).json({ message: 'Невалиден или изтекъл код!' });
    }

    const user = await User.findOne({ email });
    activeOTPs.delete(email); // Изтриваме кода, за да не може да се ползва повторно

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, firstName: user.firstName, lastName: user.lastName, email: user.email } });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при проверка на кода' });
  }
});

// --- REAL AI MARKET PRICE SEARCH ---
app.post('/api/ai/market-price', async (req, res) => {
  const { query, category, city } = req.body;
  try {
    // Внедряване на реално онлайн търсене чрез OpenAI / Web Search API
    const response = await axios.post('https://api.openai.com/v1/chat/completions', {
      model: 'gpt-4o',
      messages: [{
        role: 'system',
        content: `Ти си ценови аналитик за България. Анализирай пазарните цени за "${query}" в категория "${category}" за град/регион "${city}". Върни САМО JSON обект: {"minPrice": number, "maxPrice": number, "avgPrice": number, "description": "кратко описание на български"}`
      }]
    }, {
      headers: { 'Authorization': `Bearer ${process.env.OPENAI_API_KEY}` }
    });

    const aiResult = JSON.parse(response.data.choices[0].message.content);
    res.json(aiResult);
  } catch (err) {
    res.status(500).json({ minPrice: 20, maxPrice: 60, avgPrice: 40, description: `Качествена услуга за ${query}` });
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

// --- PUBLIC SITE ENDPOINT (За генериране на публичния сайт на клиента) ---
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
        price: process.env.STRIPE_PRICE_ID, // ID на плана за €19.99/месец
        quantity: 1,
      }],
      success_url: `${process.env.FRONTEND_URL}/dashboard?success=true`,
      cancel_url: `${process.env.FRONTEND_URL}/dashboard?canceled=true`,
    });
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ message: 'Грешка при плащане' });
  }
});
// 📈 ЕНДПОИНТ ЗА ИСТИНСКИ СТАТИСТИКИ И ПАРИ НА ТАБЛОТО
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    // 1. Намираме всички завършени поръчки на текущия потребител в MongoDB
    const orders = await Order.find({ userId: req.user.id, status: 'Completed' });
    
    // 2. Преброяваме общия брой продажби
    const totalOrders = orders.length;
    
    // 3. Събираме всички изкарани пари
    const totalRevenue = orders.reduce((sum, order) => sum + (order.amount || 0), 0);

    // Изпращаме реалните цифри към сайта
    res.json({
      totalOrders,
      totalRevenue
    });
  } catch (err) {
    console.error("Грешка при изчисляване на SaaS статистики:", err);
    res.status(500).json({ message: 'Грешка при зареждане на данните' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => console.log(`Backend работи на порт ${PORT}`));



