const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Успешна връзка с MongoDB!');
  } catch (err) {
    console.error('Грешка при връзка с MongoDB:', err.message);
    process.exit(1);
  }
};

module.exports = connectDB;