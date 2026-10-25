const mongoose = require('mongoose');

const offerSchema = new mongoose.Schema({
  title: { type: String, required: true },
  weightInGrams: { type: Number, required: true },
  karats: { type: Number, required: true },
  price: { type: Number, required: true },
imageUrl: { type: String, default: '' }
});

module.exports = mongoose.model('Offer', offerSchema);