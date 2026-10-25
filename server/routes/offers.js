const express = require('express');
const router = express.Router();
const Offer = require('../models/Offer');

// Взимане на всички оферти
router.get('/', async (req, res) => {
  try {
    const offers = await Offer.find();
    res.json(offers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Създаване на нова оферта
router.post('/', async (req, res) => {
  try {
    console.log('Изпратени данни от клиента:', req.body); // Ще отпечата данните в терминала

    const { title, weightInGrams, karats, price, imageUrl } = req.body;

    const newOffer = new Offer({
      title,
      weightInGrams: Number(weightInGrams),
      karats: Number(karats),
      price: Number(price),
      imageUrl: imageUrl || ''
    });

    const savedOffer = await newOffer.save();
    res.status(201).json(savedOffer);
  } catch (error) {
    console.error('Mongoose валидационна грешка:', error.message); // Изписва точната причина в терминала
    res.status(400).json({ error: error.message });
  }
});

module.exports = router;