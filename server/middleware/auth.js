const express = require('express');
const router = express.Router();
const Offer = require('../models/Offer');

// Взимане на всички оферти
router.get('/', async (req, res) => {
  try {
    const offers = await Offer.find();
    res.json(offers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Създаване на нова оферта
router.post('/', async (req, res) => {
  try {
    const newOffer = new Offer(req.body);
    const savedOffer = await newOffer.save();
    res.status(201).json(savedOffer);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;