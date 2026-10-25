const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.json({ msg: 'Billing route работи' });
});

router.post('/', (req, res) => {
  res.json({ msg: 'Плащането е получено' });
});

module.exports = router;