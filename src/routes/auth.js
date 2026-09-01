const express = require('express');
const router = express.Router();
const { users } = require('../db');
const { hashPassword, verifyPassword } = require('../helpers');
const { setFlash } = require('../middleware');

// Login page
router.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  res.render('login', { flash: req.session.flash || {} });
});

// Register — disabled for now
router.post('/register', (req, res) => {
  setFlash(req, 'danger', 'Registration is currently disabled.');
  res.redirect('/login');
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const trimmedEmail = (email || '').trim().toLowerCase();

    const user = await users.findOne({ email: trimmedEmail });
    if (user && await verifyPassword(password, user.password_hash)) {
      req.session.userId = user._id.toString();
      setFlash(req, 'success', `Welcome back, ${user.name}!`);
      const returnTo = req.session.returnTo || '/';
      delete req.session.returnTo;
      return res.redirect(returnTo);
    }

    setFlash(req, 'danger', 'Invalid email or password.');
    res.redirect('/login');
  } catch (err) {
    setFlash(req, 'danger', 'Login failed. Please try again.');
    res.redirect('/login');
  }
});

// Logout
router.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

module.exports = router;
