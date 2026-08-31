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

// Register
router.post('/register', async (req, res) => {
  try {
    const { name, email, password, confirm_password } = req.body;
    const trimmedName = (name || '').trim();
    const trimmedEmail = (email || '').trim().toLowerCase();
    const trimmedPass = password || '';

    if (!trimmedName || !trimmedEmail || !trimmedPass) {
      setFlash(req, 'danger', 'All fields are required.');
      return res.redirect('/login');
    }
    if (trimmedPass !== confirm_password) {
      setFlash(req, 'danger', 'Passwords do not match.');
      return res.redirect('/login');
    }
    if (trimmedPass.length < 8) {
      setFlash(req, 'danger', 'Password must be at least 8 characters.');
      return res.redirect('/login');
    }

    const existing = await users.findOne({ email: trimmedEmail });
    if (existing) {
      setFlash(req, 'danger', 'An account with this email already exists.');
      return res.redirect('/login');
    }

    const result = await users.insertOne({
      name: trimmedName,
      email: trimmedEmail,
      password_hash: await hashPassword(trimmedPass),
      email_verified: true,
      created_at: new Date()
    });

    req.session.userId = result.insertedId.toString();
    setFlash(req, 'success', `Welcome, ${trimmedName}! Your workspace is ready.`);
    res.redirect('/');
  } catch (err) {
    setFlash(req, 'danger', 'Registration failed. Please try again.');
    res.redirect('/login');
  }
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
