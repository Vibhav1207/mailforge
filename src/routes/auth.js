const express = require('express');
const router = express.Router();
const { users } = require('../db');
const { hashPassword, verifyPassword } = require('../helpers');
const { setFlash } = require('../middleware');

// Login page — redirect to dashboard (auth bypassed)
router.get('/login', (req, res) => {
  res.redirect('/');
});

// Register — disabled for now
router.post('/register', (req, res) => {
  setFlash(req, 'danger', 'Registration is currently disabled.');
  res.redirect('/login');
});

// Login — redirect to dashboard (auth bypassed)
router.post('/login', (req, res) => {
  res.redirect('/');
});

// Logout — redirect to dashboard (auth bypassed)
router.get('/logout', (req, res) => {
  res.redirect('/');
});

module.exports = router;
