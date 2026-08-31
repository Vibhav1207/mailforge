const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');

const { connect, client } = require('./db');
const { flashMessages } = require('./middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════════════════════════════════════
// SECURITY
// ═══════════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://fonts.googleapis.com", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { type: 'rate_limit_exceeded', message: 'Too many requests. Please try again later.' } },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many authentication attempts. Please try again later.',
});

app.use('/v1/', apiLimiter);
app.use('/login', authLimiter);
app.use('/register', authLimiter);

// ═══════════════════════════════════════════════════════════════
// PARSERS & SESSION
// ═══════════════════════════════════════════════════════════════
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(cookieParser());

app.use(session({
  secret: process.env.SESSION_SECRET || require('crypto').randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60, // 7 days
  }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}));

// ═══════════════════════════════════════════════════════════════
// VIEW ENGINE
// ═══════════════════════════════════════════════════════════════
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

// ═══════════════════════════════════════════════════════════════
// STATIC FILES
// ═══════════════════════════════════════════════════════════════
app.use('/public', express.static(path.join(__dirname, '..', 'public'), {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.py') || filePath.endsWith('.pyc') || filePath.endsWith('.env')) {
      return res.status(404).end();
    }
  }
}));

// ═══════════════════════════════════════════════════════════════
// SECURITY HEADERS
// ═══════════════════════════════════════════════════════════════
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  next();
});

// Flash messages middleware
app.use(flashMessages);

// ═══════════════════════════════════════════════════════════════
// ROUTES
// ═══════════════════════════════════════════════════════════════

// Auth routes (no workspace middleware)
app.use('/', require('./routes/auth'));

// REST API routes (uses API key auth, no session required)
app.use('/', require('./routes/api'));

// Dashboard page routes (uses session + workspace middleware)
app.use('/', require('./routes/pages'));

// 404 handler
app.use((req, res) => {
  res.status(404).render('login', { flash: { type: 'danger', message: 'Page not found.' } });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ═══════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════
async function start() {
  await connect();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MailForge running on http://0.0.0.0:${PORT}`);
  });
}

start().catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});

module.exports = app;
