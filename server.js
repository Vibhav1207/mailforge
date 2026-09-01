// MailForge - Local development entry point
const { connect } = require('./src/db');
const MongoStore = require('connect-mongo');
const { app, setSessionStore } = require('./src/app');

const PORT = process.env.PORT || 3000;

async function start() {
  await connect();

  // Set up MongoStore session middleware after connection is ready
  setSessionStore(MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60,
  }));

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`MailForge running on http://0.0.0.0:${PORT}`);
  });
}

start().catch(err => {
  console.error('Failed to start:', err);
  process.exit(1);
});
