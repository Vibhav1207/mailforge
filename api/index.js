// Vercel Serverless entry point
// Connect to MongoDB on cold start, set up session store, handle requests

const MongoStore = require('connect-mongo');

let isConnected = false;
let app;

async function init() {
  if (isConnected) return;

  const { connect } = require('../src/db');
  await connect();

  // Set up MongoStore session middleware after connection
  const { app: expressApp, setSessionStore } = require('../src/app');
  setSessionStore(MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions',
    ttl: 7 * 24 * 60 * 60,
  }));

  app = expressApp;
  isConnected = true;
}

module.exports = async (req, res) => {
  await init();
  return app(req, res);
};
