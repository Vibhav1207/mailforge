// Vercel Serverless entry point
// Import the Express app for Vercel's serverless runtime
const app = require('../src/app');

// For Vercel serverless, we need to handle the MongoDB connection
// differently — connect on cold start, reuse on warm invocations
let isConnected = false;

module.exports = async (req, res) => {
  if (!isConnected) {
    const { connect } = require('../src/db');
    await connect();
    isConnected = true;
  }
  return app(req, res);
};
