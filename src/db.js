const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  throw new Error('MONGODB_URI environment variable is not set');
}

const client = new MongoClient(MONGODB_URI);
const db = client.db('mailforge');

// Collections
const users = db.collection('users');
const workspaces = db.collection('workspaces');
const domains = db.collection('domains');
const senderIdentities = db.collection('sender_identities');
const apiKeys = db.collection('api_keys');
const emails = db.collection('emails');
const emailEvents = db.collection('email_events');
const templates = db.collection('templates');
const webhooks = db.collection('webhooks');
const webhookLogs = db.collection('webhook_logs');
const rateLimits = db.collection('rate_limits');

// Create indexes
async function ensureIndexes() {
  await users.createIndex({ email: 1 }, { unique: true });
  await workspaces.createIndex({ owner_id: 1 });
  await workspaces.createIndex({ slug: 1 }, { unique: true });
  await domains.createIndex({ workspace_id: 1, domain: 1 });
  await domains.createIndex({ verification_token: 1 });
  await apiKeys.createIndex({ workspace_id: 1 });
  await apiKeys.createIndex({ key_hash: 1 }, { unique: true });
  await emails.createIndex({ workspace_id: 1, created_at: -1 });
  await emails.createIndex({ status: 1 });
  await emailEvents.createIndex({ email_id: 1 });
  await senderIdentities.createIndex({ workspace_id: 1 });
  await templates.createIndex({ workspace_id: 1 });
  await webhooks.createIndex({ workspace_id: 1 });
  await webhookLogs.createIndex({ webhook_id: 1 });
  // TTL index for rate limiting (30 days)
  await rateLimits.createIndex({ timestamp: 1 }, { expireAfterSeconds: 2592000 });
}

async function connect() {
  await client.connect();
  await ensureIndexes();
  console.log('Connected to MongoDB');
}

module.exports = {
  client, db, users, workspaces, domains, senderIdentities, apiKeys,
  emails, emailEvents, templates, webhooks, webhookLogs, rateLimits,
  connect
};
