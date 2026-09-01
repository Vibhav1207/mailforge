const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.warn('WARNING: MONGODB_URI environment variable is not set. Database operations will fail.');
}

const client = MONGODB_URI ? new MongoClient(MONGODB_URI) : null;
const db = client ? client.db('mailforge') : null;

// Collections (will be null if MongoDB is not connected)
const users = db ? db.collection('users') : null;
const workspaces = db ? db.collection('workspaces') : null;
const domains = db ? db.collection('domains') : null;
const senderIdentities = db ? db.collection('sender_identities') : null;
const apiKeys = db ? db.collection('api_keys') : null;
const emails = db ? db.collection('emails') : null;
const emailEvents = db ? db.collection('email_events') : null;
const templates = db ? db.collection('templates') : null;
const webhooks = db ? db.collection('webhooks') : null;
const webhookLogs = db ? db.collection('webhook_logs') : null;
const rateLimits = db ? db.collection('rate_limits') : null;

// Create indexes
async function ensureIndexes() {
  if (!db) return;
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
  if (!client) {
    console.error('Cannot connect to MongoDB: MONGODB_URI not set.');
    return;
  }
  await client.connect();
  await ensureIndexes();
  console.log('Connected to MongoDB');
}

module.exports = {
  client, db, users, workspaces, domains, senderIdentities, apiKeys,
  emails, emailEvents, templates, webhooks, webhookLogs, rateLimits,
  connect
};
