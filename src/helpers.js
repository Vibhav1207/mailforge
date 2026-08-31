const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// Generate prefixed unique ID
function generateId(prefix = 'email') {
  return `${prefix}_${crypto.randomBytes(12).toString('hex')}`;
}

// Generate API key and its hash
function generateApiKey() {
  const raw = 'sk_live_' + crypto.randomBytes(24).toString('hex');
  const keyHash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, keyHash };
}

// Hash an existing raw key
function hashApiKey(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// Generate DNS verification token
function generateDnsToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Generate DKIM key pair (simplified for verification)
function generateDkimKey() {
  const privateKey = crypto.randomBytes(32).toString('hex');
  const publicKey = crypto.createHash('sha256').update(privateKey).digest('hex');
  return { privateKey, publicKey };
}

// Generate SPF record
function generateSpfRecord() {
  return 'v=spf1 include:spf.mailforge.io ~all';
}

// Generate DMARC record
function generateDmarcRecord() {
  return 'v=DMARC1; p=none; rua=mailto:reports@mailforge.io; pct=100';
}

// Sign webhook payload
function signWebhook(payload, secret) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const toSign = `${timestamp}.${JSON.stringify(payload)}`;
  const signature = crypto.createHmac('sha256', secret).update(toSign).digest('hex');
  return `t=${timestamp},v1=${signature}`;
}

// Hash password
async function hashPassword(password) {
  return bcrypt.hash(password, 12);
}

// Verify password
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// Format date for display
function formatDate(date) {
  if (!date) return 'Never';
  const d = new Date(date);
  const now = new Date();
  const diff = now - d;
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined });
}

// Format date for detail view
function formatDateTime(date) {
  if (!date) return 'Never';
  return new Date(date).toLocaleString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  });
}

// Escape HTML
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Sanitize for display
function sanitize(str) {
  return escapeHtml(String(str || ''));
}

// Email limits (none — unlimited sending)
const LIMITS = {
  emails_per_month: Infinity,
  api_requests_per_day: Infinity,
  domains: Infinity,
  api_keys: Infinity,
  templates: Infinity,
  webhooks: Infinity,
};

module.exports = {
  generateId, generateApiKey, hashApiKey, generateDnsToken, generateDkimKey,
  generateSpfRecord, generateDmarcRecord, signWebhook,
  hashPassword, verifyPassword, formatDate, formatDateTime,
  escapeHtml, sanitize, LIMITS
};
