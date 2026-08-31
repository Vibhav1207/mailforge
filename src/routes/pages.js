const express = require('express');
const router = express.Router();
const multer = require('multer');
const { ObjectId } = require('mongodb');
const {
  domains, senderIdentities, apiKeys, emails, emailEvents,
  templates, webhooks, webhookLogs, workspaces
} = require('../db');
const {
  generateId, generateApiKey, generateDnsToken, generateDkimKey,
  generateSpfRecord, generateDmarcRecord, formatDate, formatDateTime,
  sanitize, LIMITS
} = require('../helpers');
const { setFlash, loadWorkspace } = require('../middleware');
const { verifyDomain } = require('../services/dns');
const { processEmail, bulkQueue } = require('../services/email');


// Apply workspace middleware to all page routes
router.use(loadWorkspace);

// ═══════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════
router.get('/', async (req, res) => {
  const ws = res.locals.workspace;
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
  const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());

  const [
    totalEmails, monthEmails, delivered, failed, bounced,
    queued, domainCount, verifiedDomains, apiKeysCount
  ] = await Promise.all([
    emails.countDocuments({ workspace_id: ws._id }),
    emails.countDocuments({ workspace_id: ws._id, created_at: { $gte: monthStart } }),
    emails.countDocuments({ workspace_id: ws._id, status: 'delivered' }),
    emails.countDocuments({ workspace_id: ws._id, status: 'failed' }),
    emails.countDocuments({ workspace_id: ws._id, status: 'bounced' }),
    emails.countDocuments({ workspace_id: ws._id, status: { $in: ['queued', 'processing'] } }),
    domains.countDocuments({ workspace_id: ws._id }),
    domains.countDocuments({ workspace_id: ws._id, status: 'verified' }),
    apiKeys.countDocuments({ workspace_id: ws._id, revoked: false }),
  ]);

  const deliveryRate = totalEmails > 0 ? Math.round((delivered / totalEmails) * 1000) / 10 : 0;
  const recentEmails = await emails.find({ workspace_id: ws._id }).sort({ created_at: -1 }).limit(10).toArray();

  // 7-day stats
  const dailyStats = [];
  for (let i = 6; i >= 0; i--) {
    const day = new Date(now);
    day.setDate(day.getDate() - i);
    day.setHours(0, 0, 0, 0);
    const nextDay = new Date(day);
    nextDay.setDate(nextDay.getDate() + 1);
    const count = await emails.countDocuments({ workspace_id: ws._id, created_at: { $gte: day, $lt: nextDay } });
    dailyStats.push({ label: day.toLocaleDateString('en-US', { weekday: 'short' }), count });
  }

  res.render('dashboard', {
    totalEmails, monthEmails, delivered, failed, bounced, queued,
    deliveryRate, domainCount, verifiedDomains, apiKeysCount,
    recentEmails, dailyStats, formatDate, formatDateTime, sanitize
  });
});

// ═══════════════════════════════════════════════════════════════
// DOMAINS
// ═══════════════════════════════════════════════════════════════
router.get('/domains', async (req, res) => {
  const ws = res.locals.workspace;
  const doms = await domains.find({ workspace_id: ws._id }).sort({ created_at: -1 }).toArray();
  res.render('domains', { domains: doms, formatDate, sanitize });
});

router.post('/domains/add', async (req, res) => {
  const ws = res.locals.workspace;
  const domainName = (req.body.domain || '').trim().toLowerCase();

  if (!domainName || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/.test(domainName)) {
    setFlash(req, 'danger', 'Invalid domain format.');
    return res.redirect('/domains');
  }

  const existing = await domains.findOne({ workspace_id: ws._id, domain: domainName });
  if (existing) {
    setFlash(req, 'danger', 'This domain is already added.');
    return res.redirect('/domains');
  }

  const verificationToken = generateDnsToken();
  const { privateKey, publicKey } = generateDkimKey();
  const dkimSelector = `mailforge-${require('crypto').randomBytes(4).toString('hex')}`;

  const result = await domains.insertOne({
    workspace_id: ws._id,
    domain: domainName,
    status: 'pending',
    verification_token: verificationToken,
    dkim_private_key: privateKey,
    dkim_public_key: publicKey,
    dkim_selector: dkimSelector,
    dns_records: {
      spf: generateSpfRecord(),
      dmarc: generateDmarcRecord(),
      dkim: `v=DKIM1; k=rsa; p=${publicKey}`,
      verification: `mailforge-verification=${verificationToken}`,
    },
    created_at: new Date(),
    verified_at: null,
  });

  setFlash(req, 'success', `Domain ${domainName} added. Configure DNS records to verify.`);
  res.redirect(`/domains/${result.insertedId}`);
});

router.get('/domains/:id', async (req, res) => {
  const ws = res.locals.workspace;
  let domain;
  try {
    domain = await domains.findOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
  } catch { return res.redirect('/domains'); }
  if (!domain) { setFlash(req, 'danger', 'Domain not found.'); return res.redirect('/domains'); }

  const idents = await senderIdentities.find({ workspace_id: ws._id, domain_id: req.params.id }).toArray();
  res.render('domain-detail', { domain, identities: idents, formatDate, formatDateTime, sanitize });
});

router.post('/domains/:id/verify', async (req, res) => {
  const ws = res.locals.workspace;
  let domain;
  try {
    domain = await domains.findOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
  } catch { return res.redirect('/domains'); }
  if (!domain) { setFlash(req, 'danger', 'Domain not found.'); return res.redirect('/domains'); }

  await domains.updateOne({ _id: domain._id }, { $set: { status: 'verifying' } });

  const result = await verifyDomain(domain);

  if (result.passed) {
    await domains.updateOne({ _id: domain._id }, { $set: { status: 'verified', verified_at: new Date(), verification_errors: [] } });
    setFlash(req, 'success', `Domain ${domain.domain} verified successfully!`);
  } else {
    await domains.updateOne({ _id: domain._id }, { $set: { status: 'failed', verification_errors: result.errors } });
    setFlash(req, 'danger', `Verification failed: ${result.errors.join('; ') || 'DNS records not found'}`);
  }

  res.redirect(`/domains/${req.params.id}`);
});

router.post('/domains/:id/delete', async (req, res) => {
  const ws = res.locals.workspace;
  try {
    await domains.deleteOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
    await senderIdentities.deleteMany({ workspace_id: ws._id, domain_id: req.params.id });
    setFlash(req, 'success', 'Domain deleted.');
  } catch {
    setFlash(req, 'danger', 'Error deleting domain.');
  }
  res.redirect('/domains');
});

// ═══════════════════════════════════════════════════════════════
// SENDER IDENTITIES
// ═══════════════════════════════════════════════════════════════
router.get('/identities', async (req, res) => {
  const ws = res.locals.workspace;
  const doms = await domains.find({ workspace_id: ws._id, status: 'verified' }).toArray();
  const idents = await senderIdentities.find({ workspace_id: ws._id }).toArray();
  for (const ident of idents) {
    const dom = await domains.findOne({ _id: new ObjectId(ident.domain_id) });
    ident.domain_name = dom ? dom.domain : 'Unknown';
  }
  res.render('identities', { identities: idents, domains: doms, formatDate, sanitize });
});

router.post('/identities/add', async (req, res) => {
  const ws = res.locals.workspace;
  const { domain_id, email: emailAddr, display_name, reply_to } = req.body;

  if (!domain_id || !emailAddr) {
    setFlash(req, 'danger', 'Domain and email address are required.');
    return res.redirect('/identities');
  }

  const domain = await domains.findOne({ _id: new ObjectId(domain_id), workspace_id: ws._id, status: 'verified' });
  if (!domain) {
    setFlash(req, 'danger', 'Invalid or unverified domain.');
    return res.redirect('/identities');
  }

  const emailDomain = emailAddr.split('@')[1];
  if (emailDomain !== domain.domain) {
    setFlash(req, 'danger', `Email must be on the ${domain.domain} domain.`);
    return res.redirect('/identities');
  }

  const existing = await senderIdentities.findOne({ workspace_id: ws._id, email: emailAddr.toLowerCase() });
  if (existing) {
    setFlash(req, 'danger', 'This sender identity already exists.');
    return res.redirect('/identities');
  }

  await senderIdentities.insertOne({
    workspace_id: ws._id,
    domain_id,
    email: emailAddr.toLowerCase(),
    display_name: display_name || emailAddr.split('@')[0],
    reply_to: reply_to || '',
    enabled: true,
    created_at: new Date()
  });

  setFlash(req, 'success', `Sender identity ${emailAddr} created.`);
  res.redirect('/identities');
});

router.post('/identities/:id/delete', async (req, res) => {
  const ws = res.locals.workspace;
  try {
    await senderIdentities.deleteOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
    setFlash(req, 'success', 'Sender identity deleted.');
  } catch {
    setFlash(req, 'danger', 'Error deleting identity.');
  }
  res.redirect('/identities');
});

router.post('/identities/:id/toggle', async (req, res) => {
  const ws = res.locals.workspace;
  try {
    const ident = await senderIdentities.findOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
    if (ident) {
      await senderIdentities.updateOne({ _id: ident._id }, { $set: { enabled: !ident.enabled } });
      setFlash(req, 'success', `Sender identity ${ident.enabled ? 'disabled' : 'enabled'}.`);
    }
  } catch {
    setFlash(req, 'danger', 'Error updating identity.');
  }
  res.redirect('/identities');
});

// ═══════════════════════════════════════════════════════════════
// API KEYS
// ═══════════════════════════════════════════════════════════════
router.get('/api-keys', async (req, res) => {
  const ws = res.locals.workspace;
  const keys = await apiKeys.find({ workspace_id: ws._id }).sort({ created_at: -1 }).toArray();
  res.render('api-keys', { apiKeys: keys, formatDate, sanitize });
});

router.post('/api-keys/create', async (req, res) => {
  const ws = res.locals.workspace;
  const { name, environment } = req.body;
  if (!name) {
    setFlash(req, 'danger', 'Key name is required.');
    return res.redirect('/api-keys');
  }

  const { raw, keyHash } = generateApiKey();
  const keyPreview = raw.slice(0, 12) + '****' + raw.slice(-4);

  await apiKeys.insertOne({
    workspace_id: ws._id,
    name: name.trim(),
    key_hash: keyHash,
    key_preview: keyPreview,
    environment: environment || 'production',
    revoked: false,
    last_used: null,
    created_at: new Date(),
  });

  // Show the full key only once
  res.render('api-key-created', { rawKey: raw, name: name.trim() });
});

router.post('/api-keys/:id/revoke', async (req, res) => {
  const ws = res.locals.workspace;
  try {
    await apiKeys.updateOne(
      { _id: new ObjectId(req.params.id), workspace_id: ws._id },
      { $set: { revoked: true, revoked_at: new Date() } }
    );
    setFlash(req, 'success', 'API key revoked.');
  } catch {
    setFlash(req, 'danger', 'Error revoking key.');
  }
  res.redirect('/api-keys');
});

// ═══════════════════════════════════════════════════════════════
// EMAIL LOGS
// ═══════════════════════════════════════════════════════════════
router.get('/emails', async (req, res) => {
  const ws = res.locals.workspace;
  const statusFilter = req.query.status || '';
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const perPage = 50;
  const skip = (page - 1) * perPage;

  const query = { workspace_id: ws._id };
  if (statusFilter) query.status = statusFilter;

  const total = await emails.countDocuments(query);
  const emailList = await emails.find(query).sort({ created_at: -1 }).skip(skip).limit(perPage).toArray();
  const totalPages = Math.ceil(total / perPage);

  res.render('email-logs', {
    emails: emailList, statusFilter, page, totalPages, total,
    formatDate, formatDateTime, sanitize
  });
});

router.get('/emails/:id', async (req, res) => {
  const ws = res.locals.workspace;
  const email = await emails.findOne({ email_id: req.params.id, workspace_id: ws._id });
  if (!email) {
    setFlash(req, 'danger', 'Email not found.');
    return res.redirect('/emails');
  }
  const events = await emailEvents.find({ email_id: req.params.id }).sort({ timestamp: 1 }).toArray();
  res.render('email-detail', { email, events, formatDate, formatDateTime, sanitize });
});

// ═══════════════════════════════════════════════════════════════
// TEMPLATES
// ═══════════════════════════════════════════════════════════════
router.get('/templates', async (req, res) => {
  const ws = res.locals.workspace;
  const tmpls = await templates.find({ workspace_id: ws._id }).sort({ created_at: -1 }).toArray();
  res.render('templates-list', { templates: tmpls, formatDate, sanitize });
});

router.get('/templates/create', (req, res) => {
  res.render('template-form', { template: null });
});

router.post('/templates/create', async (req, res) => {
  const ws = res.locals.workspace;
  const { name, subject, body, html_body } = req.body;
  if (!name || !subject) {
    setFlash(req, 'danger', 'Name and subject are required.');
    return res.redirect('/templates/create');
  }
  await templates.insertOne({
    workspace_id: ws._id, name: name.trim(), subject: subject.trim(),
    body: body || '', html_body: html_body || '', created_at: new Date()
  });
  setFlash(req, 'success', 'Template created.');
  res.redirect('/templates');
});

router.get('/templates/:id/edit', async (req, res) => {
  const ws = res.locals.workspace;
  let tmpl;
  try { tmpl = await templates.findOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id }); } catch { return res.redirect('/templates'); }
  if (!tmpl) { setFlash(req, 'danger', 'Template not found.'); return res.redirect('/templates'); }
  res.render('template-form', { template: tmpl });
});

router.post('/templates/:id/edit', async (req, res) => {
  const ws = res.locals.workspace;
  const { name, subject, body, html_body } = req.body;
  try {
    await templates.updateOne(
      { _id: new ObjectId(req.params.id), workspace_id: ws._id },
      { $set: { name: name.trim(), subject: subject.trim(), body: body || '', html_body: html_body || '' } }
    );
    setFlash(req, 'success', 'Template updated.');
  } catch {
    setFlash(req, 'danger', 'Error updating template.');
  }
  res.redirect('/templates');
});

router.post('/templates/:id/delete', async (req, res) => {
  const ws = res.locals.workspace;
  try {
    await templates.deleteOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
    setFlash(req, 'success', 'Template deleted.');
  } catch {
    setFlash(req, 'danger', 'Error deleting template.');
  }
  res.redirect('/templates');
});

// API endpoint for template data
router.get('/api/template/:id', async (req, res) => {
  if (!req.session || !req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
  const { getOrCreateWorkspace } = require('../middleware');
  const ws = await getOrCreateWorkspace(req.session.userId);
  if (!ws) return res.status(404).json({ error: 'Not found' });
  try {
    const tmpl = await templates.findOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
    if (tmpl) return res.json({ subject: tmpl.subject || '', body: tmpl.body || '', html_body: tmpl.html_body || '' });
  } catch {}
  res.status(404).json({ error: 'Not found' });
});

// ═══════════════════════════════════════════════════════════════
// WEBHOOKS
// ═══════════════════════════════════════════════════════════════
router.get('/webhooks', async (req, res) => {
  const ws = res.locals.workspace;
  const hooks = await webhooks.find({ workspace_id: ws._id }).sort({ created_at: -1 }).toArray();
  res.render('webhooks', { webhooks: hooks, formatDate, sanitize });
});

router.post('/webhooks/create', async (req, res) => {
  const ws = res.locals.workspace;
  const { url, name } = req.body;
  const events = Array.isArray(req.body.events) ? req.body.events : (req.body.events ? [req.body.events] : []);

  if (!url || !url.startsWith('http')) {
    setFlash(req, 'danger', 'Valid webhook URL is required.');
    return res.redirect('/webhooks');
  }
  if (!events.length) {
    setFlash(req, 'danger', 'Select at least one event.');
    return res.redirect('/webhooks');
  }

  const crypto = require('crypto');
  const secret = crypto.randomBytes(32).toString('hex');

  await webhooks.insertOne({
    workspace_id: ws._id, name: name || url, url, events, secret, enabled: true, created_at: new Date()
  });
  setFlash(req, 'success', 'Webhook created.');
  res.redirect('/webhooks');
});

router.post('/webhooks/:id/delete', async (req, res) => {
  const ws = res.locals.workspace;
  try {
    await webhooks.deleteOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
    setFlash(req, 'success', 'Webhook deleted.');
  } catch {
    setFlash(req, 'danger', 'Error deleting webhook.');
  }
  res.redirect('/webhooks');
});

router.post('/webhooks/:id/toggle', async (req, res) => {
  const ws = res.locals.workspace;
  try {
    const hook = await webhooks.findOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
    if (hook) {
      await webhooks.updateOne({ _id: hook._id }, { $set: { enabled: !hook.enabled } });
      setFlash(req, 'success', 'Webhook updated.');
    }
  } catch {
    setFlash(req, 'danger', 'Error updating webhook.');
  }
  res.redirect('/webhooks');
});

router.post('/webhooks/:id/test', async (req, res) => {
  const ws = res.locals.workspace;
  const hook = await webhooks.findOne({ _id: new ObjectId(req.params.id), workspace_id: ws._id });
  if (!hook) {
    setFlash(req, 'danger', 'Webhook not found.');
    return res.redirect('/webhooks');
  }

  const { signWebhook } = require('../helpers');
  const crypto = require('crypto');
  const payload = {
    event: 'email.delivered',
    email_id: 'email_test_' + crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString(),
  };

  try {
    const sig = signWebhook(payload, hook.secret);
    await fetch(hook.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Webhook-Signature': sig, 'User-Agent': 'MailForge-Webhook/2.0' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });
    setFlash(req, 'success', 'Test webhook sent successfully.');
  } catch (err) {
    setFlash(req, 'danger', `Test webhook failed: ${err.message}`);
  }
  res.redirect('/webhooks');
});

// ═══════════════════════════════════════════════════════════════
// ANALYTICS
// ═══════════════════════════════════════════════════════════════
router.get('/analytics', async (req, res) => {
  const ws = res.locals.workspace;
  const now = new Date();

  const [total, delivered, failed, bounced, queued] = await Promise.all([
    emails.countDocuments({ workspace_id: ws._id }),
    emails.countDocuments({ workspace_id: ws._id, status: 'delivered' }),
    emails.countDocuments({ workspace_id: ws._id, status: 'failed' }),
    emails.countDocuments({ workspace_id: ws._id, status: 'bounced' }),
    emails.countDocuments({ workspace_id: ws._id, status: { $in: ['queued', 'processing'] } }),
  ]);

  // 30-day daily stats
  const dailyStats = [];
  for (let i = 29; i >= 0; i--) {
    const day = new Date(now); day.setDate(day.getDate() - i); day.setHours(0, 0, 0, 0);
    const nextDay = new Date(day); nextDay.setDate(nextDay.getDate() + 1);
    const [sentCount, deliveredCount, failedCount] = await Promise.all([
      emails.countDocuments({ workspace_id: ws._id, created_at: { $gte: day, $lt: nextDay } }),
      emails.countDocuments({ workspace_id: ws._id, status: 'delivered', delivered_at: { $gte: day, $lt: nextDay } }),
      emails.countDocuments({ workspace_id: ws._id, status: 'failed', created_at: { $gte: day, $lt: nextDay } }),
    ]);
    dailyStats.push({ date: day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }), sent: sentCount, delivered: deliveredCount, failed: failedCount });
  }

  // Top senders
  const topSenders = await emails.aggregate([
    { $match: { workspace_id: ws._id } },
    { $group: { _id: '$from_email', count: { $sum: 1 } } },
    { $sort: { count: -1 } },
    { $limit: 5 }
  ]).toArray();

  res.render('analytics', {
    total, delivered, failed, bounced, queued,
    dailyStats, topSenders,
    deliveryRate: total > 0 ? Math.round((delivered / total) * 1000) / 10 : 0
  });
});

// ═══════════════════════════════════════════════════════════════
// DEVELOPERS / API DOCS
// ═══════════════════════════════════════════════════════════════
router.get('/developers', (req, res) => {
  res.render('developers');
});

// ═══════════════════════════════════════════════════════════════
// SETTINGS
// ═══════════════════════════════════════════════════════════════
router.get('/settings', (req, res) => {
  res.render('settings', { quotaUsed: '-', quotaLimit: 'Unlimited' });
});

router.post('/settings/update', async (req, res) => {
  const ws = res.locals.workspace;
  const { name } = req.body;
  if (name && name.trim()) {
    await workspaces.updateOne({ _id: ws._id }, { $set: { name: name.trim() } });
    setFlash(req, 'success', 'Workspace updated.');
  }
  res.redirect('/settings');
});

// ═══════════════════════════════════════════════════════════════
// BULK SEND (Legacy Gmail functionality with 1s delay)
// ═══════════════════════════════════════════════════════════════
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

router.get('/bulk-send', async (req, res) => {
  const ws = res.locals.workspace;
  const tmpls = await templates.find({ workspace_id: ws._id }).toArray();
  const idents = await senderIdentities.find({ workspace_id: ws._id, enabled: true }).toArray();
  for (const ident of idents) {
    const dom = await domains.findOne({ _id: new ObjectId(ident.domain_id) });
    ident.domain_name = dom ? dom.domain : 'Unknown';
    ident.domain_verified = dom ? dom.status === 'verified' : false;
  }
  const verifiedIdents = idents.filter(i => i.domain_verified);
  res.render('bulk-send', { templates: tmpls, senderIdentities: verifiedIdents });
});

router.post('/bulk-send', upload.single('file'), async (req, res) => {
  const ws = res.locals.workspace;

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('X-Accel-Buffering', 'no');

  const send = (data) => res.write(JSON.stringify(data) + '\n');

  try {
    const { template_id, sender_identity_id } = req.body;
    const file = req.file;

    if (!file) {
      send({ type: 'error', message: 'No file uploaded' });
      return res.end();
    }

    let rows = [];
    const ext = file.originalname.split('.').pop().toLowerCase();

    if (ext === 'csv') {
      const { parse } = require('csv-parse/sync');
      rows = parse(file.buffer.toString(), { columns: true, skip_empty_lines: true, trim: true });
    } else if (ext === 'xlsx' || ext === 'xls') {
      const XLSX = require('xlsx');
      const wb = XLSX.read(file.buffer, { type: 'buffer' });
      rows = XLSX.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
    } else {
      send({ type: 'error', message: 'Invalid file format. Use CSV or Excel.' });
      return res.end();
    }

    // Find email column
    let emailCol = Object.keys(rows[0] || {}).find(c => c.toLowerCase() === 'email');
    if (!emailCol) emailCol = Object.keys(rows[0] || {}).find(c => c.toLowerCase().includes('email'));
    if (!emailCol) {
      send({ type: 'error', message: 'No "email" column found in file.' });
      return res.end();
    }

    let template;
    try { template = await templates.findOne({ _id: new ObjectId(template_id), workspace_id: ws._id }); } catch {}
    if (!template) {
      send({ type: 'error', message: 'Template not found.' });
      return res.end();
    }

    // Resolve sender identity
    let identity;
    try { identity = await senderIdentities.findOne({ _id: new ObjectId(sender_identity_id), workspace_id: ws._id, enabled: true }); } catch {}
    if (!identity) {
      send({ type: 'error', message: 'Sender identity not found or disabled.' });
      return res.end();
    }
    const senderEmail = identity.email;
    const senderName = identity.display_name || senderEmail.split('@')[0];

    // Use env SMTP credentials
    const smtpHost = process.env.SMTP_HOST || 'smtp.gmail.com';
    const smtpPort = parseInt(process.env.SMTP_PORT || '587');
    const smtpUser = process.env.SMTP_USER || '';
    const smtpPass = process.env.SMTP_PASS || '';

    if (!smtpUser || !smtpPass) {
      send({ type: 'error', message: 'SMTP credentials not configured. Set SMTP_USER and SMTP_PASS in your environment.' });
      return res.end();
    }

    const total = rows.length;
    send({ type: 'info', message: `Starting send for ${total} recipients via ${senderEmail}...`, total });

    const transport = require('nodemailer').createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      auth: { user: smtpUser, pass: smtpPass },
      connectionTimeout: 30000,
    });

    let sentCount = 0, failedCount = 0;

    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (i > 0) {
        // 1-second delay between emails
        await new Promise(resolve => setTimeout(resolve, 1000));
      }

      const recipientEmail = row[emailCol];
      if (!recipientEmail || String(recipientEmail).trim() === '') continue;

      let bodyContent = template.body || '';
      let subjectContent = template.subject || '';
      for (const col of Object.keys(row)) {
        const placeholder = `{{${col}}}`;
        bodyContent = bodyContent.split(placeholder).join(String(row[col] || ''));
        subjectContent = subjectContent.split(placeholder).join(String(row[col] || ''));
      }

      const emailId = generateId('email');

      try {
        await transport.sendMail({
          from: `"${senderName}" <${senderEmail}>`,
          to: String(recipientEmail).trim(),
          subject: subjectContent,
          text: bodyContent,
        });

        await emails.insertOne({
          workspace_id: ws._id, email_id: emailId, from_email: senderEmail, from_name: senderName,
          to: [String(recipientEmail).trim()], subject: subjectContent,
          html: bodyContent, text: bodyContent, status: 'delivered',
          provider: 'gmail_bulk', created_at: new Date(),
        });

        sentCount++;
        send({ type: 'success', message: `Sent to ${recipientEmail}`, sent: sentCount, failed: failedCount, total });
      } catch (err) {
        failedCount++;
        send({ type: 'error', message: `Failed: ${recipientEmail} — ${err.message}`, sent: sentCount, failed: failedCount, total });
      }
    }

    try { await transport.close(); } catch {}
    send({ type: 'done', sent: sentCount, failed: failedCount, total });
    res.end();

  } catch (err) {
    send({ type: 'error', message: `Critical Error: ${err.message}` });
    res.end();
  }
});

// ═══════════════════════════════════════════════════════════════
// API STATS (JSON)
// ═══════════════════════════════════════════════════════════════
router.get('/api/stats', async (req, res) => {
  const ws = res.locals.workspace;
  const now = new Date();
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);

  const [total, delivered, failed, month] = await Promise.all([
    emails.countDocuments({ workspace_id: ws._id }),
    emails.countDocuments({ workspace_id: ws._id, status: 'delivered' }),
    emails.countDocuments({ workspace_id: ws._id, status: 'failed' }),
    emails.countDocuments({ workspace_id: ws._id, created_at: { $gte: monthStart } }),
  ]);

  res.json({
    total_emails: total, delivered, failed, month_emails: month,
    delivery_rate: total > 0 ? Math.round((delivered / total) * 1000) / 10 : 0,
  });
});

// GET /api/bulk-status — returns queue stats
router.get('/api/bulk-status', (req, res) => {
  const ws = res.locals.workspace;
  const stats = bulkQueue.getStats(ws._id.toString());
  res.json(stats || { sent: 0, failed: 0, total: 0 });
});

module.exports = router;
