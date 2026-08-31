const express = require('express');
const router = express.Router();
const { ObjectId } = require('mongodb');
const {
  domains, senderIdentities, apiKeys, emails, emailEvents, templates, rateLimits
} = require('../db');
const { generateId, hashApiKey } = require('../helpers');
const { processEmail } = require('../services/email');

// ═══════════════════════════════════════════════════════════════
// API Key Authentication Middleware
// ═══════════════════════════════════════════════════════════════
async function authenticateApiKey(req, res, next) {
  const authHeader = req.headers.authorization || '';
  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: { type: 'authentication_required', message: 'Missing or invalid Authorization header. Use: Bearer sk_live_xxxxx' }
    });
  }

  const rawKey = authHeader.slice(7).trim();
  if (!rawKey.startsWith('sk_live_')) {
    return res.status(401).json({
      error: { type: 'invalid_api_key', message: 'Invalid API key format.' }
    });
  }

  const keyHash = hashApiKey(rawKey);
  const key = await apiKeys.findOne({ key_hash: keyHash, revoked: false });
  if (!key) {
    return res.status(401).json({
      error: { type: 'invalid_api_key', message: 'Invalid or revoked API key.' }
    });
  }

  // Update last used
  await apiKeys.updateOne({ _id: key._id }, { $set: { last_used: new Date() } });

  req.apiKey = key;
  req.workspaceId = key.workspace_id;
  next();
}

// ═══════════════════════════════════════════════════════════════
// POST /v1/emails — Send an email
// ═══════════════════════════════════════════════════════════════
router.post('/v1/emails', authenticateApiKey, async (req, res) => {
  try {
    const data = req.body;
    if (!data) {
      return res.status(400).json({ error: { type: 'invalid_request', message: 'Request body is required.' } });
    }

    const fromEmail = (data.from || '').trim();
    const toEmails = data.to || [];
    const subject = (data.subject || '').trim();
    const htmlBody = data.html || '';
    const textBody = data.text || '';
    const templateId = data.template_id;
    const variables = data.variables || {};
    const replyTo = data.reply_to || '';
    const tags = data.tags || [];
    const metadata = data.metadata || {};

    // Validate required fields
    if (!fromEmail) return res.status(400).json({ error: { type: 'validation_error', message: '"from" is required.' } });
    if (!Array.isArray(toEmails) || toEmails.length === 0) return res.status(400).json({ error: { type: 'validation_error', message: '"to" must be a non-empty array.' } });
    if (!subject && !templateId) return res.status(400).json({ error: { type: 'validation_error', message: '"subject" or "template_id" is required.' } });
    if (!htmlBody && !textBody && !templateId) return res.status(400).json({ error: { type: 'validation_error', message: '"html", "text", or "template_id" is required.' } });

    // Validate sender domain belongs to workspace
    const senderDomain = fromEmail.split('@')[1];
    const domain = await domains.findOne({ workspace_id: req.workspaceId, domain: senderDomain, status: 'verified' });
    if (!domain) {
      return res.status(400).json({ error: { type: 'invalid_sender', message: `Sender domain "${senderDomain}" is not verified in your workspace.` } });
    }

    // Check sender identity
    const identity = await senderIdentities.findOne({ workspace_id: req.workspaceId, email: fromEmail.toLowerCase(), enabled: true });

    // Resolve template
    let finalSubject = subject;
    let finalHtml = htmlBody;
    let finalText = textBody;

    if (templateId) {
      let tmpl;
      try { tmpl = await templates.findOne({ _id: new ObjectId(templateId), workspace_id: req.workspaceId }); } catch {}
      if (!tmpl) return res.status(400).json({ error: { type: 'invalid_template', message: 'Template not found.' } });

      finalSubject = tmpl.subject || '';
      finalHtml = tmpl.html_body || tmpl.body || '';

      for (const [key, value] of Object.entries(variables)) {
        const placeholder = `{{${key}}}`;
        finalSubject = finalSubject.split(placeholder).join(String(value));
        finalHtml = finalHtml.split(placeholder).join(String(value));
      }
    }

    // Create email record
    const emailId = generateId('email');
    const emailDoc = {
      workspace_id: req.workspaceId,
      email_id: emailId,
      from_email: fromEmail.toLowerCase(),
      from_name: identity ? identity.display_name : (data.from_name || fromEmail.split('@')[0]),
      to: toEmails.map(e => String(e).trim().toLowerCase()),
      cc: (data.cc || []).map(e => String(e).trim().toLowerCase()),
      bcc: (data.bcc || []).map(e => String(e).trim().toLowerCase()),
      subject: finalSubject,
      html: finalHtml,
      text: finalText,
      reply_to: replyTo || (identity ? identity.reply_to : ''),
      status: 'queued',
      provider: 'smtp',
      attempts: 0,
      max_attempts: 3,
      last_error: null,
      created_at: new Date(),
      sent_at: null,
      delivered_at: null,
      tags,
      metadata,
    };

    await emails.insertOne(emailDoc);

    // Create initial event
    await emailEvents.insertOne({
      email_id: emailId,
      workspace_id: req.workspaceId,
      event: 'queued',
      timestamp: new Date(),
      details: {},
    });

    // Process email async
    processEmail(emailId).catch(() => {});

    return res.status(200).json({
      id: emailId,
      status: 'queued',
      from: fromEmail,
      to: toEmails,
      subject: finalSubject,
      created_at: emailDoc.created_at.toISOString(),
    });

  } catch (err) {
    return res.status(500).json({ error: { type: 'internal_error', message: 'An unexpected error occurred.' } });
  }
});

// ═══════════════════════════════════════════════════════════════
// GET /v1/emails — List emails
// ═══════════════════════════════════════════════════════════════
router.get('/v1/emails', authenticateApiKey, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const offset = Math.max(parseInt(req.query.offset) || 0, 0);

    const emailList = await emails.find({ workspace_id: req.workspaceId })
      .sort({ created_at: -1 })
      .skip(offset)
      .limit(limit)
      .toArray();

    const result = emailList.map(e => ({
      id: e.email_id,
      from: e.from_email,
      to: e.to,
      subject: e.subject,
      status: e.status,
      created_at: e.created_at.toISOString(),
    }));

    return res.json({ emails: result, count: result.length });
  } catch (err) {
    return res.status(500).json({ error: { type: 'internal_error', message: 'Failed to list emails.' } });
  }
});

// ═══════════════════════════════════════════════════════════════
// GET /v1/emails/:id — Get email details
// ═══════════════════════════════════════════════════════════════
router.get('/v1/emails/:id', authenticateApiKey, async (req, res) => {
  try {
    const email = await emails.findOne({ email_id: req.params.id, workspace_id: req.workspaceId });
    if (!email) {
      return res.status(404).json({ error: { type: 'not_found', message: 'Email not found.' } });
    }

    const events = await emailEvents.find({ email_id: req.params.id }).sort({ timestamp: 1 }).toArray();

    return res.json({
      id: email.email_id,
      from: email.from_email,
      to: email.to,
      subject: email.subject,
      status: email.status,
      created_at: email.created_at.toISOString(),
      sent_at: email.sent_at ? email.sent_at.toISOString() : null,
      delivered_at: email.delivered_at ? email.delivered_at.toISOString() : null,
      events: events.map(e => ({
        event: e.event,
        timestamp: e.timestamp.toISOString(),
        details: e.details,
      })),
    });
  } catch (err) {
    return res.status(500).json({ error: { type: 'internal_error', message: 'Failed to get email.' } });
  }
});

// ═══════════════════════════════════════════════════════════════
// GET /v1/health — Health check
// ═══════════════════════════════════════════════════════════════
router.get('/v1/health', (req, res) => {
  res.json({ status: 'ok', service: 'MailForge API', version: '2.0.0' });
});

module.exports = router;
