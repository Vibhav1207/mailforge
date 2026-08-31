const nodemailer = require('nodemailer');
const { emails, emailEvents, webhooks, webhookLogs } = require('../db');
const { generateId, signWebhook } = require('../helpers');

const SMTP_HOST = process.env.SMTP_HOST || 'smtp.gmail.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '587');
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const FROM_NAME = process.env.FROM_NAME || 'MailForge';

// Create reusable transporter
let transporter = null;

function getTransporter() {
  if (!transporter && SMTP_USER) {
    transporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
      connectionTimeout: 30000,
      greetingTimeout: 10000,
    });
  }
  return transporter;
}

// Process a single email
async function processEmail(emailId) {
  const email = await emails.findOne({ email_id: emailId });
  if (!email) return;

  // Mark as processing
  await emails.updateOne(
    { email_id: emailId },
    { $set: { status: 'processing' }, $inc: { attempts: 1 } }
  );

  await emailEvents.insertOne({
    email_id: emailId,
    workspace_id: email.workspace_id,
    event: 'processing',
    timestamp: new Date(),
    details: {}
  });

  const transport = getTransporter();
  if (!transport) {
    await failEmail(emailId, email.workspace_id, 'SMTP credentials not configured. Set SMTP_USER and SMTP_PASS.');
    return;
  }

  try {
    const mailOptions = {
      from: `"${email.from_name || FROM_NAME}" <${email.from_email}>`,
      to: email.to.join(', '),
      subject: email.subject,
      messageId: `<${emailId}@mailforge.io>`,
      headers: { 'X-Mailer': 'MailForge/2.0' },
    };

    if (email.reply_to) mailOptions.replyTo = email.reply_to;
    if (email.text && email.html) {
      mailOptions.text = email.text;
      mailOptions.html = email.html;
    } else if (email.html) {
      mailOptions.html = email.html;
    } else if (email.text) {
      mailOptions.text = email.text;
    }

    await transport.sendMail(mailOptions);

    // Mark sent
    await emails.updateOne(
      { email_id: emailId },
      { $set: { status: 'sent', sent_at: new Date(), last_error: null } }
    );

    await emailEvents.insertOne({
      email_id: emailId,
      workspace_id: email.workspace_id,
      event: 'sent',
      timestamp: new Date(),
      details: { recipient_count: email.to.length }
    });

    // Mark delivered (simplified — in production use DSN/webhooks)
    await emails.updateOne(
      { email_id: emailId },
      { $set: { status: 'delivered', delivered_at: new Date() } }
    );

    await emailEvents.insertOne({
      email_id: emailId,
      workspace_id: email.workspace_id,
      event: 'delivered',
      timestamp: new Date(),
      details: {}
    });

    // Fire webhooks
    await fireWebhooks(email.workspace_id, 'email.delivered', {
      email_id: emailId,
      from: email.from_email,
      to: email.to,
      subject: email.subject,
      timestamp: new Date().toISOString()
    });

  } catch (err) {
    const errorMsg = err.message || String(err);
    const attempt = email.attempts || 1;
    const maxAttempts = email.max_attempts || 3;

    if (attempt < maxAttempts && isRetryableError(errorMsg)) {
      // Re-queue for retry
      await emails.updateOne(
        { email_id: emailId },
        { $set: { status: 'queued', last_error: errorMsg } }
      );
    } else {
      await failEmail(emailId, email.workspace_id, errorMsg);
    }
  }
}

async function failEmail(emailId, workspaceId, errorMsg) {
  await emails.updateOne(
    { email_id: emailId },
    { $set: { status: 'failed', last_error: errorMsg.slice(0, 500) } }
  );

  await emailEvents.insertOne({
    email_id: emailId,
    workspace_id: workspaceId,
    event: 'failed',
    timestamp: new Date(),
    details: { error: errorMsg.slice(0, 500) }
  });

  await fireWebhooks(workspaceId, 'email.failed', {
    email_id: emailId,
    error: errorMsg.slice(0, 200),
    timestamp: new Date().toISOString()
  });
}

function isRetryableError(msg) {
  const lower = msg.toLowerCase();
  return ['connection', 'timeout', 'temporary', 'try again', 'busy', 'pipe', 'connect'].some(r => lower.includes(r));
}

// Bulk send queue with 1-second delay between emails
class BulkEmailQueue {
  constructor() {
    this.queues = new Map(); // workspaceId -> { items: [], processing: false, stats: { sent, failed, total } }
  }

  enqueue(workspaceId, items) {
    if (this.queues.has(workspaceId)) {
      // Append to existing queue
      const q = this.queues.get(workspaceId);
      q.items.push(...items);
      q.stats.total += items.length;
      return q.stats;
    }

    const stats = { sent: 0, failed: 0, total: items.length, startedAt: new Date() };
    this.queues.set(workspaceId, { items, processing: false, stats });
    this._process(workspaceId);
    return stats;
  }

  getStats(workspaceId) {
    const q = this.queues.get(workspaceId);
    return q ? q.stats : null;
  }

  async _process(workspaceId) {
    const q = this.queues.get(workspaceId);
    if (!q || q.processing) return;
    q.processing = true;

    const transport = getTransporter();

    while (q.items.length > 0) {
      const item = q.items.shift();

      try {
        if (!transport) {
          q.stats.failed++;
          continue;
        }

        const mailOptions = {
          from: item.from,
          to: item.to,
          subject: item.subject,
          html: item.html,
          text: item.text || '',
          messageId: `<${item.emailId}@mailforge.io>`,
          headers: { 'X-Mailer': 'MailForge/2.0-Bulk' },
        };

        await transport.sendMail(mailOptions);

        await emails.updateOne(
          { email_id: item.emailId },
          { $set: { status: 'sent', sent_at: new Date() } }
        );
        await emails.updateOne(
          { email_id: item.emailId },
          { $set: { status: 'delivered', delivered_at: new Date() } }
        );
        await emailEvents.insertOne({
          email_id: item.emailId,
          workspace_id: workspaceId,
          event: 'delivered',
          timestamp: new Date(),
          details: {}
        });

        q.stats.sent++;
      } catch (err) {
        q.stats.failed++;
        await emails.updateOne(
          { email_id: item.emailId },
          { $set: { status: 'failed', last_error: (err.message || '').slice(0, 500) } }
        );
      }

      // 1-second delay between emails in bulk
      if (q.items.length > 0) {
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    q.stats.completedAt = new Date();
    q.processing = false;
  }
}

const bulkQueue = new BulkEmailQueue();

// Fire webhooks for an event
async function fireWebhooks(workspaceId, eventType, payload) {
  const hooks = await webhooks.find({
    workspace_id: workspaceId,
    enabled: true,
    events: eventType
  }).toArray();

  for (const hook of hooks) {
    try {
      const sig = signWebhook(payload, hook.secret);
      await fetch(hook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Webhook-Signature': sig,
          'User-Agent': 'MailForge-Webhook/2.0',
        },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10000),
      });

      await webhookLogs.insertOne({
        webhook_id: hook._id,
        workspace_id: workspaceId,
        event: eventType,
        status: 'success',
        payload,
        timestamp: new Date()
      });
    } catch (err) {
      await webhookLogs.insertOne({
        webhook_id: hook._id,
        workspace_id: workspaceId,
        event: eventType,
        status: 'failed',
        error: (err.message || '').slice(0, 500),
        payload,
        timestamp: new Date()
      });
    }
  }
}

module.exports = { processEmail, bulkQueue, fireWebhooks, getTransporter };
