import { EmailTemplate } from "@/types";

export const PREBUILT_TEMPLATES: EmailTemplate[] = [
  {
    id: "tpl_outreach",
    userId: null,
    name: "Professional B2B Outreach",
    description: "Concise, high-converting cold outreach email for partnerships and sales.",
    category: "outreach",
    subject: "Quick question regarding {{company}}'s email strategy",
    isDefault: true,
    createdAt: "2026-01-01T00:00:00.000Z",
    htmlContent: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Quick question</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f8fafc; margin: 0; padding: 24px 0; }
    .container { max-width: 580px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 32px 28px; }
    p { margin: 0 0 16px; font-size: 15px; }
    .btn { display: inline-block; background: #2563eb; color: #ffffff !important; text-decoration: none; padding: 10px 22px; border-radius: 6px; font-weight: 500; font-size: 14px; margin-top: 8px; }
    .footer { margin-top: 32px; padding-top: 20px; border-top: 1px solid #f1f5f9; font-size: 12px; color: #64748b; }
    .footer a { color: #64748b; text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <p>Hi {{firstName}},</p>
    <p>I noticed your recent work at <strong>{{company}}</strong> and wanted to reach out directly.</p>
    <p>We've been helping engineering and marketing teams scale their transactional and bulk email infrastructure with verified deliverability, zero queue latency, and automated suppression lists.</p>
    <p>Are you available for a brief 10-minute sync this Thursday to explore if this could streamline operations for {{company}}?</p>
    <p>
      <a href="https://example.com/calendar" class="btn">Schedule a 10-Min Call</a>
    </p>
    <p style="margin-top: 24px;">Best regards,<br><strong>{{fromName}}</strong></p>
    <div class="footer">
      <p>You received this message because of your profile at {{company}}. If you would rather not receive these emails, you can <a href="{{unsubscribeUrl}}">unsubscribe here</a>.</p>
    </div>
  </div>
</body>
</html>`,
    textContent: `Hi {{firstName}},

I noticed your recent work at {{company}} and wanted to reach out directly.

We've been helping engineering and marketing teams scale their email infrastructure with verified deliverability, zero queue latency, and automated suppression lists.

Are you available for a brief 10-minute sync this Thursday to explore if this could streamline operations for {{company}}?

Schedule a call: https://example.com/calendar

Best regards,
{{fromName}}

Unsubscribe: {{unsubscribeUrl}}`
  },
  {
    id: "tpl_event",
    userId: null,
    name: "VIP Event & Webinar Invitation",
    description: "Sleek invitation layout with date badges, hero highlights, and RSVP call to action.",
    category: "event",
    subject: "Invitation: Exclusive Product Architecture Keynote for {{firstName}}",
    createdAt: "2026-01-01T00:00:00.000Z",
    htmlContent: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Event Invitation</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background-color: #f1f5f9; margin: 0; padding: 24px 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; overflow: hidden; }
    .header { background: #0f172a; padding: 36px 32px; text-align: center; color: #ffffff; }
    .badge { display: inline-block; background: #3b82f6; color: #ffffff; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; padding: 4px 12px; border-radius: 9999px; font-weight: 600; margin-bottom: 12px; }
    .content { padding: 36px 32px; }
    .highlight-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 24px 0; }
    .btn { display: block; text-align: center; background: #2563eb; color: #ffffff !important; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-weight: 600; font-size: 15px; margin: 24px 0 12px; }
    .footer { padding: 24px 32px; background: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="badge">Virtual Summit 2026</div>
      <h1 style="margin: 0; font-size: 24px; font-weight: 700;">Scaling Modern Developer Infrastructure</h1>
    </div>
    <div class="content">
      <p style="font-size: 16px;">Dear {{firstName}},</p>
      <p>We're extending a reserved seat to leaders from <strong>{{company}}</strong> for our live interactive briefing on building resilient, high-volume communications backends.</p>
      <div class="highlight-box">
        <p style="margin: 0 0 8px; font-weight: 600; color: #0f172a;">📅 Date & Time: Thursday, Nov 5 · 1:00 PM EST</p>
        <p style="margin: 0 0 8px; color: #475569;">📍 Location: Live Interactive Stream (Access link provided on RSVP)</p>
        <p style="margin: 0; color: #475569;">🎙️ Speakers: Infrastructure Leads & Distributed Systems Engineers</p>
      </div>
      <p>Seats are limited to ensure direct Q&A availability for all registered teams.</p>
      <a href="https://example.com/rsvp" class="btn">Confirm Your Free Registration</a>
      <p style="font-size: 13px; color: #64748b; text-align: center; margin: 0;">Registration includes recorded replay and architecture blueprints.</p>
    </div>
    <div class="footer">
      <p style="margin: 0;">Sent to {{email}} for {{company}}. <a href="{{unsubscribeUrl}}">Manage email preferences or unsubscribe</a>.</p>
    </div>
  </div>
</body>
</html>`,
    textContent: `Virtual Summit 2026: Scaling Modern Developer Infrastructure

Dear {{firstName}},

We're extending a reserved seat to leaders from {{company}} for our live interactive briefing on building resilient, high-volume communications backends.

Date: Thursday, Nov 5 · 1:00 PM EST
Location: Live Interactive Stream
Speakers: Infrastructure Leads & Distributed Systems Engineers

Confirm your registration: https://example.com/rsvp

Sent to {{email}} for {{company}}. Unsubscribe: {{unsubscribeUrl}}`
  },
  {
    id: "tpl_announcement",
    userId: null,
    name: "Product Announcement & Major Release",
    description: "Modern product launch layout highlighting new capabilities with clean feature cards.",
    category: "announcement",
    subject: "Introducing MailForge 3.0: Built for {{company}}",
    createdAt: "2026-01-01T00:00:00.000Z",
    htmlContent: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Product Announcement</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #0f172a; background-color: #f8fafc; margin: 0; padding: 24px 0; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 40px 32px; }
    .title { font-size: 26px; font-weight: 800; letter-spacing: -0.5px; margin: 0 0 12px; }
    .feature-card { background: #f8fafc; border-left: 4px solid #2563eb; padding: 16px; margin: 16px 0; border-radius: 0 8px 8px 0; }
    .feature-card h3 { margin: 0 0 4px; font-size: 15px; color: #0f172a; }
    .feature-card p { margin: 0; font-size: 13.5px; color: #475569; }
    .cta { display: inline-block; background: #0f172a; color: #ffffff !important; text-decoration: none; padding: 12px 26px; border-radius: 6px; font-weight: 600; font-size: 14px; margin-top: 16px; }
    .footer { margin-top: 36px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; }
  </style>
</head>
<body>
  <div class="container">
    <div style="font-size: 12px; font-weight: 700; color: #2563eb; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Product Update</div>
    <h1 class="title">Everything is faster. Introducing MailForge 3.0.</h1>
    <p style="font-size: 15px; color: #334155;">Hello {{firstName}}, we've completely re-architected our bulk delivery engine to give {{company}} the highest deliverability rates in the industry.</p>
    
    <div class="feature-card">
      <h3>🚀 Verified High-Deliverability Engine</h3>
      <p>Send thousands of transactional and broadcast emails in parallel with automated retry and backoff.</p>
    </div>

    <div class="feature-card">
      <h3>🛡️ Real-Time Bounce & Suppression Guard</h3>
      <p>Strictly excludes unsubscribed, complained, or bounced contacts automatically before sending.</p>
    </div>

    <div class="feature-card">
      <h3>⚡ Instant CSV Ingestion & Mapping</h3>
      <p>Drag, drop, and match contact lists in seconds with automated deduplication.</p>
    </div>

    <a href="https://example.com/app" class="cta">Explore the New Dashboard</a>

    <div class="footer">
      <p>You received this announcement as a registered contact at {{company}}. <a href="{{unsubscribeUrl}}">Unsubscribe</a></p>
    </div>
  </div>
</body>
</html>`,
    textContent: `Product Update: Introducing MailForge 3.0

Hello {{firstName}}, we've completely re-architected our bulk delivery engine to give {{company}} the highest deliverability rates in the industry.

New Features:
1. Verified High-Deliverability Engine
2. Real-Time Bounce & Suppression Guard
3. Instant CSV Ingestion & Mapping

Explore the dashboard: https://example.com/app

Unsubscribe: {{unsubscribeUrl}}`
  },
  {
    id: "tpl_followup",
    userId: null,
    name: "Polite & Direct Follow-Up",
    description: "Natural, non-intrusive follow-up message to bump an earlier conversation.",
    category: "followup",
    subject: "Following up: Quick question for {{firstName}}",
    createdAt: "2026-01-01T00:00:00.000Z",
    htmlContent: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Follow Up</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #1e293b; background: #ffffff; padding: 24px; }
    p { margin: 0 0 16px; font-size: 15px; }
    .footer { margin-top: 36px; padding-top: 16px; border-top: 1px solid #f1f5f9; font-size: 12px; color: #94a3b8; }
  </style>
</head>
<body>
  <p>Hi {{firstName}},</p>
  <p>I know how full inboxes get, so I wanted to briefly circle back on my note from last week regarding {{company}}'s sending workflow.</p>
  <p>If you're already satisfied with your current delivery setup, no worries at all! But if you're experiencing email clipping, deliverability drops, or queue lag, I'd love to share how teams similar to {{company}} solved it in 15 minutes.</p>
  <p>Would you like me to send over our quick 2-page benchmark guide?</p>
  <p>Best regards,<br><strong>{{fromName}}</strong></p>
  <div class="footer">
    <p>Sent to {{email}}. Not interested? <a href="{{unsubscribeUrl}}" style="color: #94a3b8;">Unsubscribe</a>.</p>
  </div>
</body>
</html>`,
    textContent: `Hi {{firstName}},

I know how full inboxes get, so I wanted to briefly circle back on my note from last week regarding {{company}}'s sending workflow.

If you're already satisfied with your current delivery setup, no worries at all! But if you're experiencing email clipping or deliverability drops, I'd love to share how teams similar to {{company}} solved it in 15 minutes.

Would you like me to send over our quick 2-page benchmark guide?

Best regards,
{{fromName}}

Unsubscribe: {{unsubscribeUrl}}`
  },
  {
    id: "tpl_newsletter",
    userId: null,
    name: "Engineering & Product Newsletter",
    description: "Crisp editorial newsletter template with structured digest sections and clean links.",
    category: "newsletter",
    subject: "{{company}} Weekly Digest: Infrastructure Insights",
    createdAt: "2026-01-01T00:00:00.000Z",
    htmlContent: `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Newsletter</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #0f172a; background-color: #f8fafc; margin: 0; padding: 24px 0; }
    .container { max-width: 620px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 36px 30px; }
    .header { border-bottom: 2px solid #0f172a; padding-bottom: 16px; margin-bottom: 24px; }
    .digest-item { margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid #f1f5f9; }
    .digest-title { font-size: 17px; font-weight: 700; color: #0f172a; margin: 0 0 6px; }
    .digest-title a { color: #0f172a; text-decoration: none; }
    .digest-title a:hover { color: #2563eb; }
    .digest-body { font-size: 14px; color: #475569; margin: 0; }
    .footer { margin-top: 32px; font-size: 12px; color: #64748b; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: #2563eb;">Issue #42 · October Edition</div>
      <h1 style="margin: 4px 0 0; font-size: 22px; font-weight: 800;">The Infrastructure Dispatch</h1>
    </div>

    <p style="font-size: 15px; color: #334155;">Good morning {{firstName}}, here are top engineering strategies for high-performance messaging teams at {{company}}.</p>

    <div class="digest-item">
      <h2 class="digest-title"><a href="https://example.com/post-1">1. Zero-Downtime Migration from SMTP to Modern APIs</a></h2>
      <p class="digest-body">How leading teams eliminate socket bottlenecks and improve sender reputation using domain verification and instant API batching.</p>
    </div>

    <div class="digest-item">
      <h2 class="digest-title"><a href="https://example.com/post-2">2. Handling 100k Recipient Bursts in Serverless Runtimes</a></h2>
      <p class="digest-body">Architectural patterns for rate limiting, exponential backoff, and idempotent event ingestion on Next.js and Vercel.</p>
    </div>

    <div class="digest-item" style="border-bottom: none; margin-bottom: 0;">
      <h2 class="digest-title"><a href="https://example.com/post-3">3. Deliverability Rules: DKIM, DMARC & Unsubscribe Headers</a></h2>
      <p class="digest-body">An updated checklist for compliance with Gmail & Yahoo inbox deliverability rules.</p>
    </div>

    <div class="footer">
      <p>Curated with care by {{fromName}}. Sent to {{email}}.<br>
      <a href="{{unsubscribeUrl}}" style="color: #2563eb;">Unsubscribe from this newsletter</a></p>
    </div>
  </div>
</body>
</html>`,
    textContent: `The Infrastructure Dispatch · Issue #42

Good morning {{firstName}}, here are top engineering strategies for high-performance messaging teams at {{company}}.

1. Zero-Downtime Migration from SMTP to Modern APIs: https://example.com/post-1
2. Handling 100k Recipient Bursts in Serverless Runtimes: https://example.com/post-2
3. Deliverability Rules: DKIM, DMARC & Unsubscribe Headers: https://example.com/post-3

Curated with care by {{fromName}}.
Unsubscribe: {{unsubscribeUrl}}`
  }
];
