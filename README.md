# MailForge — Enterprise Bulk Email Platform

> Production-grade bulk email dispatch platform built with **Next.js 15+ (App Router)**, **TypeScript**, **Firebase Google Authentication**, **Gmail Google App Password SMTP Engine**, and **MongoDB**.

MailForge enables organizations, developer teams, and marketing operators to compose, personalize, manage, and dispatch bulk email campaigns with verified deliverability, automated suppression lists, MongoDB template folder image storage, and real-time delivery telemetry.

---

## Key Features

- **Google Authentication via Firebase:** Official `GoogleAuthProvider` integration (`signInWithPopup`), server-side token validation via Firebase Admin SDK (`verifyIdToken`), and automatic user profile sync.
- **Gmail Google App Password & Custom SMTP Engine:**
  - Connect personal or Google Workspace accounts using a standard 16-character Google App Password (`smtp.gmail.com:465`).
  - Zero third-party subscriber limits, quotas, or credit-card tiers.
  - Verification endpoint (`/api/smtp/verify`) with instant connection testing and error diagnosis.
  - Optional custom SMTP support (Brevo, AWS SES, Postmark, or private mail hosts).
- **MongoDB Template & Image Asset Storage:**
  - Store email templates and organize template banner images into customizable folders (`newsletters`, `banners`, `promotions`).
  - Upload images directly into MongoDB via `/api/templates/images` with instant URL serving.
  - One-click insertion of responsive image tags into HTML email templates.
- **Bulk Email Composer:**
  - Multiple recipient input mechanisms: comma/newline/space paste, CSV file upload with automated column mapping, and saved contact list selection.
  - Automatic address deduplication and RFC 5322 regex validation.
  - Variable interpolation (`{{firstName}}`, `{{lastName}}`, `{{company}}`, `{{email}}`, plus custom CSV fields).
  - Dual-mode editor: Visual Rich-Text editor and Raw HTML code mode.
  - Pre-built responsive HTML templates (Outreach, Webinar/Event, Product Launch, Follow-Up, Newsletter).
  - Plain-text fallback auto-generation.
  - Interactive personalized preview with recipient switcher.
  - Instant test email delivery to the authenticated user.
  - Debounced auto-save draft functionality.
- **Audience & Contact Management:**
  - Full CRUD operations with search, list tagging, and status filtering.
  - CSV Import and CSV Export.
  - Strict exclusion of unsubscribed, bounced, or suppressed contacts prior to dispatch.
- **Campaign Execution & Delivery Engine:**
  - Immediate send and future date/time scheduling.
  - Server-side chunked batching with throttled rate-limiting and exponential backoff retry.
  - Idempotency keys per campaign to prevent accidental duplicate dispatches.
  - Single-click retry for transient failures without resending previously accepted messages.
- **Security & Compliance:**
  - Automated CAN-SPAM and GDPR unsubscribe footer injection with public opt-out portal (`/unsubscribe`).
  - Hard bounces and spam complaints automatically registered in suppression lists.
  - Zero exposure of provider credentials in client-side bundles.

---

## Technology Stack

| Layer | Technology |
|---|---|
| **Framework** | Next.js 15+ (App Router) |
| **Language** | TypeScript (Strict Mode) |
| **Styling** | Tailwind CSS (Zinc / Slate SaaS theme) |
| **Authentication** | Firebase Authentication (Google Sign-In) |
| **Database (Primary & Storage)** | MongoDB (`mongodb` driver) & Firebase Firestore |
| **Email Infrastructure** | Gmail SMTP (Google App Password) & Nodemailer |
| **CSV Parsing** | PapaParse (`papaparse`) |
| **Icons** | Lucide React |
| **Deployment Target** | Vercel |

---

## Project Structure

```
├── firestore.rules               # Production Firestore security rules
├── firestore.indexes.json        # Composite indexes for contacts & campaigns
├── .env.example                  # Environment template with complete instructions
├── src/
│   ├── app/
│   │   ├── api/
│   │   │   ├── campaigns/send/   # POST: Server batch dispatcher & suppression check
│   │   │   ├── campaigns/[id]/retry/ # POST: Transient failure retry
│   │   │   ├── send-test/        # POST: Instant preview test email
│   │   │   ├── unsubscribe/      # POST: Public opt-out handler
│   │   │   └── webhooks/resend/  # POST: Svix-verified webhook handler
│   │   ├── dashboard/
│   │   │   ├── compose/          # Bulk email composition & staging
│   │   │   ├── contacts/         # Audience management & CSV import/export
│   │   │   ├── campaigns/        # Campaign listing & draft management
│   │   │   ├── campaigns/[id]/   # Detailed delivery reports & audit logs
│   │   │   ├── templates/        # Responsive email template gallery & custom editor
│   │   │   ├── history/          # Historical analytics & delivery breakdowns
│   │   │   ├── settings/         # Sender identities, compliance & webhooks
│   │   │   ├── layout.tsx        # Dashboard shell & responsive navigation
│   │   │   └── page.tsx          # Real-time dashboard KPI overview
│   │   ├── unsubscribe/          # Public recipient unsubscribe page
│   │   ├── layout.tsx            # Global layout with font & AuthProvider
│   │   └── page.tsx              # Landing page with Google Sign-In & Demo mode
│   ├── context/
│   │   └── auth-context.tsx      # Firebase auth provider, session state & cookie sync
│   ├── lib/
│   │   ├── email/
│   │   │   ├── provider.ts       # Resend batch client, retries, and rate limiting
│   │   │   └── templates.ts      # 5 pre-built responsive HTML email templates
│   │   ├── firebase/
│   │   │   ├── client.ts         # Firebase client SDK initialization
│   │   │   ├── admin.ts          # Firebase Admin SDK initialization
│   │   │   └── auth-middleware.ts # Server-side ID token verification middleware
│   │   ├── store/
│   │   │   └── db-service.ts     # Firestore CRUD services with offline demo fallback
│   │   └── utils.ts              # RFC email regex, CSV tokenizer, variable interpolation
│   └── types/
│       └── index.ts              # Complete TypeScript interfaces
```

---

## Getting Started

### 1. Prerequisites
- Node.js 18+ or Node.js 20+
- npm, yarn, or pnpm
- A Firebase project (free tier is sufficient)
- A Resend account (free tier includes 3,000 emails/month)

### 2. Clone and Install Dependencies

```bash
git clone <repository-url>
cd email-sender
npm install
```

### 3. Configure Environment Variables

Copy the template file to `.env.local`:

```bash
cp .env.example .env.local
```

Fill in your project credentials:

#### A. Firebase Configuration
1. Go to the [Firebase Console](https://console.firebase.google.com/).
2. Create a new project or select an existing one.
3. Enable **Authentication** > **Sign-in method** > **Google** (Click Enable and Save).
4. Go to **Project Settings** > **General** > **Your apps** > Add a Web App (`</>`).
5. Copy the configuration values into `.env.local`:
   - `NEXT_PUBLIC_FIREBASE_API_KEY`
   - `NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN`
   - `NEXT_PUBLIC_FIREBASE_PROJECT_ID`
   - `NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET`
   - `NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID`
   - `NEXT_PUBLIC_FIREBASE_APP_ID`
6. Create a Firestore Database in production or test mode:
   - **Firestore Database** > **Create database**.
   - Deploy `firestore.rules` and `firestore.indexes.json` using the Firebase CLI (`firebase deploy --only firestore`).
7. Generate Firebase Admin SDK credentials:
   - Go to **Project Settings** > **Service Accounts** > **Generate new private key**.
   - Download the JSON file and copy:
     - `FIREBASE_PROJECT_ID`
     - `FIREBASE_CLIENT_EMAIL`
     - `FIREBASE_PRIVATE_KEY` (ensure `\n` linebreaks are preserved inside double quotes).

#### B. Resend Configuration
1. Go to [Resend Dashboard](https://resend.com/api-keys) and generate an API key (`re_...`).
2. Add your verified sender domain or use the default sandbox identity for testing:
   ```env
   RESEND_API_KEY=re_your_api_key_here
   RESEND_FROM_EMAIL=onboarding@resend.dev
   RESEND_FROM_NAME="MailForge Notifications"
   ```
3. Set up the Webhook endpoint (Optional but recommended):
   - In Resend, go to **Webhooks** > **Add Webhook**.
   - Enter your URL: `https://your-domain.vercel.app/api/webhooks/resend`.
   - Subscribe to events: `email.delivered`, `email.bounced`, `email.complained`.
   - Copy the Signing Secret into `.env.local`:
     ```env
     RESEND_WEBHOOK_SECRET=whsec_your_secret_here
     ```

---

## Local Development

Start the development server:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

> **Offline / Demo Mode:** If Firebase credentials are not yet configured in `.env.local`, MailForge will detect this and allow you to explore the application via **"Explore Demo Workspace"**. You can test audience management, campaign composition, CSV imports, variable interpolation, and previewing without crashing. As soon as Firebase and Resend keys are provided, the app automatically switches to real Google Sign-In and live provider delivery.

---

## Type Checking & Testing

To run TypeScript verification across all pages and route handlers:

```bash
npx tsc --noEmit
```

To create a production build locally:

```bash
npm run build
```

---

## Deployment to Vercel

1. Push your repository to GitHub or GitLab.
2. Import the repository in [Vercel](https://vercel.com/new).
3. In **Project Settings** > **Environment Variables**, paste all the keys from your `.env.local`:
   - `NEXT_PUBLIC_APP_URL` (set to your Vercel deployment URL, e.g. `https://mailforge.vercel.app`)
   - `NEXT_PUBLIC_FIREBASE_*` variables
   - `FIREBASE_PROJECT_ID`, `FIREBASE_CLIENT_EMAIL`, `FIREBASE_PRIVATE_KEY`
   - `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `RESEND_FROM_NAME`
   - `RESEND_WEBHOOK_SECRET`
4. Click **Deploy**. Vercel will automatically detect the Next.js App Router and deploy edge-optimized serverless routes.

---

## Security Best Practices Enforced

1. **Authentication Integrity:** Only requests bearing a valid Firebase ID token are accepted by protected server API routes (`/api/campaigns/send`, `/api/send-test`, etc.).
2. **Domain Spoofing Prevention:** Sender identities are constrained to domains verified in Resend (`RESEND_FROM_EMAIL`).
3. **Suppression Protection:** Contacts marked as `unsubscribed` or stored in the `suppressionLists` collection are automatically excluded before any batches are queued.
4. **Idempotency:** Every send operation generates an idempotency key to prevent accidental duplicate dispatches if a network timeout occurs.
5. **No Secret Leaks:** API keys and service account private keys are accessed exclusively inside server-side route handlers (`src/app/api/*`) and are never included in client JavaScript bundles.

---

## License

MIT License. Designed and engineered for production bulk email workflows.
