import * as admin from "firebase-admin";

const projectId = process.env.FIREBASE_PROJECT_ID;
const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
let privateKey = process.env.FIREBASE_PRIVATE_KEY;

if (privateKey) {
  // Handle escaped \n in environment variables
  privateKey = privateKey.replace(/\\n/g, "\n");
}

export const isFirebaseAdminConfigured = Boolean(
  projectId &&
  projectId !== "mailforge-prod" &&
  clientEmail &&
  privateKey &&
  !privateKey.includes("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6example")
);

function initAdmin(): admin.app.App | null {
  if (admin.apps.length > 0) {
    return admin.apps[0]!;
  }

  if (isFirebaseAdminConfigured && projectId && clientEmail && privateKey) {
    try {
      return admin.initializeApp({
        credential: admin.credential.cert({
          projectId,
          clientEmail,
          privateKey,
        }),
      });
    } catch (err) {
      console.error("Firebase Admin initialization error:", err);
      return null;
    }
  }

  return null;
}

const adminApp = initAdmin();
export const adminAuth = adminApp ? adminApp.auth() : null;
export const adminDb = adminApp ? adminApp.firestore() : null;
export { admin };
