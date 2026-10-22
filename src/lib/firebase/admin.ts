import { cert, getApps, initializeApp, applicationDefault } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import { configured } from "@/lib/server/config";
import { ApiError } from "@/lib/server/errors";

export function isFirebaseAdminConfigured(): boolean {
  return Boolean(configured(process.env.FIREBASE_PROJECT_ID) &&
    ((configured(process.env.FIREBASE_CLIENT_EMAIL) && configured(process.env.FIREBASE_PRIVATE_KEY)) ||
      process.env.GOOGLE_APPLICATION_CREDENTIALS ||
      (process.env.NODE_ENV !== "production" && process.env.FIREBASE_AUTH_EMULATOR_HOST && process.env.FIRESTORE_EMULATOR_HOST)));
}

function adminApp() {
  const existing = getApps().find((app) => app.name === "mailforge");
  if (existing) return existing;
  if (!isFirebaseAdminConfigured()) {
    throw new ApiError(503, "Firebase Admin is not configured. Add the server service-account credentials.", "CONFIGURATION_REQUIRED");
  }
  if (process.env.NODE_ENV === "production" && (process.env.FIREBASE_AUTH_EMULATOR_HOST || process.env.FIRESTORE_EMULATOR_HOST)) {
    throw new ApiError(503, "Firebase emulator configuration is not permitted in production.", "CONFIGURATION_REQUIRED");
  }
  try {
    const projectId = process.env.FIREBASE_PROJECT_ID!;
    const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n");
    const emulator = process.env.FIREBASE_AUTH_EMULATOR_HOST && process.env.FIRESTORE_EMULATOR_HOST;
    return initializeApp({
      projectId,
      ...(emulator ? {} : { credential: privateKey ? cert({ projectId, clientEmail: process.env.FIREBASE_CLIENT_EMAIL, privateKey }) : applicationDefault() }),
    }, "mailforge");
  } catch {
    throw new ApiError(503, "Firebase Admin credentials could not be initialized.", "CONFIGURATION_REQUIRED");
  }
}

export const getAdminAuth = () => getAuth(adminApp());
export const getAdminDb = () => getFirestore(adminApp());
