"use client";

import React, { createContext, useContext, useEffect, useState, useTransition } from "react";
import {
  User as FirebaseUser,
  onAuthStateChanged,
  signInWithPopup,
  signOut as firebaseSignOut,
} from "firebase/auth";
import { auth, googleProvider, isFirebaseConfigured } from "@/lib/firebase/client";
import { UserProfile, UserSettings } from "@/types";
import { syncUserProfile, DEFAULT_SETTINGS } from "@/lib/store/db-service";

interface AuthContextType {
  user: FirebaseUser | null;
  profile: UserProfile | null;
  idToken: string | null;
  loading: boolean;
  error: string | null;
  isFirebaseActive: boolean;
  signInWithGoogle: () => Promise<void>;
  signOut: () => Promise<void>;
  refreshProfile: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  profile: null,
  idToken: null,
  loading: true,
  error: null,
  isFirebaseActive: false,
  signInWithGoogle: async () => {},
  signOut: async () => {},
  refreshProfile: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<FirebaseUser | null>(null);
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [idToken, setIdToken] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [, startTransition] = useTransition();

  // Store token in cookie for server route verification
  const setAuthCookie = (token: string | null) => {
    if (typeof document === "undefined") return;
    if (token) {
      document.cookie = `mf_auth_token=${token}; path=/; max-age=604800; SameSite=Lax`;
    } else {
      document.cookie = `mf_auth_token=; path=/; max-age=0; SameSite=Lax`;
    }
  };

  useEffect(() => {
    if (!auth || !isFirebaseConfigured) {
      setLoading(false);
      return;
    }

    const unsubscribe = onAuthStateChanged(
      auth,
      async (firebaseUser) => {
        setLoading(true);
        if (firebaseUser) {
          try {
            const token = await firebaseUser.getIdToken();
            setIdToken(token);
            setAuthCookie(token);
            setUser(firebaseUser);

            const userProf = await syncUserProfile({
              uid: firebaseUser.uid,
              email: firebaseUser.email || "",
              displayName: firebaseUser.displayName,
              photoURL: firebaseUser.photoURL,
            });
            setProfile(userProf);
          } catch (err: any) {
            console.error("Auth state profile sync error:", err);
            setError(err?.message || "Failed to sync user profile");
          }
        } else {
          setUser(null);
          setProfile(null);
          setIdToken(null);
          setAuthCookie(null);
        }
        setLoading(false);
      },
      (err) => {
        console.error("Firebase auth state error:", err);
        setError(err.message);
        setLoading(false);
      }
    );

    return () => unsubscribe();
  }, []);

  const signInWithGoogle = async () => {
    setError(null);
    setLoading(true);

    if (!isFirebaseConfigured || !auth || !googleProvider) {
      const msg =
        "Firebase credentials are not configured. Please add NEXT_PUBLIC_FIREBASE_API_KEY and NEXT_PUBLIC_FIREBASE_PROJECT_ID to .env.local.";
      setError(msg);
      setLoading(false);
      throw new Error(msg);
    }

    try {
      const result = await signInWithPopup(auth, googleProvider);
      const token = await result.user.getIdToken();
      setIdToken(token);
      setAuthCookie(token);
      setUser(result.user);

      const userProf = await syncUserProfile({
        uid: result.user.uid,
        email: result.user.email || "",
        displayName: result.user.displayName,
        photoURL: result.user.photoURL,
      });
      setProfile(userProf);
    } catch (err: any) {
      console.error("Google sign in error:", err);
      setError(err?.message || "Failed to sign in with Google");
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const signOut = async () => {
    setLoading(true);
    try {
      if (auth && isFirebaseConfigured) {
        await firebaseSignOut(auth);
      }
      setUser(null);
      setProfile(null);
      setIdToken(null);
      setAuthCookie(null);
    } catch (err: any) {
      console.error("Sign out error:", err);
      setError(err?.message || "Error signing out");
    } finally {
      setLoading(false);
    }
  };

  const refreshProfile = async () => {
    const currentUid = user?.uid || profile?.uid;
    if (!currentUid) return;
    const currentEmail = user?.email || profile?.email || "";
    const updated = await syncUserProfile({
      uid: currentUid,
      email: currentEmail,
      displayName: user?.displayName || profile?.displayName,
      photoURL: user?.photoURL || profile?.photoURL,
    });
    setProfile(updated);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        profile,
        idToken,
        loading,
        error,
        isFirebaseActive: isFirebaseConfigured,
        signInWithGoogle,
        signOut,
        refreshProfile,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
