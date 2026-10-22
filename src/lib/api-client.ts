"use client";

import { auth } from "@/lib/firebase/client";

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  if (!path.startsWith("/api/")) throw new Error("API requests must use an application API path.");
  let token: string | null = null;
  if (auth) {
    await auth.authStateReady();
    if (auth.currentUser) {
      token = await auth.currentUser.getIdToken();
    }
  }
  if (!token && typeof document !== "undefined") {
    const match = document.cookie.match(/(?:^|;\s*)mf_auth_token=([^;]+)/);
    if (match) token = match[1];
  }
  if (!token) {
    throw new Error("Please sign in with your Google account to perform this operation.");
  }
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  return fetch(path, { ...init, headers, cache: "no-store" });
}

export async function apiRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiFetch(path, init);
  const data = await response.json();
  if (!response.ok) {
    const detail = data.issues?.slice(0, 3).map((issue: { path: string; message: string }) => `${issue.path}: ${issue.message}`).join(" ");
    throw new Error(detail || data.error || "The request failed.");
  }
  return data as T;
}
