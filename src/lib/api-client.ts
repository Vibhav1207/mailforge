"use client";

import { auth } from "@/lib/firebase/client";

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  if (!path.startsWith("/api/")) throw new Error("API requests must use an application API path.");
  let token: string | null = null;
  if (auth?.currentUser) {
    try {
      token = await auth.currentUser.getIdToken();
    } catch {}
  }
  if (!token && typeof document !== "undefined") {
    const match = document.cookie.match(/(?:^|;\s*)mf_auth_token=([^;]+)/);
    if (match) token = match[1];
  }
  if (!token && auth) {
    try {
      await Promise.race([
        auth.authStateReady(),
        new Promise((_, reject) => setTimeout(() => reject(new Error("Auth timeout")), 2000)),
      ]);
      if (auth.currentUser) token = await auth.currentUser.getIdToken();
    } catch {}
  }
  if (!token && typeof document !== "undefined") {
    const match = document.cookie.match(/(?:^|;\s*)mf_auth_token=([^;]+)/);
    if (match) token = match[1];
  }
  if (!token) throw new Error("Please sign in with your Google account to perform this operation.");

  const headers = new Headers(init.headers);
  if (init.body && typeof init.body === "string" && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  headers.set("Authorization", `Bearer ${token}`);

  const request = { ...init, headers, cache: "no-store" as RequestCache };
  const canRetry = (request.method || "GET").toUpperCase() === "GET";
  for (let attempt = 0; ; attempt++) {
    const response = await fetch(path, request);
    if (!canRetry || ![502, 503, 504].includes(response.status) || attempt >= 2) {
      return response;
    }
    await new Promise((resolve) => setTimeout(resolve, 400 * (attempt + 1)));
  }
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
