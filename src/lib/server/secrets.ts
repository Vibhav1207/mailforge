import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { encryptionKey } from "./config";

export function encryptSecret(value: string, owner: string): string {
  const nonce = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), nonce);
  cipher.setAAD(Buffer.from(owner));
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return ["v1", nonce.toString("base64url"), cipher.getAuthTag().toString("base64url"), ciphertext.toString("base64url")].join(".");
}

export function decryptSecret(value: string, owner: string): string {
  const [version, nonce, tag, ciphertext] = value.split(".");
  if (version !== "v1" || !nonce || !tag || !ciphertext) throw new Error("Invalid encrypted credential");
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(nonce, "base64url"));
  decipher.setAAD(Buffer.from(owner));
  decipher.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, "base64url")), decipher.final()]).toString("utf8");
}
