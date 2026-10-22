import { ApiError } from "./errors";

export const MAX_IMAGE_BYTES = 3 * 1024 * 1024;

export function imageContentType(bytes: Buffer): string | null {
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) return "image/png";
  if (bytes.length >= 3 && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return "image/jpeg";
  if (["GIF87a", "GIF89a"].includes(bytes.subarray(0, 6).toString("ascii"))) return "image/gif";
  if (bytes.length >= 12 && bytes.subarray(0, 4).toString("ascii") === "RIFF" && bytes.subarray(8, 12).toString("ascii") === "WEBP") return "image/webp";
  return null;
}

export function validateImage(bytes: Buffer, declaredType?: string): string {
  if (!bytes.length) throw new ApiError(400, "The image is empty.", "INVALID_IMAGE");
  if (bytes.length > MAX_IMAGE_BYTES) throw new ApiError(413, "Images must be 3 MB or smaller.", "PAYLOAD_TOO_LARGE");
  const contentType = imageContentType(bytes);
  if (!contentType || (declaredType && declaredType !== "application/octet-stream" && declaredType !== contentType)) throw new ApiError(400, "Upload a valid PNG, JPEG, GIF, or WebP image.", "INVALID_IMAGE");
  return contentType;
}

export function decodeImageBase64(value: string): Buffer {
  const encoded = value.replace(/^data:image\/(?:png|jpeg|gif|webp);base64,/i, "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new ApiError(400, "Invalid base64 image data.", "INVALID_IMAGE");
  return Buffer.from(encoded, "base64");
}
