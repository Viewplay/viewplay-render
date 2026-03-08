// /server/utils/base64url.js
export function encodeBase64Url(bytes) {
  const b64 = Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function decodeBase64Url(s) {
  try {
    let b64 = String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    return new Uint8Array(Buffer.from(b64, "base64"));
  } catch {
    return null;
  }
}