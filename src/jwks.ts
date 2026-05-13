/**
 * JWKS (JSON Web Key Set) fetcher.
 *
 * Fetches RSA public keys from any OIDC-compliant issuer and extracts
 * the modulus needed for the ZK proof witness. Supports Google, Clerk,
 * and any issuer with a standard JWKS endpoint.
 */

import type { JWKSKey } from "./types";

const GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";

// Cache per issuer URI
const cache = new Map<string, { keys: JWKSKey[]; expiry: number }>();
const CACHE_TTL = 3600_000; // 1 hour

/**
 * Derive the JWKS URI from a JWT issuer.
 * Google uses a non-standard path; all other OIDC issuers use /.well-known/jwks.json.
 */
function jwksUriForIssuer(issuer: string): string {
  if (issuer === "https://accounts.google.com") {
    return GOOGLE_JWKS_URI;
  }
  // Standard OIDC convention
  const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;
  return `${base}/.well-known/jwks.json`;
}

/**
 * Fetch JWKS keys for an issuer.
 */
export async function fetchJWKS(issuer?: string): Promise<JWKSKey[]> {
  const uri = jwksUriForIssuer(issuer ?? "https://accounts.google.com");
  const cached = cache.get(uri);
  if (cached && Date.now() < cached.expiry) {
    return cached.keys;
  }

  const res = await fetch(uri);
  if (!res.ok) {
    throw new Error(`Failed to fetch JWKS from ${uri}: ${res.status}`);
  }

  const data = await res.json();
  const keys = data.keys as JWKSKey[];
  cache.set(uri, { keys, expiry: Date.now() + CACHE_TTL });
  return keys;
}

/** @deprecated Use fetchJWKS() instead */
export const fetchGoogleJWKS = () => fetchJWKS("https://accounts.google.com");

/**
 * Find the RSA key matching a JWT's kid.
 * If issuer is provided, fetches from that issuer's JWKS endpoint.
 */
export async function getJWKSKeyForKid(kid: string, issuer?: string): Promise<JWKSKey> {
  const keys = await fetchJWKS(issuer);
  const key = keys.find((k) => k.kid === kid);
  if (!key) {
    throw new Error(`No JWKS key found for kid: ${kid}`);
  }
  if (key.kty !== "RSA") {
    throw new Error(`Expected RSA key, got ${key.kty}`);
  }
  return key;
}

/**
 * Decode a base64url-encoded JWKS modulus to a BigInt.
 */
export function decodeModulus(base64url: string): bigint {
  const binary = atob(base64url.replace(/-/g, "+").replace(/_/g, "/"));
  let hex = "";
  for (let i = 0; i < binary.length; i++) {
    hex += binary.charCodeAt(i).toString(16).padStart(2, "0");
  }
  return BigInt("0x" + hex);
}

/**
 * Decode a base64url-encoded JWKS modulus to raw bytes.
 */
export function decodeModulusBytes(base64url: string): Uint8Array {
  const binary = atob(base64url.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
