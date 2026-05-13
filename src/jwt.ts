/**
 * JWT parsing utilities for ZK proof witness construction.
 *
 * Extracts the components needed by the noir jwt_auth circuit:
 * - Signed data (header.payload as raw bytes)
 * - RSA signature (decoded from base64url)
 * - Key ID (kid) from the header for JWKS lookup
 */

import type { IdTokenClaims } from "./types";

/** Parsed JWT components needed for proof generation. */
export interface ParsedJWT {
  /** Raw signed data: base64(header) + "." + base64(payload) as bytes */
  signedData: Uint8Array;
  /** Base64-decoded RSA signature bytes */
  signatureBytes: Uint8Array;
  /** Key ID from the JWT header — used to find the right JWKS key */
  kid: string;
  /** Decoded payload claims */
  claims: IdTokenClaims;
  /** Offset where base64-encoded payload starts (header length + 1 for the dot) */
  base64DecodeOffset: number;
}

/**
 * Parse a JWT into its components for ZK proof generation.
 */
export function parseJWT(jwt: string): ParsedJWT {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT: expected 3 parts");
  }

  const [headerB64, payloadB64, signatureB64] = parts;

  // Decode header to get kid
  const header = JSON.parse(base64urlDecode(headerB64));
  if (header.alg !== "RS256") {
    throw new Error(`Unsupported JWT algorithm: ${header.alg}`);
  }

  // Signed data is the raw ASCII bytes of "header.payload"
  const signedDataStr = `${headerB64}.${payloadB64}`;
  const signedData = new TextEncoder().encode(signedDataStr);

  // Decode the RSA signature
  const signatureBytes = base64urlDecodeBytes(signatureB64);

  // Decode claims
  const claims = JSON.parse(base64urlDecode(payloadB64)) as IdTokenClaims;

  return {
    signedData,
    signatureBytes,
    kid: header.kid,
    claims,
    base64DecodeOffset: headerB64.length + 1,
  };
}

function base64urlDecode(s: string): string {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  return atob(padded);
}

function base64urlDecodeBytes(s: string): Uint8Array {
  const decoded = base64urlDecode(s);
  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) {
    bytes[i] = decoded.charCodeAt(i);
  }
  return bytes;
}
