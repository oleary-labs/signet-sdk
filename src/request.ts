/**
 * Session-authenticated request signing.
 *
 * After auth, every keygen/sign request must include a signature
 * over the canonical request hash, produced with the session private key.
 *
 * Canonical hash: SHA256(groupID ":" keyID ":" nonce ":" timestamp_8BE [":" messageHash])
 * Signature: 64-byte [R || S] secp256k1 ECDSA (no recovery byte)
 */

import type { SessionKeypair, IdTokenClaims } from "./types";
import { bytesToHex } from "./session";

/** Signed request ready to POST to a node. */
export interface SignedRequest {
  group_id: string;
  key_suffix?: string;
  session_pub: string;
  request_sig: string;
  nonce: string;
  timestamp: number;
}

/** Signed request with message_hash for /v1/sign. */
export interface SignedSignRequest extends SignedRequest {
  message_hash: string;
}

/**
 * Derive the key ID that the node will resolve for this session.
 *
 * For OAuth sessions: iss:sub or iss:sub:suffix
 * e.g. https://accounts.google.com:114810956681671373980
 */
export function deriveKeyId(claims: IdTokenClaims, keySuffix?: string, identity?: string): string {
  const base = identity ?? `${claims.iss}:${claims.sub}`;
  return keySuffix ? `${base}:${keySuffix}` : base;
}

/**
 * Build and sign a keygen request.
 *
 * @param identity - For auth key cert sessions, pass the identity string.
 *   The key ID becomes `identity[:suffix]` instead of `iss:sub[:suffix]`.
 */
export async function signKeygenRequest(
  keypair: SessionKeypair,
  claims: IdTokenClaims,
  groupId: string,
  keySuffix?: string,
  identity?: string,
): Promise<SignedRequest> {
  const normalizedGroupId = groupId.toLowerCase();
  const keyId = deriveKeyId(claims, keySuffix, identity);
  const nonce = generateNonce();
  const timestamp = Math.floor(Date.now() / 1000);

  const hash = await canonicalRequestHash(normalizedGroupId, keyId, nonce, timestamp);
  const sig = await signHash(keypair.privateKey, hash);

  return {
    group_id: normalizedGroupId,
    key_suffix: keySuffix,
    session_pub: keypair.publicKeyHex,
    request_sig: bytesToHex(sig),
    nonce,
    timestamp,
  };
}

/**
 * Build and sign a threshold signing request.
 */
export async function signSignRequest(
  keypair: SessionKeypair,
  claims: IdTokenClaims,
  groupId: string,
  messageHash: Uint8Array,
  keySuffix?: string,
  identity?: string,
): Promise<SignedSignRequest> {
  const normalizedGroupId = groupId.toLowerCase();
  const keyId = deriveKeyId(claims, keySuffix, identity);
  const nonce = generateNonce();
  const timestamp = Math.floor(Date.now() / 1000);

  const hash = await canonicalRequestHash(
    normalizedGroupId,
    keyId,
    nonce,
    timestamp,
    messageHash
  );
  const sig = await signHash(keypair.privateKey, hash);

  return {
    group_id: normalizedGroupId,
    key_suffix: keySuffix,
    session_pub: keypair.publicKeyHex,
    request_sig: bytesToHex(sig),
    nonce,
    timestamp,
    message_hash: bytesToHex(messageHash),
  };
}

/**
 * Compute the canonical request hash matching the Go node's format.
 *
 * SHA256(groupID ":" keyID ":" nonce ":" timestamp_8BE [":" messageHash])
 */
async function canonicalRequestHash(
  groupId: string,
  keyId: string,
  nonce: string,
  timestamp: number,
  messageHash?: Uint8Array
): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  const enc = new TextEncoder();

  parts.push(enc.encode(groupId));
  parts.push(enc.encode(":"));
  parts.push(enc.encode(keyId));
  parts.push(enc.encode(":"));
  parts.push(enc.encode(nonce));
  parts.push(enc.encode(":"));

  // timestamp as 8-byte big-endian
  const tsBuf = new ArrayBuffer(8);
  const view = new DataView(tsBuf);
  view.setBigUint64(0, BigInt(timestamp));
  parts.push(new Uint8Array(tsBuf));

  if (messageHash && messageHash.length > 0) {
    parts.push(enc.encode(":"));
    parts.push(messageHash);
  }

  // Concatenate
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    buf.set(p, offset);
    offset += p.length;
  }

  const digest = await crypto.subtle.digest("SHA-256", buf);
  return new Uint8Array(digest);
}

/**
 * Sign a 32-byte hash with the session private key.
 * Returns 64-byte [R || S] signature (no recovery byte).
 *
 * Uses signAsync which works without configuring hashes.sha256.
 * lowS: true to match go-ethereum's crypto.VerifySignature.
 */
async function signHash(
  privateKey: Uint8Array,
  hash: Uint8Array
): Promise<Uint8Array> {
  const { signAsync } = await import("@noble/secp256k1");
  // prehash: false — our input is already SHA-256'd, don't hash again
  const sig = await signAsync(hash, privateKey, { lowS: true, prehash: false });
  return new Uint8Array(sig);
}

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}
