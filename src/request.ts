/**
 * Session-authenticated request signing.
 *
 * After auth, every keygen/sign request must include a signature
 * over the canonical request hash, produced with the session private key.
 *
 * Canonical hash: SHA256(groupID ":" keyID ":" nonce ":" timestamp_8BE [":" messageHash])
 * Signature: 64-byte [R || S] secp256k1 ECDSA (no recovery byte)
 */

import type { SessionKeypair, IdTokenClaims } from "./types.js";
import { bytesToHex } from "./session.js";

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
  /**
   * Curve to sign with. OMITTING THIS IS RARELY WHAT YOU WANT: the node
   * defaults to FROST Schnorr when `curve` is absent, so an ECDSA key posted
   * without it comes back as `ethereum_signature` (Schnorr) rather than
   * `ecdsa_signature`, and the mismatch only surfaces downstream — often
   * on-chain. Pass "ecdsa_secp256k1" for any key you intend to verify with
   * `ecrecover`.
   */
  curve?: string;
}

/** Namespaces the node prepends itself, after verifying the request signature. */
const RESERVED_KEY_NAMESPACES = ["authkey:", "oauth:", "resolver:"];

/**
 * Derive the key ID that the node will resolve for this session.
 *
 * For OAuth sessions: iss:sub or iss:sub:suffix
 * e.g. https://accounts.google.com:114810956681671373980
 *
 * IMPORTANT: this returns the *logical* key id — the value the client signs
 * over. The node verifies the request signature against exactly this string and
 * only afterwards prepends the storage namespace ("authkey:", "oauth:", or a
 * resolver prefix); see `validateSessionRequest` in node/handlers.go, whose
 * comment reads "The prefix is internal — clients never see it".
 *
 * So for an auth-key session with identity "my-backend", pass "my-backend" and
 * NOT "authkey:my-backend", even though the key is stored under the latter.
 * Getting this wrong produces a signature over the wrong string, which the node
 * rejects as a sanitized `401 {"error":"unauthorized"}` with no further detail —
 * indistinguishable from a bad auth key or an expired session.
 *
 * @throws if `identity` carries a namespace the node would add itself.
 */
export function deriveKeyId(claims: IdTokenClaims, keySuffix?: string, identity?: string): string {
  if (identity) {
    const reserved = RESERVED_KEY_NAMESPACES.find((p) => identity.startsWith(p));
    if (reserved) {
      throw new Error(
        `identity must not include the "${reserved}" namespace — the node adds it ` +
          `after verifying the request signature. Pass ` +
          `"${identity.slice(reserved.length)}" instead of "${identity}".`,
      );
    }
  }
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
  curve?: string,
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
    ...(curve ? { curve } : {}),
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
