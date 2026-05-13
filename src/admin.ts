/**
 * Admin API authentication for Signet group management.
 *
 * Admin auth is stateless: sign SHA256(group_id : nonce : timestamp_BE)
 * with a trusted auth key. For Schnorr auth keys (prefix 0x01), the
 * signature is produced via FROST threshold signing through the bootstrap
 * group.
 */

import type { SessionKeypair, IdTokenClaims } from "./types";
import { signSignRequest } from "./request";
import { bytesToHex } from "./session";

export interface AdminAuthConfig {
  nodeProxyUrl: string;
  bootstrapGroup: string;
  bootstrapNodes: string[];
}

export interface AdminAuth {
  group_id: string;
  auth_key_pub: string;
  signature: string;
  nonce: string;
  timestamp: number;
}

/**
 * Build an admin auth payload by threshold-signing the admin hash
 * via the bootstrap group.
 *
 * The admin hash is: SHA256(group_id + ":" + nonce + ":" + timestamp_8BE)
 * The signature is a 65-byte FROST Schnorr signature.
 */
export async function buildAdminAuth(
  config: AdminAuthConfig,
  groupId: string,
  authKeyPub: string,
  sessionKeypair: SessionKeypair,
  claims: IdTokenClaims,
): Promise<AdminAuth> {
  const normalizedGroupId = groupId.toLowerCase();
  const nonce = generateNonce();
  const timestamp = Math.floor(Date.now() / 1000);

  // Build the admin hash: SHA256(group_id + ":" + nonce + ":" + timestamp_8BE)
  const adminHash = await computeAdminHash(normalizedGroupId, nonce, timestamp);

  // Threshold-sign the hash via bootstrap group
  const signReq = await signSignRequest(
    sessionKeypair,
    claims,
    config.bootstrapGroup,
    adminHash,
  );

  const signRes = await fetch(config.nodeProxyUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-node-url": config.bootstrapNodes[0],
      "x-node-path": "/v1/sign",
    },
    body: JSON.stringify(signReq),
  });

  if (!signRes.ok) {
    const body = await signRes.text();
    throw new Error(`Admin signing failed: ${signRes.status} — ${body}`);
  }

  const { ethereum_signature } = await signRes.json();

  return {
    group_id: normalizedGroupId,
    auth_key_pub: authKeyPub,
    signature: ethereum_signature,
    nonce,
    timestamp,
  };
}

/**
 * Call an admin endpoint with auth.
 *
 * If the signing request fails with a 401 "session not found" error and
 * a reauthenticate callback is provided, re-establishes the node session
 * and retries once.
 */
export async function adminRequest<T>(
  config: AdminAuthConfig,
  nodeUrl: string,
  path: string,
  groupId: string,
  authKeyPub: string,
  sessionKeypair: SessionKeypair,
  claims: IdTokenClaims,
  extraBody?: Record<string, unknown>,
  reauthenticate?: () => Promise<void>,
): Promise<T> {
  try {
    return await adminRequestInner<T>(config, nodeUrl, path, groupId, authKeyPub, sessionKeypair, claims, extraBody);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (reauthenticate && /session not found/i.test(msg)) {
      await reauthenticate();
      return await adminRequestInner<T>(config, nodeUrl, path, groupId, authKeyPub, sessionKeypair, claims, extraBody);
    }
    throw err;
  }
}

async function adminRequestInner<T>(
  config: AdminAuthConfig,
  nodeUrl: string,
  path: string,
  groupId: string,
  authKeyPub: string,
  sessionKeypair: SessionKeypair,
  claims: IdTokenClaims,
  extraBody?: Record<string, unknown>,
): Promise<T> {
  const auth = await buildAdminAuth(config, groupId, authKeyPub, sessionKeypair, claims);

  const res = await fetch(config.nodeProxyUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-node-url": nodeUrl,
      "x-node-path": path,
    },
    body: JSON.stringify({ ...auth, ...extraBody }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Admin ${path} failed: ${res.status} — ${body}`);
  }

  return res.json();
}

async function computeAdminHash(
  groupId: string,
  nonce: string,
  timestamp: number
): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const parts: Uint8Array[] = [];

  parts.push(enc.encode(groupId));
  parts.push(enc.encode(":"));
  parts.push(enc.encode(nonce));
  parts.push(enc.encode(":"));

  // timestamp as 8-byte big-endian
  const tsBuf = new ArrayBuffer(8);
  const view = new DataView(tsBuf);
  view.setBigUint64(0, BigInt(timestamp));
  parts.push(new Uint8Array(tsBuf));

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

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}
