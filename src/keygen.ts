/**
 * Distributed key generation via bootstrap nodes.
 *
 * After auth, call keygen to create a key shard for the session identity.
 * 409 (key already exists) is treated as success — the key was already created
 * in a previous session.
 */

import type { SessionKeypair, IdTokenClaims } from "./types";
import { signKeygenRequest } from "./request";

export interface KeygenConfig {
  nodeUrls: string[];
  groupId: string;
  /** Proxy endpoint for CORS */
  proxyEndpoint?: string;
}

export interface KeygenResult {
  keyId: string;
  ethereumAddress: string;
  groupPublicKey: string;
  alreadyExisted: boolean;
}

/**
 * Trigger keygen on a bootstrap node.
 * If the key already exists (409), returns success with alreadyExisted=true.
 */
export async function keygen(
  config: KeygenConfig,
  keypair: SessionKeypair,
  claims: IdTokenClaims,
  keySuffix?: string,
  identity?: string,
  curve?: string,
  scope?: string,
): Promise<KeygenResult> {
  const req = await signKeygenRequest(keypair, claims, config.groupId, keySuffix, identity);

  // Try the first node (keygen only needs to be initiated on one node)
  const nodeUrl = config.nodeUrls[0];
  const url = config.proxyEndpoint
    ? config.proxyEndpoint
    : `${nodeUrl}/v1/keygen`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (config.proxyEndpoint) {
    headers["x-node-url"] = nodeUrl;
    headers["x-node-path"] = "/v1/keygen";
  }

  // Add optional curve and scope to the request body
  const body: Record<string, unknown> = { ...req };
  if (curve) body.curve = curve;
  if (scope) body.scope = scope;

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (res.status === 409) {
    // Key already exists — node now returns full key info on 409
    const data = await res.json();
    return {
      keyId: data.key_id ?? `${claims.iss}:${claims.sub}${keySuffix ? `:${keySuffix}` : ""}`,
      ethereumAddress: data.ethereum_address ?? "",
      groupPublicKey: data.public_key ?? "",
      alreadyExisted: true,
    };
  }

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Keygen failed: ${res.status} — ${body}`);
  }

  const data = await res.json();
  return {
    keyId: data.key_id,
    ethereumAddress: data.ethereum_address,
    groupPublicKey: data.public_key,
    alreadyExisted: false,
  };
}
