/**
 * Distributed key generation via bootstrap nodes.
 *
 * After auth, call keygen to create a key shard for the session identity.
 * 409 (key already exists) is treated as success — the key was already created
 * in a previous session.
 */

import type { SessionKeypair, IdTokenClaims } from "./types.js";
import { signKeygenRequest, deriveKeyId } from "./request.js";
import { withNodeFailover, postJson } from "./failover.js";

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
  claims: IdTokenClaims | null,
  keySuffix?: string,
  identity?: string,
  curve?: string,
  scope?: string,
): Promise<KeygenResult> {
  const req = await signKeygenRequest(keypair, claims, config.groupId, keySuffix, identity);

  // Add optional curve and scope to the request body
  const body: Record<string, unknown> = { ...req };
  if (curve) body.curve = curve;
  if (scope) body.scope = scope;

  // Keygen is initiated on one node, but any node can serve it, so an
  // unreachable node is worth moving past rather than failing on.
  //
  // Failover is safe here because a duplicate is not a second DKG: the
  // initiating node does not return until every node has acked the start of the
  // protocol, so a node reached afterwards answers 409 rather than starting a
  // competing run. That also makes failover *necessary* rather than merely nice
  // — a request that times out in transit may well have started a DKG, and
  // without a retry the caller has no way to find out.
  return withNodeFailover(config.nodeUrls, async (nodeUrl) => {
    const res = await postJson(nodeUrl, "/v1/keygen", body, config.proxyEndpoint);

    if (res.status === 409) {
      // Key already exists — node returns full key info on 409.
      const data = await res.json();
      const groupPublicKey = data.public_key ?? "";

      // A 409 whose key material is absent is a DKG that has started and not
      // finished — the ack precedes completion. Returning empty strings here
      // would read as a successful keygen and fail later at the point of use,
      // far from the cause. There is no awaitKey on this path, so the honest
      // answer is to say so and let the caller poll.
      if (!groupPublicKey) {
        throw new Error(
          `Keygen for "${data.key_id ?? deriveKeyId(claims, keySuffix, identity)}" is ` +
            `already in progress on ${nodeUrl}: the node reported the key exists but ` +
            `returned no public key, which means the DKG has started and not yet ` +
            `completed. Retry keygen shortly — a completed run answers 409 with the key.`,
        );
      }

      return {
        // Older nodes omit key_id on 409; deriveKeyId reproduces what was sent.
        keyId: data.key_id ?? deriveKeyId(claims, keySuffix, identity),
        ethereumAddress: data.ethereum_address ?? "",
        groupPublicKey,
        alreadyExisted: true,
      };
    }

    if (!res.ok) {
      throw new Error(`Keygen failed: ${res.status} — ${await res.text()}`);
    }

    const data = await res.json();
    return {
      keyId: data.key_id,
      ethereumAddress: data.ethereum_address,
      groupPublicKey: data.public_key,
      alreadyExisted: false,
    };
  });
}
