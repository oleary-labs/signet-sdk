/**
 * Delegation token minting and delegation-based auth.
 *
 * Delegation tokens are JWTs signed by a parent FROST/ECDSA key that grant
 * an agent long-lived access to a specific scoped sub-key without requiring
 * the user's OAuth session.
 *
 * Flow:
 * 1. User creates parent key + scoped sub-key via keygen
 * 2. User calls requestDelegation() → gets a JWT signed by parent key
 * 3. Agent calls authenticateWithDelegation() → establishes session
 * 4. Agent signs with the scoped sub-key via the session
 */

import type { SessionKeypair, IdTokenClaims } from "./types";
import { signKeygenRequest } from "./request";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DelegationResult {
  token: string;
  keyId: string;
  parentKey: string;
  expiresAt: number;
}

export interface DelegationAuthResult {
  identity: string;
  keyId: string;
  expiresAt: number;
}

// ---------------------------------------------------------------------------
// Mint delegation token (user path)
// ---------------------------------------------------------------------------

/**
 * Request a delegation token for a scoped sub-key.
 *
 * Requires an active OAuth session. The node threshold-signs a JWT using
 * the parent key, granting the token holder access to the sub-key.
 *
 * @param nodeUrl - Target group node URL
 * @param proxyEndpoint - CORS proxy URL (e.g. "/api/node/proxy")
 * @param groupId - Group contract address
 * @param keyId - The sub-key to delegate access to
 * @param parentKeyId - The parent key that signs the JWT
 * @param curve - Key curve (e.g. "ecdsa_secp256k1")
 * @param expiresIn - Token lifetime in seconds (e.g. 2592000 for 30 days)
 * @param sessionKeypair - Active session keypair
 * @param claims - OAuth claims for session auth
 * @param identity - For auth key cert sessions
 */
export async function requestDelegation(
  nodeUrl: string,
  proxyEndpoint: string,
  groupId: string,
  keySuffix: string,
  parentKeyId: string,
  curve: string,
  expiresIn: number,
  sessionKeypair: SessionKeypair,
  claims: IdTokenClaims,
  identity?: string,
): Promise<DelegationResult> {
  // Build session-authenticated request.
  // Try with suffix in the canonical hash — if the node resolves the key
  // from session + suffix, the signature must cover the suffixed key ID.
  const signReq = await signKeygenRequest(
    sessionKeypair,
    claims,
    groupId,
    keySuffix,
    identity,
  );



  const res = await fetch(proxyEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-node-url": nodeUrl,
      "x-node-path": "/v1/delegate",
    },
    body: JSON.stringify({
      group_id: groupId.toLowerCase(),
      key_suffix: keySuffix,
      parent_key_id: parentKeyId,
      curve,
      expires_in: expiresIn,
      session_pub: signReq.session_pub,
      request_sig: signReq.request_sig,
      nonce: signReq.nonce,
      timestamp: signReq.timestamp,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Delegation failed: ${res.status} — ${body}`);
  }

  const data = await res.json();
  return {
    token: data.token,
    keyId: data.key_id,
    parentKey: data.parent_key,
    expiresAt: data.expires_at,
  };
}

// ---------------------------------------------------------------------------
// Authenticate with delegation token (agent path)
// ---------------------------------------------------------------------------

/**
 * Authenticate with a node using a delegation token.
 *
 * The agent presents a JWT signed by the parent key. The node verifies
 * the signature and creates a session scoped to the sub-key.
 *
 * @param nodeUrl - Target group node URL
 * @param proxyEndpoint - CORS proxy URL
 * @param groupId - Group contract address
 * @param delegationToken - The JWT from requestDelegation()
 * @param sessionKeypair - Fresh ephemeral session keypair for the agent
 */
export async function authenticateWithDelegation(
  nodeUrl: string,
  proxyEndpoint: string,
  groupId: string,
  delegationToken: string,
  sessionKeypair: SessionKeypair,
): Promise<DelegationAuthResult> {
  const res = await fetch(proxyEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-node-url": nodeUrl,
      "x-node-path": "/v1/auth",
    },
    body: JSON.stringify({
      group_id: groupId.toLowerCase(),
      delegation_token: delegationToken,
      session_pub: sessionKeypair.publicKeyHex,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Delegation auth failed: ${res.status} — ${body}`);
  }

  const data = await res.json();
  return {
    identity: data.identity,
    keyId: data.key_id,
    expiresAt: data.expires_at,
  };
}
