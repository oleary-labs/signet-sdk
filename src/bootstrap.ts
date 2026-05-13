/**
 * Bootstrap group node authentication.
 *
 * After generating a ZK proof of the JWT, POST it to each
 * bootstrap node to register the session key.
 */

import type { NodeAuthRequest } from "./types";
import { bytesToHex } from "./session";

export interface BootstrapConfig {
  groupId: string; // bootstrap group contract address
  nodeUrls: string[]; // bootstrap node API URLs
  /** Proxy endpoint for CORS — if set, requests go through this instead of directly to nodes */
  proxyEndpoint?: string;
}

export interface AuthResult {
  identity: string;
  expiresAt: number;
}

/**
 * Authenticate with all bootstrap nodes.
 *
 * Posts the ZK proof + session public key to each node's /v1/auth.
 * All nodes must accept the session for signing to work.
 */
export async function authenticateWithBootstrap(
  config: BootstrapConfig,
  proof: Uint8Array,
  sessionPubHex: string,
  claims: { iss: string; sub: string; exp: number; aud: string; azp: string },
  jwksModulusBytes: Uint8Array
): Promise<AuthResult> {
  const request: NodeAuthRequest = {
    group_id: config.groupId,
    session_pub: sessionPubHex,
    proof: bytesToHex(proof),
    sub: claims.sub,
    iss: claims.iss,
    exp: claims.exp,
    aud: claims.aud,
    azp: claims.azp,
    jwks_modulus: bytesToHex(jwksModulusBytes),
  };

  // Auth with all nodes in parallel
  const results = await Promise.allSettled(
    config.nodeUrls.map((url) =>
      authWithNode(url, request, config.proxyEndpoint)
    )
  );

  // Check that at least one succeeded
  const successes = results.filter(
    (r): r is PromiseFulfilledResult<AuthResult> => r.status === "fulfilled"
  );
  const failures = results.filter(
    (r): r is PromiseRejectedResult => r.status === "rejected"
  );

  if (successes.length === 0) {
    const reasons = failures.map((f) => f.reason?.message ?? String(f.reason));
    throw new Error(
      `All bootstrap nodes rejected auth: ${reasons.join("; ")}`
    );
  }

  if (failures.length > 0) {
    console.warn(
      `${failures.length}/${config.nodeUrls.length} bootstrap nodes failed auth:`,
      failures.map((f) => f.reason?.message)
    );
  }

  return successes[0].value;
}

async function authWithNode(
  baseUrl: string,
  request: NodeAuthRequest,
  proxyEndpoint?: string
): Promise<AuthResult> {
  const url = proxyEndpoint ?? `${baseUrl}/v1/auth`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (proxyEndpoint) {
    headers["x-node-url"] = baseUrl;
    headers["x-node-path"] = "/v1/auth";
  }

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(request),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${baseUrl}: ${res.status} — ${body}`);
  }

  return res.json();
}
