/**
 * Structured EIP-712 signing for scoped keys.
 *
 * Scoped keys reject raw hash signing — the caller must provide a
 * structured payload that the node verifies against the key's scope
 * before computing the hash and signing.
 */

import type { SessionKeypair, IdTokenClaims } from "./types";
import { signKeygenRequest } from "./request";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface EIP712Domain {
  name?: string;
  version?: string;
  chainId: number;
  verifyingContract: string;
}

export interface EIP712TypedData {
  domain: EIP712Domain;
  types: Record<string, Array<{ name: string; type: string }>>;
  primaryType: string;
  message: Record<string, unknown>;
}

export interface ScopedSignResult {
  signature: string;       // raw signature hex
  ecdsaSignature: string;  // ECDSA-formatted (r, s, v)
  curve: string;
}

// ---------------------------------------------------------------------------
// Scope construction
// ---------------------------------------------------------------------------

/**
 * Build an EIP-712 domain scope (scheme 0x03).
 *
 * Format: 0x03 | chainId (8 bytes, uint64 BE) | verifyingContract (20 bytes)
 * Total: 29 bytes.
 */
export function buildEIP712Scope(chainId: number, verifyingContract: string): string {
  const buf = new Uint8Array(29);
  buf[0] = 0x03;

  // chainId as 8-byte big-endian
  const view = new DataView(buf.buffer);
  view.setBigUint64(1, BigInt(chainId));

  // verifyingContract as 20 bytes
  const addr = verifyingContract.startsWith("0x")
    ? verifyingContract.slice(2)
    : verifyingContract;
  for (let i = 0; i < 20; i++) {
    buf[9 + i] = parseInt(addr.slice(i * 2, i * 2 + 2), 16);
  }

  return "0x" + Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Structured signing
// ---------------------------------------------------------------------------

/**
 * Sign a structured EIP-712 payload with a scoped key.
 *
 * The node extracts the domain from the typed data, verifies it matches
 * the key's scope, computes hashTypedData, and threshold-signs.
 *
 * @param nodeUrl - Target group node URL
 * @param proxyEndpoint - CORS proxy URL
 * @param groupId - Group contract address
 * @param keyId - The scoped sub-key to sign with
 * @param curve - Key curve (e.g. "ecdsa_secp256k1")
 * @param typedData - Full EIP-712 typed data structure
 * @param sessionKeypair - Active session keypair
 * @param claims - OAuth/identity claims for session auth
 * @param identity - For auth key cert sessions
 */
export async function signTypedData(
  nodeUrl: string,
  proxyEndpoint: string,
  groupId: string,
  keyId: string,
  curve: string,
  typedData: EIP712TypedData,
  sessionKeypair: SessionKeypair,
  claims: IdTokenClaims,
  identity?: string,
): Promise<ScopedSignResult> {
  // Build session-authenticated request (no message hash — payload is sent separately)
  // The canonical hash must use the full sub-key ID (identity + suffix).
  // Extract suffix from keyId: "oauth:iss:sub:suffix" → suffix is last segment
  // The identity param is "iss:sub", so we need to add the suffix.
  const keyParts = keyId.split(":");
  const keySuffix = keyParts.length > 1 ? keyParts[keyParts.length - 1] : undefined;

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
      "x-node-path": "/v1/sign",
    },
    body: JSON.stringify({
      group_id: groupId.toLowerCase(),
      key_id: keyId,
      curve,
      payload: {
        scheme: "eip712",
        typed_data: typedData,
      },
      session_pub: signReq.session_pub,
      request_sig: signReq.request_sig,
      nonce: signReq.nonce,
      timestamp: signReq.timestamp,
    }),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Scoped sign failed: ${res.status} — ${body}`);
  }

  const data = await res.json();
  return {
    signature: data.signature,
    ecdsaSignature: data.ecdsa_signature,
    curve: data.curve ?? curve,
  };
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

export const CHAIN_PRESETS = [
  {
    label: "USDC on Base",
    chainId: 8453,
    contractName: "USDC",
    verifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    eip712Name: "USD Coin",
    eip712Version: "2",
  },
  {
    label: "USDC on Base Sepolia",
    chainId: 84532,
    contractName: "USDC",
    verifyingContract: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    eip712Name: "USD Coin",
    eip712Version: "2",
  },
  {
    label: "USDC on Ethereum",
    chainId: 1,
    contractName: "USDC",
    verifyingContract: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    eip712Name: "USD Coin",
    eip712Version: "2",
  },
  {
    label: "USDC on Sepolia",
    chainId: 11155111,
    contractName: "USDC",
    verifyingContract: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
    eip712Name: "USD Coin",
    eip712Version: "2",
  },
] as const;
