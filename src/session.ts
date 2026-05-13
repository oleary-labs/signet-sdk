/**
 * Session keypair management (secp256k1).
 *
 * Generates an ephemeral keypair for authenticating with bootstrap nodes.
 * The private key is held in memory only — never persisted.
 */

import type { SessionKeypair } from "./types";

/**
 * Generate a new ephemeral secp256k1 session keypair.
 */
export async function generateSessionKeypair(): Promise<SessionKeypair> {
  const { utils, getPublicKey } = await import("@noble/secp256k1");
  const privateKey = utils.randomSecretKey();
  const publicKeyBytes = getPublicKey(privateKey, true); // compressed
  const publicKeyHex = bytesToHex(publicKeyBytes);
  return { privateKey, publicKeyHex };
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
