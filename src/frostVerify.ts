/**
 * Client-side FROST Schnorr signature verification (RFC 9591 secp256k1-SHA256-v1).
 *
 * Verifies a 65-byte FROST threshold signature against a compressed group
 * public key and message. Uses the same algorithm as FROSTVerifier.sol:
 *
 *   Verification equation: z·G = R + c·Y
 *   Challenge: c = H2(R || Y || msg) via expand_message_xmd (RFC 9380)
 *   DST: "FROST-secp256k1-SHA256-v1chal"
 *
 * Uses @noble/curves (already installed) for elliptic curve arithmetic
 * and RFC 9380 hash-to-curve utilities.
 */

import { secp256k1 } from "@noble/curves/secp256k1";
import { expand_message_xmd } from "@noble/curves/abstract/hash-to-curve";
import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";

const DST = new TextEncoder().encode("FROST-secp256k1-SHA256-v1chal");
const N = secp256k1.CURVE.n;

/**
 * Verify a FROST Schnorr signature.
 *
 * @param message - The message bytes that were signed (typically 32 bytes)
 * @param signature - 65-byte signature: R.x(32) || z(32) || v(1)
 * @param groupPublicKey - 33-byte compressed secp256k1 group public key
 * @returns true if the signature is valid
 */
export function verifyFrostSignature(
  message: Uint8Array,
  signature: Uint8Array,
  groupPublicKey: Uint8Array,
): boolean {
  if (signature.length !== 65) return false;
  if (groupPublicKey.length !== 33) return false;

  const rx = signature.slice(0, 32);
  const z = bytesToBigInt(signature.slice(32, 64));
  const v = signature[64];

  if (z === 0n || z >= N) return false;

  // Reconstruct compressed R from R.x + parity
  const rCompressed = new Uint8Array(33);
  rCompressed[0] = v === 0 ? 0x02 : 0x03;
  rCompressed.set(rx, 1);

  // Challenge: c = H2(R_compressed || groupPublicKey || message)
  // Uses expand_message_xmd (RFC 9380) with SHA-256, output 48 bytes, reduced mod N
  const input = concatBytes(rCompressed, groupPublicKey, message);
  const uniform = expand_message_xmd(input, DST, 48, sha256);
  const c = bytesToBigInt(uniform) % N;

  if (c === 0n) return false;

  // Verify: z·G == R + c·Y
  try {
    const R = secp256k1.ProjectivePoint.fromHex(rCompressed);
    const Y = secp256k1.ProjectivePoint.fromHex(groupPublicKey);
    const G = secp256k1.ProjectivePoint.BASE;

    const lhs = G.multiply(z);
    const rhs = R.add(Y.multiply(c));

    return lhs.equals(rhs);
  } catch {
    return false;
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}
