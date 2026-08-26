/**
 * EVM signature helpers.
 *
 * The node returns recoverable ECDSA signatures as r(32) || s(32) || v(1) with
 * `v` in {0,1} (node/handlers.go — the recovery id is found by trial recovery
 * against the group key, and emitted without the +27 offset). Every on-chain
 * verifier in the EVM ecosystem expects {27,28} instead:
 *
 *   - Solidity's `ecrecover` precompile returns address(0) for other values.
 *   - OpenZeppelin `ECDSA.recover` reverts.
 *   - Citizen Wallet's Safe module rejects the signature before it ever reaches
 *     `ecrecover`:
 *         if (v != 27 && v != 28) revert("...invalid signature 'v' value");
 *
 * viem's `recoverAddress` and ethers' `recoverAddress` both accept yParity 0/1,
 * so a signature that passes a JS round-trip test can still revert on-chain.
 * Normalize before submitting anything to a contract.
 */

import { keccak_256 } from "@noble/hashes/sha3";

/**
 * Convert a node ECDSA signature into the form EVM contracts accept.
 *
 * Accepts a 65-byte signature as hex (with or without 0x) or bytes, and returns
 * the same signature with `v` mapped into {27,28}. Already-normalized
 * signatures pass through unchanged, so this is safe to apply unconditionally.
 *
 * @throws if the signature is not 65 bytes, or `v` is not one of 0, 1, 27, 28.
 */
export function toEvmSignature(signature: string | Uint8Array): string {
	const bytes =
		typeof signature === "string" ? hexToSigBytes(signature) : Uint8Array.from(signature);

	if (bytes.length !== 65) {
		throw new Error(`expected a 65-byte signature, got ${bytes.length}`);
	}

	const v = bytes[64];
	if (v === 27 || v === 28) return toHex(bytes);
	if (v !== 0 && v !== 1) {
		throw new Error(`unexpected recovery id ${v}; expected 0, 1, 27 or 28`);
	}

	const out = Uint8Array.from(bytes);
	out[64] = v + 27;
	return toHex(out);
}

/**
 * The EIP-191 digest an EVM `personal_sign` verifier recovers against:
 * keccak256("\x19Ethereum Signed Message:\n32" || hash).
 *
 * Use this when a contract verifies with `toEthSignedMessageHash(h)` — ERC-4337
 * account implementations commonly do — and sign the RESULT as the raw
 * `message_hash`, not the bare hash.
 *
 * Synchronous. (`await`-ing it is harmless if you already wrote it that way.)
 */
export function eip191Digest(hash32: Uint8Array): Uint8Array {
	if (hash32.length !== 32) {
		throw new Error(`expected a 32-byte hash, got ${hash32.length}`);
	}
	const prefix = new TextEncoder().encode("\x19Ethereum Signed Message:\n32");
	const buf = new Uint8Array(prefix.length + 32);
	buf.set(prefix, 0);
	buf.set(hash32, prefix.length);
	return keccak_256(buf);
}

function hexToSigBytes(hex: string): Uint8Array {
	const h = hex.startsWith("0x") ? hex.slice(2) : hex;
	if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) {
		throw new Error("signature is not valid hex");
	}
	const out = new Uint8Array(h.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
	return out;
}

function toHex(bytes: Uint8Array): string {
	return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
