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
import type { SessionKeypair, IdTokenClaims } from "./types.js";
import { deriveKeyId, signSignRequest } from "./request.js";

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

// ---------------------------------------------------------------------------
// One-call EVM signing
// ---------------------------------------------------------------------------

/** Where to send the sign request. One node — nodes are symmetric. */
export interface EvmSignConfig {
	groupId: string;
	nodeUrl: string;
	/** CORS proxy. When set, nodeUrl travels in `x-node-url` instead. */
	proxyEndpoint?: string;
}

export interface EvmSignParams {
	keypair: SessionKeypair;
	/** The 32-byte hash to sign, as bytes or hex. */
	hash: Uint8Array | string;
	/**
	 * The key id base for every scheme except OAuth — an auth-key identity, a
	 * delegation identity, or the subject from a resolver session. Pass exactly
	 * what the node returned; the storage namespace is applied node-side.
	 */
	identity?: string;
	/** OAuth sessions only: the key id becomes `iss:sub`. Otherwise `null`. */
	claims?: IdTokenClaims | null;
	keySuffix?: string;
	/**
	 * Wrap `hash` in the `personal_sign` envelope before signing — sign
	 * keccak256("\x19Ethereum Signed Message:\n32" || hash) rather than `hash`.
	 *
	 * Defaults to true, because the contracts that verify these signatures
	 * almost always call `toEthSignedMessageHash` first: ERC-4337 account
	 * implementations, OpenZeppelin's `SignatureChecker`, and Safe's
	 * `checkSignatures` for the eth_sign case all do. Pass false only when the
	 * verifier recovers against the bare hash — EIP-712 and EIP-3009 both do,
	 * since their digests already carry a `\x19\x01` prefix of their own.
	 */
	eip191?: boolean;
}

export interface EvmSignResult {
	/** 0x r||s||v, with v in {27,28}. Usable on-chain as-is. */
	signature: string;
	/** The digest actually signed — post-envelope when `eip191` applied. */
	digest: string;
	/** The logical key id the request was signed under. */
	keyId: string;
}

/**
 * Produce an EVM-ready signature in one call.
 *
 * Collapses the four steps every caller was assembling by hand — EIP-191
 * envelope, session-authenticated request signing, the POST, and `v`
 * normalization — each of which has a failure mode that only shows up
 * on-chain:
 *
 *   - Skipping the envelope against a verifier that applies one recovers a
 *     different address, with no error anywhere in the JS.
 *   - Omitting `curve` gets you a FROST Schnorr signature back under a
 *     different response field (see `SignedSignRequest.curve`).
 *   - Leaving `v` at {0,1} passes a viem/ethers round-trip and then reverts.
 *
 * The curve is pinned to `ecdsa_secp256k1`: a signature `ecrecover` accepts is
 * the entire point of this helper. For FROST Schnorr, call `signSignRequest`
 * and post it yourself.
 *
 * @throws if the node answers with a Schnorr signature, which means the key is
 *   not an ECDSA key rather than anything wrong with the request.
 */
export async function signEvmDigest(
	config: EvmSignConfig,
	params: EvmSignParams,
): Promise<EvmSignResult> {
	const raw = typeof params.hash === "string" ? hexToSigBytes(params.hash) : params.hash;
	if (raw.length !== 32) {
		throw new Error(`expected a 32-byte hash to sign, got ${raw.length}`);
	}

	const digest = params.eip191 === false ? raw : eip191Digest(raw);
	const claims = params.claims ?? null;
	const keyId = deriveKeyId(claims, params.keySuffix, params.identity);

	const signReq = await signSignRequest(
		params.keypair,
		claims,
		config.groupId,
		digest,
		params.keySuffix,
		params.identity,
		"ecdsa_secp256k1",
	);

	const headers: Record<string, string> = { "Content-Type": "application/json" };
	let url: string;
	if (config.proxyEndpoint) {
		url = config.proxyEndpoint;
		headers["x-node-url"] = config.nodeUrl;
		headers["x-node-path"] = "/v1/sign";
	} else {
		url = `${config.nodeUrl}/v1/sign`;
	}

	const res = await fetch(url, {
		method: "POST",
		headers,
		body: JSON.stringify(signReq),
	});

	if (!res.ok) {
		throw new Error(`EVM sign failed: ${res.status} — ${await res.text()}`);
	}

	let data: Record<string, unknown>;
	try {
		data = await res.json();
	} catch {
		throw new Error("malformed sign response: 200 with a body that is not JSON");
	}

	const sig = data.ecdsa_signature;
	if (typeof sig !== "string") {
		// The node falls back to FROST Schnorr for a non-ECDSA key rather than
		// erroring, so this is a key-type mismatch, not a malformed request.
		if (typeof data.ethereum_signature === "string") {
			throw new Error(
				`key "${keyId}" signed with FROST Schnorr, not ECDSA — the node returned ` +
					`ethereum_signature. Generate the key with curve "ecdsa_secp256k1"; an ` +
					`existing Schnorr key cannot be verified by ecrecover.`,
			);
		}
		throw new Error("malformed sign response: no ecdsa_signature");
	}

	return { signature: toEvmSignature(sig), digest: toHex(digest), keyId };
}
