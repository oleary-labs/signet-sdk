/**
 * Signet DKMS SDK
 *
 * Framework-agnostic library for Signet protocol interactions.
 *
 * This barrel export includes only the core modules that have no heavy
 * dependencies. For ZK proof generation (client-side), import directly:
 *
 *   import { generateJWTProof } from "@oleary-labs/signet-sdk/proof"
 *   import { buildFullWitness } from "@oleary-labs/signet-sdk/witness"
 *
 * These require @noir-lang/noir_js, @aztec/bb.js, and
 * @oleary-labs/signet-circuits as peer dependencies.
 */

// Core
export * from "./types.js";
export * from "./session.js";
export * from "./request.js";
export * from "./signature.js";
export * from "./keygen.js";

// Auth (lightweight — no WASM)
export * from "./oauth.js";
export * from "./jwt.js";
export * from "./jwks.js";
export * from "./bootstrap.js";
export * from "./authkey-session.js";
export * from "./resolver-session.js";
export * from "./failover.js";
export * from "./server-prover.js";

// Admin
export * from "./admin.js";

// Signing + Delegation
export * from "./delegate.js";
export * from "./scopedSign.js";
export * from "./frostVerify.js";

// x402
export * from "./x402.js";

// ERC-4337
export * from "./userop.js";
export * from "./bundler.js";
