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
export * from "./types";
export * from "./session";
export * from "./request";
export * from "./keygen";

// Auth (lightweight — no WASM)
export * from "./oauth";
export * from "./jwt";
export * from "./jwks";
export * from "./bootstrap";
export * from "./authkey-session";
export * from "./server-prover";

// Admin
export * from "./admin";

// Signing + Delegation
export * from "./delegate";
export * from "./scopedSign";
export * from "./frostVerify";

// x402
export * from "./x402";

// ERC-4337
export * from "./userop";
export * from "./bundler";
