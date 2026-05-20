# @oleary-labs/signet-sdk

TypeScript client for the [Signet](https://github.com/oleary-labs/signet-protocol) threshold-signing protocol. Handles session keys, OAuth + ZK auth, threshold keygen, threshold signing across three signing schemes (FROST/secp256k1, FROST/Ed25519, threshold ECDSA/secp256k1), delegation tokens, scoped sub-keys, ERC-4337 user operations, and x402 payments.

Extracted from `signet-ui`; now consumed by `signet-ui` and `signet-better-mcp`.

## Install

```bash
bun add @oleary-labs/signet-sdk
# or: npm install @oleary-labs/signet-sdk
```

Optional peer dependencies (only needed if you call the corresponding subpaths):

| Peer dep | Required for | Default state |
|---|---|---|
| `viem` >=2.0.0 | `./userop`, `./bundler`, `./x402`, anything that touches EVM ABI encoding | strongly recommended for most consumers |
| `@noir-lang/noir_js` 1.0.0-beta.11 | `./proof`, `./witness` (in-browser ZK proving) | optional — only needed if you prove client-side |
| `@aztec/bb.js` 0.82.2 | `./proof`, `./witness` | optional — same as above |
| `@oleary-labs/signet-circuits` 0.1.0 | `./proof`, `./witness` | optional — bump to `^0.3.0` when convenient (server-side proving via the bundler always uses the latest) |

Most consumers delegate ZK proof generation to `signet-min-bundler`'s `POST /v1/prove` (see `./server-prover`) and don't install the Noir/bb peers at all.

## Concept overview — what's where

Signet's protocol nodes accept a `curve` parameter on every signing endpoint and dispatch to one of three schemes:

| Curve string | Scheme | Where it's used |
|---|---|---|
| `frost_secp256k1` | FROST Schnorr / secp256k1 (RFC 9591) | Admin signing, ERC-4337 user-op signing, anything FROST-based |
| `frost_ed25519` | FROST Schnorr / Ed25519 | Solana and other Ed25519 chains |
| `ecdsa_secp256k1` | Threshold ECDSA / secp256k1 (DJNPO20, 4-round robust) | Scoped sub-keys, x402 agent payments, EIP-712 typed-data signing where the verifier expects raw ECDSA |

The SDK reflects this with a unified function-per-operation API rather than separate client classes — every signing function takes a `curve` argument (or hard-codes one where it makes sense). The HTTP responses for signing carry both `signature` (the scheme's native format) and `ecdsa_signature` (a 65-byte r‖s‖v variant) where applicable.

Session authentication and auth-key certificates always use ephemeral local ECDSA — that's universal and lives entirely in the client.

## Subpath exports

The SDK ships with 19 subpath exports. Import the one you need; the entry point (`@oleary-labs/signet-sdk`) re-exports the most common identifiers.

### Core

| Subpath | Purpose |
|---|---|
| `./session` | Generate/import an ephemeral secp256k1 session keypair; hex helpers |
| `./types` | `SessionKeypair`, `IdTokenClaims`, and shared types |
| `./request` | Build canonical request hashes; sign them with the session ECDSA key (used internally by most other modules) |

### Auth

| Subpath | Purpose |
|---|---|
| `./oauth` | OAuth code exchange and JWT extraction (`handleOAuthCallback`, `getOAuthReturnTo`) |
| `./jwt` | JWT decode / validate |
| `./jwks` | JWKS fetch and key lookup |
| `./bootstrap` | Bootstrap-group authentication wrapper |
| `./authkey-session` | Auth-key certificate session — server-side flow that lets a backend authenticate with a long-lived ECDSA key instead of an OAuth bearer token |

### Keygen and signing

| Subpath | Purpose |
|---|---|
| `./keygen` | Threshold keygen request (`keygen(config, keypair, claims, keySuffix?, identity?, curve?, scope?)`) |
| `./admin` | Admin API auth — bootstrap-group FROST signing for admin endpoints |
| `./delegate` | Mint and redeem delegation JWTs (`requestDelegation`, `authenticateWithDelegation`) for autonomous-agent flows |
| `./scopedSign` | EIP-712 structured signing with scoped sub-keys (`signTypedData(...)`; `buildEIP712Scope`; `CHAIN_PRESETS`) |
| `./frostVerify` | Client-side FROST Schnorr verification (RFC 9591) — useful for tests and round-trip checks |

### ERC-4337 and payments

| Subpath | Purpose |
|---|---|
| `./userop` | Build ERC-4337 v0.7 user operations and FROST-sign them |
| `./bundler` | JSON-RPC client for `signet-min-bundler` (send/estimate/receipt) |
| `./x402` | `x402Fetch` — performs the full x402 dance (request → 402 → sign → retry) |

### ZK proofs

| Subpath | Purpose |
|---|---|
| `./witness` | Build the witness for the `jwt_auth` Noir circuit |
| `./proof` | Generate the proof in-browser using `@aztec/bb.js` + `@noir-lang/noir_js` |
| `./server-prover` | Delegate proof generation to `signet-min-bundler`'s `POST /v1/prove` (recommended for most apps) |

## The `curve` parameter contract

Functions that hit a signing endpoint accept a curve string. Pass one of the three canonical values exactly:

```ts
"frost_secp256k1" | "frost_ed25519" | "ecdsa_secp256k1"
```

Mismatches between what you pass here and the key's actual scheme will fail at the node, not in the client.

The session itself (the ephemeral keypair from `./session`) and auth-key certificates always use local ECDSA — there's no curve parameter for those; only the threshold-signing operations take one.

## Example flows

### A. FROST keygen via OAuth (Console main flow)

```ts
import { generateSessionKeypair } from "@oleary-labs/signet-sdk/session";
import { handleOAuthCallback } from "@oleary-labs/signet-sdk/oauth";
import { keygen } from "@oleary-labs/signet-sdk/keygen";

const keypair = await generateSessionKeypair();
const { claims } = await handleOAuthCallback(/* ... */);

const result = await keygen(
  {
    nodeUrls: ["https://node-1.example.com", "https://node-2.example.com", "https://node-3.example.com"],
    groupId: "0xf0700...",
    proxyEndpoint: "/api/node/proxy", // optional CORS proxy
  },
  keypair,
  claims,
  /* keySuffix */ undefined,
  /* identity */ undefined,
  /* curve */ "frost_secp256k1",
);

console.log(result.ethereumAddress, result.groupPublicKey);
```

### B. ECDSA scoped sub-key + EIP-712 signing (x402 agent flow)

```ts
import { keygen } from "@oleary-labs/signet-sdk/keygen";
import { requestDelegation, authenticateWithDelegation } from "@oleary-labs/signet-sdk/delegate";
import { signTypedData, buildEIP712Scope, CHAIN_PRESETS } from "@oleary-labs/signet-sdk/scopedSign";
import { x402Fetch } from "@oleary-labs/signet-sdk/x402";

// Operator side: mint a scoped sub-key bound to USDC on Base
const scope = buildEIP712Scope(8453, CHAIN_PRESETS[0].verifyingContract);
const subkey = await keygen(config, keypair, claims, /* keySuffix */ "agent-1", /* identity */ undefined, "ecdsa_secp256k1", scope);

// Mint a delegation JWT for the agent
const delegation = await requestDelegation({ /* ... */ curve: "ecdsa_secp256k1" });

// Agent side: redeem the delegation and sign
const agentSession = await authenticateWithDelegation(delegation, /* ... */);
const signed = await signTypedData(
  nodeUrl,
  proxyEndpoint,
  groupId,
  subkey.keyId,
  "ecdsa_secp256k1",
  typedData,
  agentSession.keypair,
  agentSession.claims,
);

// Use it for an x402 invoice
const response = await x402Fetch("https://api.example.com/pay", { /* ... */ });
```

### C. Admin signing via bootstrap group (FROST)

```ts
import { adminSign } from "@oleary-labs/signet-sdk/admin";

const adminSig = await adminSign({
  groupId,
  nodeUrl,
  proxyEndpoint,
  // ...
});
```

See `signet-ui` (Console, x402 demo) and `signet-better-mcp` (MCP server) for full working examples.

## Relation to other Signet repos

```
signet-circuits ──► signet-protocol (embeds VK)
                ──► signet-min-bundler (embeds circuit, runs `nargo` + `bb`)
                ──► signet-sdk (peer dep, optional — for browser proving)

signet-protocol  ◄── HTTP /v1/* ── signet-sdk ◄── signet-ui, signet-better-mcp
signet-min-bundler ◄── /v1/prove ── signet-sdk (./server-prover)
```

The SDK has no opinion about hosting — caller supplies all URLs at runtime (no hardcoded endpoints). For local development point it at the signet-protocol devnet (`http://localhost:8080..8082`) and `signet-min-bundler` (`http://localhost:4337`).

## Build

```bash
bun install
bun run build       # tsc to ./dist (ESM + .d.ts)
bun run typecheck   # tsc --noEmit
```

ESM-only. `prepublishOnly` runs the build so `bun publish` (or `npm publish`) ships a current `dist/`.

## License

MIT.
