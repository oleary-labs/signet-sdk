# Changelog

## 0.4.0

Everything here came out of the SFLuv on-chain-resolver rollout, which was the
first integration to drive the SDK from something other than an OAuth session.
Additive — no breaking changes from 0.3.0.

### A fourth auth route: `onchain_resolver`

- **`authenticateWithResolver`** (new `./resolver-session`). The user signs an
  ERC-4361 message with the EOA behind their wallet, the node reads a resolver
  contract at a client-pinned block, and the session is namespaced under the
  subject the resolver returns. The module owns Signet's message format and
  failure semantics; the caller keeps its own signer and RPC endpoints, which
  arrive as `signMessage` and `getBlockPin` callbacks — nothing in `src/`
  performs a chain read.
- Authenticates against one node, matching `authkey-session` and `delegate`.
  Every node independently re-runs SIWE recovery and the resolver read at the
  same pinned block, so nodes cannot disagree and propagation is a timing
  question rather than a consistency one. `barrierNodeUrls` optionally waits for
  the others first; it never changes the outcome.

### `identity` accepted wherever `claims` was required

- `claims` was read only to build the `iss:sub` base of an OAuth key id, yet
  every request-signing entry point demanded it — so auth-key, delegation,
  resolver and ZK-proof callers passed a stub of empty strings that read as
  meaningful. `deriveKeyId`, `signKeygenRequest`, `signSignRequest`, `keygen`,
  `signTypedData` and `delegate` now take `IdTokenClaims | null` and throw when
  neither `claims` nor `identity` is supplied, rather than deriving `":"` and
  signing over it — which the node rejected as an opaque 401.
- Fixes keygen's 409 fallback, which rebuilt the key id from claims and so
  ignored `identity` entirely.

### `signEvmDigest`

- New. Collapses the four steps every EVM caller was assembling by hand: the
  EIP-191 envelope, session-authenticated request signing, the POST, and `v`
  normalisation. Each has a failure mode invisible in JS that only surfaces as a
  reverted transaction — skipping the envelope recovers a different address;
  omitting `curve` returns Schnorr under a different response field; leaving `v`
  at `{0,1}` survives a viem/ethers round-trip and then reverts. Curve is pinned
  to `ecdsa_secp256k1`; `eip191: false` covers EIP-712 and EIP-3009, whose
  digests carry their own `\x19\x01` prefix. `signSignRequest` is unchanged for
  callers posting the request themselves.

### The userop path is no longer OAuth-only

- `SignetWriteParams` gains `identity`, `keySuffix` and `curve`. Previously only
  an OAuth session could sign a user operation; an ECDSA request would have read
  `ethereum_signature`, found `undefined`, and assigned it as the signature.
  The response field is now chosen by the requested curve, and ECDSA is
  normalised before it reaches `validateUserOp`.

### Node failover

- New `./failover` module: `withNodeFailover`, `postJson`,
  `NodeTransportError`, `AllNodesFailedError`, `isTransportStatus`. Wired into
  `keygen` (which used `nodeUrls[0]` and nothing else, on a six-node fleet),
  `signEvmDigest` and `authenticateWithResolver`.
- Deliberately transport-tier only. A 4xx from one node is not retried
  elsewhere: every node reads at the same pinned block and would answer
  identically, so asking four more turns one clear error into five and buries
  the cause. A propagation 401 means the session has not reached *that* node
  yet, so the fix is to retry it or to pass `barrierNodeUrls`.
- Keygen failover is safe because the initiating node does not return until
  every node has acked the protocol start, so a node reached afterwards answers
  409 rather than starting a competing DKG. A 409 landing mid-DKG used to return
  empty strings that read as success and failed later at the point of use; it
  now says the DKG is still running.

### Packaging

- **Reachable from CommonJS.** The exports map carried only an `import`
  condition, so under `require` every subpath threw
  `ERR_PACKAGE_PATH_NOT_EXPORTED` — bundlers honour `import` and were fine,
  plain Node was not, and the *importing* file's package scope decides the
  condition, so no loader or ESM marker fixes it. Added `default` alongside
  `import` and moved `types` first, since conditions match in order. Node
  >=22.12 `require()`s ESM directly and the SDK has no top-level await; older
  Node now fails with `ERR_REQUIRE_ESM`, which at least names the cause.
- Added `prepare`, so a git-URL install builds. `dist` is gitignored, so
  installing from a branch previously produced a package with no `dist` at all.

### Consumer status

- `signet-platform` — pins `^0.3.0`. Nothing in 0.4.0 is required by it today;
  the userop path it does not yet use on mainnet is the part that changed.
- `signet-better-mcp` — pins `^0.2.0`, still owes the 0.3.0 `buildEIP712Scope`
  `typeHash` argument at `src/tools/create_payment_key.ts:52`.

## 0.3.0

**Breaking — requires nodes running the matching `signet-protocol` fix. 0.3.0 and
pre-fix nodes reject each other's scoped sign requests. Keys scoped under 0.2.0
must be regenerated.**

### Scoped EIP-712 signing hardened

- **Sign over a locally-computed EIP-712 hash (security, H1).** `signTypedData`
  now computes `hashTypedData(typedData)` client-side and binds it into the
  canonical request signature (via `signSignRequest`). Nodes recompute the hash
  from the payload and verify the session signature against it, so the payload
  can no longer be substituted by the initiating node or in transit.
  - *Silent break:* this is a runtime/node-compat change, not a compile error —
    `signTypedData` call sites keep building but fail against pre-fix nodes.

- **Bind the EIP-712 primary type into 0x03 scopes.** A 0x03 scope is now
  **61 bytes**: `0x03 | chainId (8) | verifyingContract (20) | typeHash (32)`
  (was 29 bytes, domain-only). A key scoped to one method (e.g.
  `TransferWithAuthorization`) can no longer sign a different method (e.g. an
  EIP-2612 `permit`) on the same contract.
  - `buildEIP712Scope(chainId, verifyingContract, typeHash)` — now takes a third
    `typeHash` argument (**compile break** for existing 2-arg callers).
  - `eip712TypeHash(primaryType, types)` — new. `keccak256(encodeType(...))`,
    matching the EIP-712 spec / go-ethereum `apitypes.TypeHash`, so the bytes
    match what the node and on-chain verifier use. Verified in tests against the
    canonical EIP-3009 typehash `0x7c7c6cdb…`.
  - `buildEIP712ScopeForTypedData(typedData)` — new, recommended. Derives
    chainId + verifyingContract + typeHash from a typed-data sample.

### Consumer status (as of this release)

Neither consumer has been updated to 0.3.0 yet — intentionally deferred pending
the next-testnet decision. When resuming:

- `signet-ui` — pin `0.2.0`; `buildEIP712Scope` call at
  `src/app/demo/x402/page.tsx:96` needs the new `typeHash` arg.
- `signet-better-mcp` — pin `^0.2.0`; `buildEIP712Scope` call at
  `src/tools/create_payment_key.ts:52` needs the new `typeHash` arg.
- `signTypedData` call sites in both repos compile unchanged but require
  fix-enabled nodes at runtime.

## 0.2.0

- Include ZK proof modules in `dist`; add all subpath exports.

## 0.1.x

- Initial SDK extraction from `signet-ui`; `dist/` build with `.d.ts`, subpath
  exports, Better Auth integration guide.
