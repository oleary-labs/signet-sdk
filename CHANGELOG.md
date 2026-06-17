# Changelog

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
