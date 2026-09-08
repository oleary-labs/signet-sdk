/**
 * On-chain auth resolver sessions (`onchain_resolver` scheme).
 *
 * The user signs an ERC-4361 (SIWE) message with the EOA behind their wallet.
 * Every node independently reads a resolver contract — at a block the client
 * pins — that answers "which account does this address speak for?", and
 * namespaces the session under the subject the resolver returns. Identity
 * follows the wallet rather than the login provider.
 *
 * Flow:
 * 1. Build the SIWE message binding the session public key (`buildSiweMessage`)
 * 2. Have the user's EOA `personal_sign` it
 * 3. Pin a recent block on the resolver's chain
 * 4. POST /v1/auth to ONE node with message + signature + pin
 * 5. Use the session key for subsequent keygen/sign requests
 *
 * Contact one node, not all of them. Nodes are symmetric: /v1/auth broadcasts a
 * `msgAuth` coord message to the participants, and each one independently
 * re-runs SIWE recovery and the resolver read at the same pinned block rather
 * than trusting the initiator's verdict (handlers.go, coord.go). All four auth
 * schemes work this way. Because every node reads at the pinned block, they
 * cannot disagree — propagation is a timing question, never a consistency one.
 *
 * The broadcast is asynchronous, so /v1/auth returns before participants have
 * cached the session. Authenticating and immediately signing against a
 * *different* node can lose that race. Two remedies, in order of preference:
 * retry the sign once on a 401, or pass `barrierNodeUrls` to have this call
 * wait on the other nodes first — the same barrier the protocol harness uses to
 * keep propagation noise out of its measurements, and equally not a
 * requirement.
 *
 * This path has a wider window than the others: each participant makes its own
 * `eth_call` at the pinned block, so propagation is bounded by every node's RPC
 * latency to the resolver's chain.
 *
 * A stored key id has three layers, and only one of them is the client's:
 *
 *   resolver:<addr>:   from the group's resolver config — blocks a
 *                      resolver-swap hijack (spec §10 R-1)
 *   <subject>          from the authenticated session — blocks one user
 *                      reaching another's keys
 *   :<suffix>          from the client — carries no security property; it is
 *                      just how one user holds several keys
 *
 * The client signs over the LOGICAL id only — `<subject>[:<suffix>]`, with no
 * `resolver:` prefix and no resolver address. The namespace is applied after
 * signature verification (handlers.go:1194-1205), and `stripKeyNamespace`
 * takes it off again on the way out, so the prefix never appears in anything
 * this SDK constructs, signs, or receives.
 *
 * Hence the rule for callers: CHOOSE THE SUFFIX, NEVER THE SUBJECT OR PREFIX.
 * The subject is the `bytes32` from `resolve()` and is opaque — Signet
 * namespaces under it without interpreting it, and a resolver may pack
 * anything into those 32 bytes (SFLuv's packs a Safe address, which is a
 * property of that deployment, not of the scheme). Echo
 * `ResolverAuthResult.identity` verbatim into `signSignRequest` and store it
 * verbatim; never rebuild it from what you believe the subject to be. It is
 * hashed into the request signature, so a wrong reconstruction fails as a
 * sanitized 401 with no detail.
 *
 * What this module deliberately does NOT do: talk to a chain. The block pin
 * arrives through the `getBlockPin` callback and message signing through
 * `signMessage`, so the SDK carries the protocol rules while the caller keeps
 * ownership of its RPC endpoints and signer. This mirrors `x402Fetch`.
 */

import type { SessionKeypair } from "./types.js";
import { isTransportStatus } from "./failover.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A block on the resolver's chain that every node re-reads `resolve()` at. */
export interface BlockPin {
  number: number;
  /** 32-byte block hash, 0x-prefixed. */
  hash: string;
}

export interface ResolverSessionConfig {
  /** Group contract address. */
  groupId: string;
  /**
   * The node to authenticate against. One is enough — /v1/auth broadcasts the
   * session to the other participants, which re-verify it themselves.
   */
  nodeUrl: string;
  /** If set, requests go through this proxy (for CORS). */
  proxyEndpoint?: string;
  /**
   * Optionally wait for these nodes to hold the session before returning, by
   * posting the same request to each. Purely a barrier against the
   * asynchronous broadcast — the session reaches them regardless, and their
   * verdicts cannot differ from `nodeUrl`'s because all of them read at the
   * pinned block. Use it when the very next call signs against an arbitrary
   * node and you would rather not handle a propagation 401.
   *
   * Failures here do not fail the authentication; they are reported on
   * `ResolverAuthResult.barrier`.
   */
  barrierNodeUrls?: string[];
  /**
   * How many times to refetch the block pin and re-POST when the node rejects
   * the pin as stale. Default 3. The user is NOT asked to sign again — the pin
   * lives outside the signed message.
   */
  maxPinRetries?: number;
  /**
   * Nodes to try, in order, if `nodeUrl` cannot be reached — it refuses the
   * connection, times out, or answers 5xx/429. Only a node that never produced
   * a verdict is failed over.
   *
   * A verdict is never failed over, and the 401 that looks like it wants to be
   * is the one case where moving nodes is actively wrong: it means the session
   * has not propagated to *that* node yet, so the fix is to retry the same node
   * — or to have used `barrierNodeUrls` in the first place. Every node reads at
   * the pinned block, so no two of them can disagree about the answer.
   */
  failoverNodeUrls?: string[];
}

/** Fields of the SIWE message the node checks and will reject on. */
export interface SiweParams {
  /** Must equal the nodes' configured `siwe_domain`, exactly. */
  domain: string;
  /** The EOA that signs. Checked by signature recovery. */
  address: string;
  /**
   * The RESOLVER's chain id — not the app's, and not the group's. Signing with
   * the wrong one is rejected as `siwe chain id N != resolver chain id M`.
   */
  chainId: number;
  /** ERC-4361 `URI` field. Defaults to `https://<domain>`. */
  uri?: string;
  /** Human-readable line shown in the wallet. Optional. */
  statement?: string;
  /**
   * ERC-4361 nonce — at least 8 alphanumeric characters. Generated if omitted.
   * Required for the message to parse; note the node does not currently
   * replay-check it on this path.
   */
  nonce?: string;
  /** Defaults to now. */
  issuedAt?: Date;
  /**
   * Bounds the session. Required by the node, and capped at 24 hours.
   * Defaults to one hour out.
   */
  expirationTime?: Date;
}

export interface ResolverAuthParams {
  /**
   * 33-byte compressed secp256k1 session public key as lowercase hex with NO
   * `0x` prefix — exactly what `generateSessionKeypair()` puts in
   * `publicKeyHex`. Pass `sessionKeypair.publicKeyHex` straight through.
   */
  sessionPubHex: string;
  siwe: SiweParams;
  /**
   * Personal-sign the SIWE message with the user's EOA. Called ONCE: the block
   * pin is not part of the signed message, so staleness retries reuse this
   * signature rather than re-prompting.
   */
  signMessage: (message: string) => Promise<string>;
  /**
   * Fetch a fresh `(number, hash)` from the resolver's chain. Called once per
   * attempt. Do not cache the result — the node accepts only a narrow window
   * behind its own head.
   */
  getBlockPin: () => Promise<BlockPin>;
}

/** Per-node outcome, so a partial rollout is visible rather than silent. */
export interface NodeAuthOutcome {
  nodeUrl: string;
  ok: boolean;
  /** Present when `ok`. */
  identity?: string;
  /** Present when `ok`. */
  expiresAt?: number;
  /** Present when not `ok`. */
  error?: ResolverAuthError;
}

export interface ResolverAuthResult {
  /**
   * The logical identity for this session — the subject the resolver returned,
   * as the node rendered it. Opaque, and NOT an address even when the resolver
   * packs one into its bytes32.
   *
   * Plumbing, not a value to act on: pass it straight to
   * `signSignRequest`/`deriveKeyId` as `identity` and store it as given. The
   * only part of a key id you should be choosing is the suffix. Persist it as
   * text wide enough for 0x-prefixed 32 bytes, not as an address column.
   */
  identity: string;
  expiresAt: number;
  /** The node that established the session. */
  nodeUrl: string;
  /** How many block pins were burned getting here. */
  pinAttempts: number;
  /**
   * Per-node results of the optional propagation barrier. Absent when
   * `barrierNodeUrls` was not set. A failure here means that node had not
   * cached the session yet — not that the session is invalid.
   */
  barrier?: NodeAuthOutcome[];
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Classified cause of a `401 resolver auth failed: <msg>`.
 *
 * The node returns these as prose. Matching them here is what lets a caller
 * tell "this node was never configured" from "the user is not enrolled" from
 * "refetch the block and try again" — all of which arrive as the same status.
 */
export type ResolverAuthErrorCode =
  /** Node's `siwe_domain` is unset — the whole scheme is disabled there. */
  | "siwe_domain_not_configured"
  /** No resolver bound to the group yet, or the binding has not been polled. */
  | "no_resolver_bound"
  /** Node has no RPC for the resolver's chain. */
  | "no_chain_rpc"
  /** Resolver's `typeAndVersion()` is outside the node's accept-list. */
  | "unsupported_resolver_version"
  /** Signed with the app's chain id instead of the resolver's. */
  | "chain_id_mismatch"
  /** `signet://session/<pub>` absent, malformed, or put in the statement. */
  | "missing_session_resource"
  /** No `Expiration Time` field. */
  | "missing_expiration"
  /** Bad signature, wrong domain, or already expired. */
  | "siwe_verification_failed"
  /** Pin older than the node's max lag — refetch and retry. */
  | "block_pin_stale"
  /** Client's RPC is ahead of the node's — refetch and retry. */
  | "block_pin_ahead"
  /** Reorg, or a hash from a different chain or height. */
  | "block_pin_hash_mismatch"
  /** Not bound, no longer authorized, or the gate denied it. */
  | "not_authorized"
  /** Anything else, including non-401 transport failures. */
  | "unknown";

/** Codes that a fresh block pin can fix. Retried automatically. */
const RETRYABLE_CODES: ReadonlySet<ResolverAuthErrorCode> = new Set([
  "block_pin_stale",
  "block_pin_ahead",
  "block_pin_hash_mismatch",
]);

/**
 * Codes that mean a node was never configured for this scheme, as opposed to
 * anything about this particular request. These are what a rollout preflight
 * is looking for.
 */
const NODE_CONFIG_CODES: ReadonlySet<ResolverAuthErrorCode> = new Set([
  "siwe_domain_not_configured",
  "no_resolver_bound",
  "no_chain_rpc",
  "unsupported_resolver_version",
]);

export class ResolverAuthError extends Error {
  readonly code: ResolverAuthErrorCode;
  readonly nodeUrl: string;
  readonly status?: number;
  /** The node's raw message, before classification. */
  readonly detail: string;
  /**
   * True when the node never produced a verdict — unreachable, or 5xx/429/408.
   * The only condition under which another node is worth trying.
   */
  readonly transport: boolean;

  constructor(
    code: ResolverAuthErrorCode,
    nodeUrl: string,
    detail: string,
    status?: number,
    transport = false,
  ) {
    super(`${nodeUrl}: ${code} — ${detail}`);
    this.name = "ResolverAuthError";
    this.code = code;
    this.nodeUrl = nodeUrl;
    this.detail = detail;
    this.status = status;
    this.transport = transport;
  }

  /** True when refetching the block pin and retrying may succeed. */
  get retryable(): boolean {
    return RETRYABLE_CODES.has(this.code);
  }

  /** True when this node is missing configuration, not handling a bad request. */
  get isNodeMisconfiguration(): boolean {
    return NODE_CONFIG_CODES.has(this.code);
  }
}

/** Map a node's prose error onto a code. Ordered most- to least-specific. */
export function classifyResolverError(message: string): ResolverAuthErrorCode {
  const m = message.toLowerCase();
  if (m.includes("siwe domain not configured")) return "siwe_domain_not_configured";
  if (m.includes("no auth resolver configured")) return "no_resolver_bound";
  if (m.includes("no rpc configured for chain")) return "no_chain_rpc";
  if (m.includes("unsupported resolver version")) return "unsupported_resolver_version";
  if (m.includes("!= resolver chain id")) return "chain_id_mismatch";
  if (m.includes("missing session resource")) return "missing_session_resource";
  if (m.includes("missing expiration time")) return "missing_expiration";
  if (m.includes("too stale")) return "block_pin_stale";
  if (m.includes("ahead of head")) return "block_pin_ahead";
  if (m.includes("block hash mismatch")) return "block_pin_hash_mismatch";
  if (m.includes("did not authorize")) return "not_authorized";
  if (m.includes("verify siwe")) return "siwe_verification_failed";
  return "unknown";
}

// ---------------------------------------------------------------------------
// SIWE message
// ---------------------------------------------------------------------------

/** Max session lifetime the node will accept. */
export const MAX_SESSION_SECONDS = 24 * 60 * 60;

/** The resource URI that binds a SIWE message to one Signet session key. */
export function sessionResourceUri(sessionPubHex: string): string {
  return `signet://session/${assertSessionPubHex(sessionPubHex)}`;
}

/**
 * Build the ERC-4361 message the node verifies.
 *
 * Hand-rolled rather than pulled from a SIWE library: the message is fully
 * determined by the fields below, and `viem/siwe` would raise this package's
 * effective minimum viem well above the declared `>=2.0.0` peer range. The
 * tests pin the output byte-for-byte against `viem`'s `createSiweMessage`.
 *
 * The single `Resources` entry is what stops a SIWE signature minted for
 * another site from opening a Signet session, so the node matches it strictly
 * and will not read the session key out of the statement text.
 */
export function buildSiweMessage(
  params: SiweParams & { sessionPubHex: string },
): string {
  const {
    domain,
    address,
    chainId,
    sessionPubHex,
    statement,
    uri = `https://${domain}`,
    nonce = generateNonce(),
    issuedAt = new Date(),
    expirationTime,
  } = params;

  if (!domain) throw new Error("siwe domain is required");
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error(`siwe address must be a 0x-prefixed 20-byte address, got "${address}"`);
  }
  if (!Number.isInteger(chainId) || chainId <= 0) {
    throw new Error(`siwe chainId must be a positive integer, got ${chainId}`);
  }
  if (nonce.length < 8 || !/^[a-zA-Z0-9]+$/.test(nonce)) {
    throw new Error("siwe nonce must be at least 8 alphanumeric characters");
  }
  if (statement?.includes("\n")) {
    throw new Error("siwe statement must not contain a newline");
  }

  const expiry =
    expirationTime ?? new Date(issuedAt.getTime() + 60 * 60 * 1000);
  const lifetimeSeconds = (expiry.getTime() - issuedAt.getTime()) / 1000;
  if (lifetimeSeconds <= 0) {
    throw new Error("siwe expirationTime must be after issuedAt");
  }
  if (lifetimeSeconds > MAX_SESSION_SECONDS) {
    throw new Error(
      `siwe expirationTime is ${Math.round(lifetimeSeconds / 3600)}h out; ` +
        `the node caps sessions at ${MAX_SESSION_SECONDS / 3600}h`,
    );
  }

  // ERC-4361 layout. The blank line after the address is always present; the
  // statement, when given, sits between it and a second blank line.
  const head = `${domain} wants you to sign in with your Ethereum account:\n${address}\n`;
  const body = statement === undefined ? "\n" : `\n${statement}\n`;

  return (
    head +
    body +
    "\n" +
    `URI: ${uri}\n` +
    "Version: 1\n" +
    `Chain ID: ${chainId}\n` +
    `Nonce: ${nonce}\n` +
    `Issued At: ${issuedAt.toISOString()}\n` +
    `Expiration Time: ${expiry.toISOString()}\n` +
    "Resources:\n" +
    `- ${sessionResourceUri(sessionPubHex)}`
  );
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/**
 * Establish a session by authenticating against a single node.
 *
 * The user signs once. If the node rejects the block pin as stale — the
 * accepted window is only a handful of seconds on a fast chain — a fresh pin is
 * fetched and the same signed message re-posted, up to `maxPinRetries`.
 *
 * The session propagates to the other participants on its own. Set
 * `barrierNodeUrls` only when you want to wait for that to finish.
 *
 * @throws {ResolverAuthError} classified by cause — `isNodeMisconfiguration`
 *   separates a node that was never set up for this scheme from a user who is
 *   not enrolled, and `retryable` marks the pin failures already retried here.
 */
export async function authenticateWithResolver(
  config: ResolverSessionConfig,
  params: ResolverAuthParams,
): Promise<ResolverAuthResult> {
  if (!config.nodeUrl) throw new Error("nodeUrl is required");

  const sessionPubHex = assertSessionPubHex(params.sessionPubHex);
  const message = buildSiweMessage({ ...params.siwe, sessionPubHex });
  // Signed once, outside the retry loop: the pin is not covered by it.
  const signature = await params.signMessage(message);

  const maxAttempts = (config.maxPinRetries ?? 3) + 1;
  const nodes = [config.nodeUrl, ...(config.failoverNodeUrls ?? [])];
  let outcome: NodeAuthOutcome | undefined;
  let pinAttempts = 0;

  // Two loops with different reasons to go round. The outer one moves to
  // another node when this one never answered; the inner one refetches the
  // block pin against the *same* node when only the pin was stale. The pin
  // budget is per node, since a node that has not answered has not consumed it.
  for (const nodeUrl of nodes) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      const pin = await params.getBlockPin();
      pinAttempts++;
      const request = buildRequest(config.groupId, sessionPubHex, message, signature, pin);
      outcome = await authWithNode(nodeUrl, request, config.proxyEndpoint);

      if (outcome.ok) {
        const barrier = config.barrierNodeUrls?.length
          ? await Promise.all(
              config.barrierNodeUrls
                .filter((url) => url !== nodeUrl)
                .map((url) => authWithNode(url, request, config.proxyEndpoint)),
            )
          : undefined;

        return {
          identity: outcome.identity as string,
          expiresAt: outcome.expiresAt as number,
          nodeUrl,
          pinAttempts,
          ...(barrier ? { barrier } : {}),
        };
      }

      // Only a stale pin is worth another round trip to the same node.
      if (!outcome.error?.retryable) break;
    }

    // A verdict is a verdict — every node reads at the pinned block and would
    // say the same thing. Only an unanswered request is worth another node.
    if (!outcome?.error?.transport) break;
  }

  throw outcome?.error ??
    new ResolverAuthError("unknown", config.nodeUrl, "authentication failed");
}

/**
 * Authenticate against every listed node individually and report each outcome
 * without throwing.
 *
 * This is a rollout diagnostic, not the auth path — one node is enough for that
 * (see `authenticateWithResolver`). It exists because a node's own /v1/auth
 * verdict is the only readiness signal available client-side: /v1/info
 * advertises neither `siwe_domain` nor which chains it has RPC for, and the
 * initiator returns 200 on its own verification regardless of whether the
 * participants can do the resolver read. Contacting each node directly is what
 * makes a half-configured fleet visible before it matters.
 */
export async function preflightResolverNodes(
  config: Omit<ResolverSessionConfig, "nodeUrl" | "barrierNodeUrls"> & {
    nodeUrls: string[];
  },
  params: ResolverAuthParams,
): Promise<NodeAuthOutcome[]> {
  const sessionPubHex = assertSessionPubHex(params.sessionPubHex);
  const message = buildSiweMessage({ ...params.siwe, sessionPubHex });
  const signature = await params.signMessage(message);
  const pin = await params.getBlockPin();
  const request = buildRequest(config.groupId, sessionPubHex, message, signature, pin);

  return Promise.all(
    config.nodeUrls.map((url) => authWithNode(url, request, config.proxyEndpoint)),
  );
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface ResolverAuthRequest {
  group_id: string;
  session_pub: string;
  siwe_message: string;
  siwe_signature: string;
  block_number: number;
  block_hash: string;
}

function buildRequest(
  groupId: string,
  sessionPubHex: string,
  message: string,
  signature: string,
  pin: BlockPin,
): ResolverAuthRequest {
  return {
    group_id: groupId.toLowerCase(),
    session_pub: sessionPubHex,
    siwe_message: message,
    siwe_signature: signature,
    block_number: pin.number,
    block_hash: pin.hash,
  };
}

async function authWithNode(
  nodeUrl: string,
  request: ResolverAuthRequest,
  proxyEndpoint?: string,
): Promise<NodeAuthOutcome> {
  const url = proxyEndpoint ?? `${nodeUrl}/v1/auth`;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (proxyEndpoint) {
    headers["x-node-url"] = nodeUrl;
    headers["x-node-path"] = "/v1/auth";
  }

  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(request),
    });
  } catch (e) {
    return {
      nodeUrl,
      ok: false,
      error: new ResolverAuthError(
        "unknown",
        nodeUrl,
        `unreachable: ${e instanceof Error ? e.message : String(e)}`,
        undefined,
        true,
      ),
    };
  }

  if (!res.ok) {
    const body = await res.text();
    return {
      nodeUrl,
      ok: false,
      error: new ResolverAuthError(
        classifyResolverError(body),
        nodeUrl,
        body,
        res.status,
        isTransportStatus(res.status),
      ),
    };
  }

  // A 200 carrying a non-JSON body is a real case behind a CORS proxy, which
  // may answer for an upstream it could not reach. Classify it like any other
  // node failure rather than letting it escape the fanout as a SyntaxError.
  let data: { identity?: string; expires_at?: number };
  try {
    data = await res.json();
  } catch (e) {
    return {
      nodeUrl,
      ok: false,
      error: new ResolverAuthError(
        "unknown",
        nodeUrl,
        `malformed auth response: ${e instanceof Error ? e.message : String(e)}`,
        res.status,
      ),
    };
  }

  if (typeof data.identity !== "string" || typeof data.expires_at !== "number") {
    return {
      nodeUrl,
      ok: false,
      error: new ResolverAuthError(
        "unknown",
        nodeUrl,
        `auth response missing identity/expires_at: ${JSON.stringify(data)}`,
        res.status,
      ),
    };
  }

  return {
    nodeUrl,
    ok: true,
    identity: data.identity,
    expiresAt: data.expires_at,
  };
}

/**
 * The session key must reach the node as bare lowercase hex. Every other
 * public-key-shaped value in this SDK is 0x-prefixed, so prefixing here is the
 * natural mistake — and it surfaces as `missing session resource`, which does
 * not point at the cause.
 */
function assertSessionPubHex(hex: string): string {
  if (hex.startsWith("0x")) {
    throw new Error(
      `sessionPubHex must not be 0x-prefixed — the node matches the resource ` +
        `URI literally. Pass "${hex.slice(2)}" (this is exactly what ` +
        `generateSessionKeypair() returns in publicKeyHex).`,
    );
  }
  if (!/^[0-9a-f]{66}$/.test(hex)) {
    throw new Error(
      `sessionPubHex must be a 33-byte compressed secp256k1 key as 66 ` +
        `lowercase hex characters, got ${hex.length}`,
    );
  }
  return hex;
}

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(36).padStart(2, "0")).join("").slice(0, 24);
}

/** Convenience for callers holding a full keypair rather than the hex. */
export function sessionPubOf(keypair: SessionKeypair): string {
  return keypair.publicKeyHex;
}
