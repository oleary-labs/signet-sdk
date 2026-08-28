import { test, expect, beforeEach, afterEach } from "bun:test";
import {
  buildSiweMessage,
  sessionResourceUri,
  classifyResolverError,
  authenticateWithResolver,
  preflightResolverNodes,
  MAX_SESSION_SECONDS,
} from "./resolver-session.js";

const PUB = "02" + "ab".repeat(32);
const ADDRESS = "0x" + "11".repeat(20);
const NODES = ["http://n1", "http://n2", "http://n3", "http://n4", "http://n5", "http://n6"];

const SIWE = {
  domain: "app.sfluv.org",
  address: ADDRESS,
  chainId: 42220,
  nonce: "abcd1234efgh",
  issuedAt: new Date("2026-08-28T12:00:00.000Z"),
  expirationTime: new Date("2026-08-28T13:00:00.000Z"),
};

// ---------------------------------------------------------------------------
// SIWE message
// ---------------------------------------------------------------------------

// The exact bytes the node parses. Pinned literally rather than reconstructed,
// because every field position here is something the node rejects on, and a
// reconstruction would reproduce any bug in the builder. Verified byte-for-byte
// against viem's createSiweMessage.
const EXPECTED_NO_STATEMENT =
  "app.sfluv.org wants you to sign in with your Ethereum account:\n" +
  ADDRESS +
  "\n\n\n" +
  "URI: https://app.sfluv.org\n" +
  "Version: 1\n" +
  "Chain ID: 42220\n" +
  "Nonce: abcd1234efgh\n" +
  "Issued At: 2026-08-28T12:00:00.000Z\n" +
  "Expiration Time: 2026-08-28T13:00:00.000Z\n" +
  "Resources:\n" +
  "- signet://session/" + PUB;

test("builds the ERC-4361 message byte-for-byte", () => {
  expect(buildSiweMessage({ ...SIWE, sessionPubHex: PUB })).toBe(EXPECTED_NO_STATEMENT);
});

test("a statement sits between the two blank lines", () => {
  const msg = buildSiweMessage({ ...SIWE, sessionPubHex: PUB, statement: "Sign in to SFLuv." });
  expect(msg).toBe(EXPECTED_NO_STATEMENT.replace("\n\n\n", "\n\nSign in to SFLuv.\n\n"));
});

test("session resource is unprefixed lowercase hex", () => {
  expect(sessionResourceUri(PUB)).toBe(`signet://session/${PUB}`);
});

// 0x-prefixing is the natural mistake — every other pubkey-shaped value in the
// SDK carries one — and the node reports it as `missing session resource`,
// which does not point at the cause.
test("rejects a 0x-prefixed session key with a message naming the fix", () => {
  expect(() => buildSiweMessage({ ...SIWE, sessionPubHex: "0x" + PUB })).toThrow(
    /must not be 0x-prefixed/,
  );
});

test("rejects a session key that is not 33 bytes", () => {
  expect(() => buildSiweMessage({ ...SIWE, sessionPubHex: "02ab" })).toThrow(/33-byte/);
});

test("rejects a session longer than the node's cap", () => {
  expect(() =>
    buildSiweMessage({
      ...SIWE,
      sessionPubHex: PUB,
      expirationTime: new Date(SIWE.issuedAt.getTime() + (MAX_SESSION_SECONDS + 1) * 1000),
    }),
  ).toThrow(/caps sessions at 24h/);
});

test("rejects an expiry at or before issuance", () => {
  expect(() =>
    buildSiweMessage({ ...SIWE, sessionPubHex: PUB, expirationTime: SIWE.issuedAt }),
  ).toThrow(/must be after issuedAt/);
});

test("rejects a malformed signer address", () => {
  expect(() => buildSiweMessage({ ...SIWE, address: "nope", sessionPubHex: PUB })).toThrow(
    /20-byte address/,
  );
});

// A newline would let statement text impersonate the header fields below it.
test("rejects a statement containing a newline", () => {
  expect(() =>
    buildSiweMessage({ ...SIWE, sessionPubHex: PUB, statement: "a\nResources:" }),
  ).toThrow(/must not contain a newline/);
});

test("generates a conforming nonce when none is given", () => {
  const msg = buildSiweMessage({ ...SIWE, nonce: undefined, sessionPubHex: PUB });
  const nonce = msg.match(/^Nonce: (.+)$/m)![1];
  expect(nonce.length).toBeGreaterThanOrEqual(8);
  expect(nonce).toMatch(/^[a-zA-Z0-9]+$/);
});

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

test("classifies every documented node error", () => {
  const cases: Array<[string, string]> = [
    ["siwe domain not configured", "siwe_domain_not_configured"],
    ["group has no auth resolver configured", "no_resolver_bound"],
    ["no RPC configured for chain 42220", "no_chain_rpc"],
    ['unsupported resolver version "SignetAuthResolver 2.0.0"', "unsupported_resolver_version"],
    ["siwe chain id 8453 != resolver chain id 42220", "chain_id_mismatch"],
    ["missing session resource signet://session/02ab", "missing_session_resource"],
    ["siwe message missing expiration time", "missing_expiration"],
    ["verify siwe: signature mismatch", "siwe_verification_failed"],
    ["pinned block 100 too stale (max lag 30)", "block_pin_stale"],
    ["pinned block 200 ahead of head 150", "block_pin_ahead"],
    ["pinned block hash mismatch at 100", "block_pin_hash_mismatch"],
    ["resolver did not authorize address 0xabc", "not_authorized"],
    ["something else entirely", "unknown"],
  ];
  for (const [msg, code] of cases) {
    expect(classifyResolverError(`resolver auth failed: ${msg}`)).toBe(code);
  }
});

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

const okResponse = () =>
  new Response(JSON.stringify({ identity: "0xSAFE", expires_at: 999 }), { status: 200 });
const errResponse = (msg: string) =>
  new Response(`resolver auth failed: ${msg}`, { status: 401 });

let signCalls = 0;
let pinCalls = 0;
let posted: string[] = [];

function harness(responder: (url: string, attempt: number) => Response) {
  signCalls = 0;
  pinCalls = 0;
  posted = [];
  globalThis.fetch = (async (url: string) => {
    posted.push(String(url));
    return responder(String(url), pinCalls);
  }) as unknown as typeof fetch;
  return {
    sessionPubHex: PUB,
    siwe: SIWE,
    signMessage: async () => {
      signCalls++;
      return "0x" + "aa".repeat(65);
    },
    getBlockPin: async () => {
      pinCalls++;
      return { number: 100 + pinCalls, hash: "0x" + "bb".repeat(32) };
    },
  };
}

const config = { groupId: "0xGROUP", nodeUrl: NODES[0] };

beforeEach(() => {
  signCalls = 0;
  pinCalls = 0;
  posted = [];
});

// Nodes are symmetric: /v1/auth broadcasts msgAuth and every participant
// re-verifies the SIWE recovery and the resolver read itself. Contacting more
// than one is a propagation barrier, never a correctness requirement.
test("authenticates against a single node", async () => {
  const result = await authenticateWithResolver(config, harness(() => okResponse()));
  expect(result.identity).toBe("0xSAFE");
  expect(result.nodeUrl).toBe(NODES[0]);
  expect(result.pinAttempts).toBe(1);
  expect(posted).toEqual([`${NODES[0]}/v1/auth`]);
  expect(result.barrier).toBe(undefined);
});

test("throws the node's classified error", async () => {
  await expect(
    authenticateWithResolver(
      config,
      harness(() => errResponse("resolver did not authorize address 0x1")),
    ),
  ).rejects.toThrow(/not_authorized/);
});

test("surfaces a misconfigured node distinctly from an unenrolled user", async () => {
  try {
    await authenticateWithResolver(
      config,
      harness(() => errResponse("no RPC configured for chain 42220")),
    );
    throw new Error("expected a rejection");
  } catch (e) {
    const err = e as { code: string; isNodeMisconfiguration: boolean };
    expect(err.code).toBe("no_chain_rpc");
    expect(err.isNodeMisconfiguration).toBe(true);
  }
});

// The pin is not covered by the signed message, so a staleness retry must not
// re-prompt the user. An app hand-rolling this would naturally re-sign.
test("retries a stale pin without asking for a second signature", async () => {
  const result = await authenticateWithResolver(
    config,
    harness((_url, attempt) =>
      attempt === 1 ? errResponse("pinned block 101 too stale (max lag 30)") : okResponse(),
    ),
  );
  expect(result.pinAttempts).toBe(2);
  expect(signCalls).toBe(1);
  expect(pinCalls).toBe(2);
});

test("does not retry an error a fresh pin cannot fix", async () => {
  await expect(
    authenticateWithResolver(config, harness(() => errResponse("siwe domain not configured"))),
  ).rejects.toThrow();
  expect(pinCalls).toBe(1);
});

test("stops after maxPinRetries", async () => {
  await expect(
    authenticateWithResolver(
      { ...config, maxPinRetries: 2 },
      harness(() => errResponse("pinned block 101 too stale (max lag 30)")),
    ),
  ).rejects.toThrow();
  expect(pinCalls).toBe(3); // initial attempt + 2 retries
});

// The barrier waits out the asynchronous broadcast; it does not gate the result.
test("barrier posts to the other nodes and reports them", async () => {
  const result = await authenticateWithResolver(
    { ...config, barrierNodeUrls: NODES },
    harness((url) => (url.startsWith(NODES[0]) ? okResponse() : errResponse("verify siwe: not yet"))),
  );
  expect(result.identity).toBe("0xSAFE");
  expect(result.barrier!.length).toBe(NODES.length - 1); // primary not re-posted
  expect(result.barrier!.every((o) => !o.ok)).toBe(true);
  expect(signCalls).toBe(1);
});

test("preflight reports every node without throwing", async () => {
  let n = 0;
  const report = await preflightResolverNodes(
    { groupId: "0xGROUP", nodeUrls: NODES },
    harness(() => (++n <= 2 ? okResponse() : errResponse("siwe domain not configured"))),
  );
  expect(report.length).toBe(6);
  expect(report.filter((o) => o.ok).length).toBe(2);
  expect(report.filter((o) => o.error?.isNodeMisconfiguration).map((o) => o.nodeUrl)).toEqual([
    "http://n3",
    "http://n4",
    "http://n5",
    "http://n6",
  ]);
});

// A CORS proxy can answer 200 for an upstream it never reached.
test("classifies a 200 carrying a non-JSON body", async () => {
  await expect(
    authenticateWithResolver(
      config,
      harness(() => new Response("<html>502 Bad Gateway</html>", { status: 200 })),
    ),
  ).rejects.toThrow(/malformed auth response/);
});

test("rejects a 200 that omits identity", async () => {
  await expect(
    authenticateWithResolver(
      config,
      harness(() => new Response(JSON.stringify({ expires_at: 1 }), { status: 200 })),
    ),
  ).rejects.toThrow(/missing identity/);
});

test("surfaces a transport failure as an unknown-code outcome", async () => {
  globalThis.fetch = (async () => {
    throw new Error("ECONNREFUSED");
  }) as typeof fetch;
  const report = await preflightResolverNodes(
    { groupId: "0xGROUP", nodeUrls: NODES },
    {
      sessionPubHex: PUB,
      siwe: SIWE,
      signMessage: async () => "0x" + "aa".repeat(65),
      getBlockPin: async () => ({ number: 101, hash: "0x" + "bb".repeat(32) }),
    },
  );
  expect(report.every((o) => o.error?.code === "unknown")).toBe(true);
  expect(report[0].error?.retryable).toBe(false);
});
