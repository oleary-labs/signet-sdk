import { test, expect, afterEach } from "bun:test";
import { toEvmSignature, eip191Digest, signEvmDigest } from "./signature.js";

const HASH = new Uint8Array(32).fill(0x11);
const KEYPAIR = {
  privateKey: new Uint8Array(32).fill(7),
  publicKeyHex: "02" + "ab".repeat(32),
};
const SUBJECT = "0x" + "00".repeat(12) + "ab".repeat(20);
const CONFIG = { groupId: "0xGROUP", nodeUrl: "http://n1" };

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

let bodies: Array<Record<string, unknown>> = [];
let urls: string[] = [];
let headers: Array<Record<string, string>> = [];

function respond(body: unknown, status = 200) {
  bodies = [];
  urls = [];
  headers = [];
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    urls.push(String(url));
    headers.push(init.headers as Record<string, string>);
    bodies.push(JSON.parse(String(init.body)));
    return new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
}

// v arrives as {0,1} from the node and is rejected by ecrecover, OZ's
// ECDSA.recover, and Safe's checkSignatures alike. Nothing in a JS round-trip
// catches it, so the helper must not hand back an un-normalized signature.
test("normalizes v before returning", async () => {
  respond({ ecdsa_signature: "0x" + "cd".repeat(64) + "00" });
  const out = await signEvmDigest(CONFIG, { keypair: KEYPAIR, hash: HASH, identity: SUBJECT });
  expect(out.signature.slice(-2)).toBe("1b"); // 27
  expect(out.keyId).toBe(SUBJECT);
});

test("applies the EIP-191 envelope by default and skips it on request", async () => {
  respond({ ecdsa_signature: "0x" + "cd".repeat(64) + "01" });
  const wrapped = await signEvmDigest(CONFIG, { keypair: KEYPAIR, hash: HASH, identity: SUBJECT });
  expect(wrapped.digest).toBe(
    "0x" + Array.from(eip191Digest(HASH), (b) => b.toString(16).padStart(2, "0")).join(""),
  );

  respond({ ecdsa_signature: "0x" + "cd".repeat(64) + "01" });
  const bare = await signEvmDigest(CONFIG, {
    keypair: KEYPAIR,
    hash: HASH,
    identity: SUBJECT,
    eip191: false,
  });
  expect(bare.digest).toBe("0x" + "11".repeat(32));
});

// Omitting curve is the documented footgun: the node silently answers with
// Schnorr under a different field, and the mismatch surfaces on-chain.
test("always pins the ECDSA curve in the request", async () => {
  respond({ ecdsa_signature: "0x" + "cd".repeat(64) + "00" });
  await signEvmDigest(CONFIG, { keypair: KEYPAIR, hash: HASH, identity: SUBJECT });
  expect(bodies[0].curve).toBe("ecdsa_secp256k1");
  // The logical key id is never in the body — the node derives it from session.
  expect(bodies[0].key_id).toBe(undefined);
});

test("names the cause when the key turns out to be Schnorr", async () => {
  respond({ ethereum_signature: "0x" + "cd".repeat(65) });
  await expect(
    signEvmDigest(CONFIG, { keypair: KEYPAIR, hash: HASH, identity: SUBJECT }),
  ).rejects.toThrow(/FROST Schnorr, not ECDSA/);
});

test("routes through a proxy with the node in a header", async () => {
  respond({ ecdsa_signature: "0x" + "cd".repeat(64) + "00" });
  await signEvmDigest(
    { ...CONFIG, proxyEndpoint: "https://proxy.example/rpc" },
    { keypair: KEYPAIR, hash: HASH, identity: SUBJECT },
  );
  expect(urls[0]).toBe("https://proxy.example/rpc");
  expect(headers[0]["x-node-url"]).toBe("http://n1");
  expect(headers[0]["x-node-path"]).toBe("/v1/sign");
});

test("posts directly to /v1/sign with no proxy", async () => {
  respond({ ecdsa_signature: "0x" + "cd".repeat(64) + "00" });
  await signEvmDigest(CONFIG, { keypair: KEYPAIR, hash: HASH, identity: SUBJECT });
  expect(urls[0]).toBe("http://n1/v1/sign");
});

test("rejects a hash that is not 32 bytes", async () => {
  respond({ ecdsa_signature: "0x" + "cd".repeat(64) + "00" });
  await expect(
    signEvmDigest(CONFIG, { keypair: KEYPAIR, hash: "0xdeadbeef", identity: SUBJECT }),
  ).rejects.toThrow(/32-byte hash/);
});

test("a 200 carrying a non-JSON body is classified, not thrown raw", async () => {
  respond("<html>502</html>");
  await expect(
    signEvmDigest(CONFIG, { keypair: KEYPAIR, hash: HASH, identity: SUBJECT }),
  ).rejects.toThrow(/malformed sign response/);
});

test("toEvmSignature is idempotent", () => {
  const raw = "0x" + "cd".repeat(64) + "00";
  const once = toEvmSignature(raw);
  expect(toEvmSignature(once)).toBe(once);
});
