import { test, expect, afterEach } from "bun:test";
import { keygen } from "./keygen.js";

const KEYPAIR = { privateKey: new Uint8Array(32).fill(7), publicKeyHex: "02" + "ab".repeat(32) };
const NODES = ["http://n1", "http://n2", "http://n3"];
const CONFIG = { groupId: "0xGROUP", nodeUrls: NODES };
const SUBJECT = "0x" + "00".repeat(12) + "ab".repeat(20);

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

let tried: string[] = [];
function harness(responder: (url: string) => Response) {
  tried = [];
  globalThis.fetch = (async (url: string) => {
    tried.push(String(url));
    return responder(String(url));
  }) as unknown as typeof fetch;
}

const created = () =>
  new Response(
    JSON.stringify({ key_id: SUBJECT, ethereum_address: "0xabc", public_key: "0xdef" }),
    { status: 200 },
  );

// Failover is safe because the initiating node does not return until every node
// has acked the start of the protocol — so a node reached afterwards answers
// 409 rather than starting a competing DKG.
test("advances past an unreachable node", async () => {
  harness((url) =>
    url.startsWith(NODES[0]) ? new Response("down", { status: 503 }) : created(),
  );
  const out = await keygen(CONFIG, KEYPAIR, null, undefined, SUBJECT);
  expect(out.keyId).toBe(SUBJECT);
  expect(tried).toEqual([`${NODES[0]}/v1/keygen`, `${NODES[1]}/v1/keygen`]);
});

test("a 409 with key material is success, not failure", async () => {
  harness(() =>
    new Response(
      JSON.stringify({ key_id: SUBJECT, ethereum_address: "0xabc", public_key: "0xdef" }),
      { status: 409 },
    ),
  );
  const out = await keygen(CONFIG, KEYPAIR, null, undefined, SUBJECT);
  expect(out.alreadyExisted).toBe(true);
  expect(out.groupPublicKey).toBe("0xdef");
  expect(tried.length).toBe(1); // 409 is a verdict — no failover
});

// The ack precedes completion, so a retry can land inside the DKG window. This
// used to return empty strings, which read as a successful keygen and failed
// later at the point of use.
test("a 409 without key material says the DKG is still running", async () => {
  harness(() => new Response(JSON.stringify({ key_id: SUBJECT }), { status: 409 }));
  await expect(keygen(CONFIG, KEYPAIR, null, undefined, SUBJECT)).rejects.toThrow(
    /already in progress.*DKG has started and not yet completed/s,
  );
});

test("a verdict does not fan out across the fleet", async () => {
  harness(() => new Response("unauthorized", { status: 401 }));
  await expect(keygen(CONFIG, KEYPAIR, null, undefined, SUBJECT)).rejects.toThrow(/401/);
  expect(tried.length).toBe(1);
});

test("an entirely unreachable fleet names every node", async () => {
  harness(() => new Response("down", { status: 503 }));
  await expect(keygen(CONFIG, KEYPAIR, null, undefined, SUBJECT)).rejects.toThrow(
    /all 3 nodes failed to respond/,
  );
  expect(tried.length).toBe(3);
});
