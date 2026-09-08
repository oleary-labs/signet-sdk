import { test, expect, afterEach } from "bun:test";
import {
  withNodeFailover,
  NodeTransportError,
  AllNodesFailedError,
  isTransportStatus,
  postJson,
} from "./failover.js";

const NODES = ["http://n1", "http://n2", "http://n3"];

test("classifies only unanswered requests as transport-tier", () => {
  for (const s of [500, 502, 503, 504, 429, 408]) expect(isTransportStatus(s)).toBe(true);
  // A verdict every node would reach alike. Failing over hides the cause.
  for (const s of [200, 400, 401, 403, 404, 409]) expect(isTransportStatus(s)).toBe(false);
});

test("advances past unreachable nodes and returns the first success", async () => {
  const tried: string[] = [];
  const got = await withNodeFailover(NODES, async (url) => {
    tried.push(url);
    if (url !== "http://n3") throw new NodeTransportError(url, "refused");
    return "ok";
  });
  expect(got).toBe("ok");
  expect(tried).toEqual(NODES);
});

// The whole design rests on this: a 401 or 409 is an answer, and asking four
// more nodes turns one clear error into five identical ones.
test("a verdict propagates from the first node without trying another", async () => {
  const tried: string[] = [];
  await expect(
    withNodeFailover(NODES, async (url) => {
      tried.push(url);
      throw new Error("unauthorized");
    }),
  ).rejects.toThrow("unauthorized");
  expect(tried).toEqual(["http://n1"]);
});

test("an exhausted fleet reports every node it tried", async () => {
  try {
    await withNodeFailover(NODES, async (url) => {
      throw new NodeTransportError(url, "refused", 503);
    });
    throw new Error("expected a rejection");
  } catch (e) {
    expect(e).toBeInstanceOf(AllNodesFailedError);
    const err = e as AllNodesFailedError;
    expect(err.attempts.map((a) => a.nodeUrl)).toEqual(NODES);
    expect(err.attempts.every((a) => a.status === 503)).toBe(true);
    for (const url of NODES) expect(err.message).toContain(url);
  }
});

test("an empty node list is a programming error, not an empty fleet", async () => {
  await expect(withNodeFailover([], async () => "x")).rejects.toThrow(/at least one node/);
});

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

test("postJson raises transport errors and passes verdicts through", async () => {
  globalThis.fetch = (async () => new Response("boom", { status: 503 })) as typeof fetch;
  await expect(postJson("http://n1", "/v1/sign", {})).rejects.toBeInstanceOf(NodeTransportError);

  globalThis.fetch = (async () => new Response("nope", { status: 401 })) as typeof fetch;
  const res = await postJson("http://n1", "/v1/sign", {});
  expect(res.status).toBe(401);

  globalThis.fetch = (async () => {
    throw new Error("ECONNREFUSED");
  }) as typeof fetch;
  await expect(postJson("http://n1", "/v1/sign", {})).rejects.toThrow(/unreachable/);
});

test("postJson puts the node in a header when proxied", async () => {
  let seen: { url: string; headers: Record<string, string> } | undefined;
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    seen = { url: String(url), headers: init.headers as Record<string, string> };
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;

  await postJson("http://n1", "/v1/keygen", {}, "https://proxy.example");
  expect(seen!.url).toBe("https://proxy.example");
  expect(seen!.headers["x-node-url"]).toBe("http://n1");
  expect(seen!.headers["x-node-path"]).toBe("/v1/keygen");
});
