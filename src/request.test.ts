import { test, expect } from "bun:test";
import { deriveKeyId } from "./request.js";

const CLAIMS = {
  iss: "https://accounts.google.com",
  sub: "114810956681671373980",
  email: "a@b.c",
  azp: "x",
  aud: "x",
  exp: 0,
  iat: 0,
};

test("an OAuth key id is iss:sub", () => {
  expect(deriveKeyId(CLAIMS)).toBe("https://accounts.google.com:114810956681671373980");
  expect(deriveKeyId(CLAIMS, "agent-1")).toBe(
    "https://accounts.google.com:114810956681671373980:agent-1",
  );
});

// Every non-OAuth scheme derives the whole key id from `identity`. Requiring a
// claims object there produced a stub of empty strings that read as meaningful.
test("identity alone derives the key id, with no claims object", () => {
  const subject = "0x" + "00".repeat(12) + "ab".repeat(20);
  expect(deriveKeyId(null, undefined, subject)).toBe(subject);
  expect(deriveKeyId(null, "evm", subject)).toBe(`${subject}:evm`);
});

// A stub of empty strings used to derive ":" and be signed over — a request the
// node rejects as an opaque 401.
test("supplying neither claims nor identity throws", () => {
  expect(() => deriveKeyId(null)).toThrow(/either `claims`.*or.*`identity`/s);
  expect(() => deriveKeyId(null, "evm")).toThrow();
});

test("identity still wins when both are supplied", () => {
  expect(deriveKeyId(CLAIMS, "evm", "0xabc")).toBe("0xabc:evm");
});

test("rejects an identity carrying a namespace the node adds itself", () => {
  expect(() => deriveKeyId(null, undefined, "resolver:0xdead:0xbeef")).toThrow(
    /must not include the "resolver:" namespace/,
  );
});
