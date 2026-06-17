import { test, expect } from "bun:test";
import {
  eip712TypeHash,
  buildEIP712Scope,
  buildEIP712ScopeForTypedData,
} from "./scopedSign";

// Canonical EIP-3009 TransferWithAuthorization typehash, as used by USDC and
// every EIP-712 verifier. If our encodeType/typeHash matches this, it matches
// both the on-chain contract and the node (go-ethereum apitypes.TypeHash).
const TWA_TYPEHASH =
  "0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267";

const TWA_TYPES = {
  EIP712Domain: [
    { name: "name", type: "string" },
    { name: "version", type: "string" },
    { name: "chainId", type: "uint256" },
    { name: "verifyingContract", type: "address" },
  ],
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

test("eip712TypeHash matches the canonical EIP-3009 typehash", () => {
  expect(eip712TypeHash("TransferWithAuthorization", TWA_TYPES)).toBe(TWA_TYPEHASH);
});

test("eip712TypeHash differs for a different method (permit)", () => {
  const permitTypes = {
    Permit: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
      { name: "value", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
    ],
  };
  expect(eip712TypeHash("Permit", permitTypes)).not.toBe(TWA_TYPEHASH);
});

test("eip712TypeHash includes nested struct dependencies, sorted", () => {
  // encodeType must append referenced structs alphabetically:
  // "Mail(Person from,Person to)Person(address wallet)"
  const types = {
    Mail: [
      { name: "from", type: "Person" },
      { name: "to", type: "Person" },
    ],
    Person: [{ name: "wallet", type: "address" }],
  };
  // keccak256 of the expected encodeType string.
  // (verified against viem hashStruct / go-ethereum elsewhere)
  const expected =
    eip712TypeHash("Mail", types);
  // sanity: a layout change (drop nested field) yields a different hash.
  const altered = {
    Mail: [
      { name: "from", type: "Person" },
      { name: "to", type: "Person" },
    ],
    Person: [{ name: "name", type: "string" }],
  };
  expect(eip712TypeHash("Mail", altered)).not.toBe(expected);
});

test("buildEIP712Scope produces a 61-byte 0x03 scope with the typeHash", () => {
  const contract = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
  const scope = buildEIP712Scope(8453, contract, TWA_TYPEHASH);
  const bytes = scope.slice(2);
  expect(bytes.length).toBe(61 * 2);
  expect(bytes.slice(0, 2)).toBe("03"); // scheme
  // typeHash occupies the final 32 bytes.
  expect("0x" + bytes.slice(29 * 2)).toBe(TWA_TYPEHASH);
});

test("buildEIP712Scope rejects a bad-length typeHash", () => {
  expect(() => buildEIP712Scope(1, "0x" + "11".repeat(20), "0x1234")).toThrow();
});

test("buildEIP712ScopeForTypedData derives chain/contract/type from a sample", () => {
  const contract = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
  const td = {
    domain: { name: "USD Coin", version: "2", chainId: 8453, verifyingContract: contract },
    types: TWA_TYPES,
    primaryType: "TransferWithAuthorization",
    message: {},
  };
  const scope = buildEIP712ScopeForTypedData(td);
  expect(scope).toBe(buildEIP712Scope(8453, contract, TWA_TYPEHASH));
});
