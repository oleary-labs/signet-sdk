/**
 * Signet UserOperation pipeline.
 *
 * Framework-agnostic orchestration of the full ERC-4337 flow:
 *   build → (paymaster stub) → estimate → (paymaster real) → hash → FROST sign → submit → confirm
 *
 * The caller provides an already-encoded callData (the app-specific part);
 * everything else is generic Signet protocol logic.
 */

import {
  type Address,
  type Hex,
  encodeFunctionData,
  encodeAbiParameters,
  keccak256,
  concat,
  createPublicClient,
  http,
} from "viem";
import type { SessionKeypair, IdTokenClaims } from "./types";
import { signSignRequest } from "./request";
import {
  sendUserOp as bundlerSendUserOp,
  getUserOpReceipt as bundlerGetUserOpReceipt,
  estimateUserOpGas,
  getPaymasterStubData,
  getPaymasterData,
  applyPaymasterSponsorship,
  type PaymasterContext,
} from "./bundler";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * ERC-4337 PackedUserOperation.
 *
 * This is the format expected by the EntryPoint and validated
 * by SignetAccount.validateUserOp. The signature field carries
 * a 65-byte FROST Schnorr signature (Rx || z || v).
 */
export interface PackedUserOperation {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex;
  preVerificationGas: bigint;
  gasFees: Hex;
  paymasterAndData: Hex;
  signature: Hex;
}

export type UserOpStatus =
  | "building"
  | "sponsoring-stub"
  | "estimating"
  | "sponsoring"
  | "signing"
  | "submitting"
  | "confirming";

export interface SignetWriteConfig {
  rpcUrl: string;
  chainId: number;
  entryPointAddress: Address;
  bundlerProxyUrl: string;
  nodeProxyUrl: string;
  bootstrapGroup: Address;
  bootstrapNodes: string[];
  accountFactoryAddress: Address;
  accountFactoryAbi: readonly Record<string, unknown>[];
  usePaymaster: boolean;
  paymasterContext?: PaymasterContext;
}

export interface SignetWriteParams {
  account: Address;
  groupPublicKey: Hex;
  dest: Address;
  value?: bigint;
  callData: Hex;
  sessionKeypair: SessionKeypair;
  claims: IdTokenClaims;
  onStatus?: (status: UserOpStatus) => void;
}

export interface SignetWriteResult {
  userOpHash: Hex;
  transactionHash: Hex;
}

// ---------------------------------------------------------------------------
// Main pipeline
// ---------------------------------------------------------------------------

/**
 * Submit a UserOperation through the full Signet pipeline.
 *
 * Ordering is strict — see CLAUDE.md "Write flow ordering" for rationale:
 * 1. Build unsigned UserOp (with initCode if account not deployed)
 * 2. (if paymaster) Attach stub paymasterAndData for gas estimation
 * 3. Estimate gas via bundler
 * 4. (if paymaster) Replace stub with real signed paymaster blob
 * 5. Compute UserOp hash
 * 6. FROST threshold sign via bootstrap group
 * 7. Submit to bundler
 * 8. Poll for receipt
 */
export async function submitUserOp(
  config: SignetWriteConfig,
  params: SignetWriteParams
): Promise<SignetWriteResult> {
  const { onStatus } = params;

  // 1. Build the UserOperation
  onStatus?.("building");
  const nonce = await fetchNonce(config.rpcUrl, config.entryPointAddress, params.account);
  const initCode = await buildInitCode(config, params.account, params.groupPublicKey);

  let userOp = buildUserOp({
    sender: params.account,
    nonce,
    initCode,
    dest: params.dest,
    value: params.value,
    callData: params.callData,
  });

  // 2. (optional) Attach paymaster stub before gas estimation
  if (config.usePaymaster) {
    onStatus?.("sponsoring-stub");
    const stub = await getPaymasterStubData(
      config.bundlerProxyUrl, config.entryPointAddress, config.chainId, userOp,
      config.paymasterContext,
    );
    userOp = applyPaymasterSponsorship(userOp, stub);
  }

  // 3. Estimate gas
  onStatus?.("estimating");
  const gasEstimate = await estimateUserOpGas(
    config.bundlerProxyUrl, config.entryPointAddress, userOp
  );
  userOp.accountGasLimits =
    `0x${BigInt(gasEstimate.verificationGasLimit).toString(16).padStart(32, "0")}${BigInt(gasEstimate.callGasLimit).toString(16).padStart(32, "0")}` as Hex;
  userOp.preVerificationGas = BigInt(gasEstimate.preVerificationGas);

  // 4. (optional) Replace stub with real signed paymaster blob
  if (config.usePaymaster) {
    onStatus?.("sponsoring");
    const real = await getPaymasterData(
      config.bundlerProxyUrl, config.entryPointAddress, config.chainId, userOp,
      config.paymasterContext,
    );
    userOp = applyPaymasterSponsorship(userOp, real);
  }

  // 5. Hash + 6. FROST threshold sign
  onStatus?.("signing");
  const opHash = getUserOpHash(userOp, config.entryPointAddress, config.chainId);
  const messageHash = hexToBytes(opHash);

  const signReq = await signSignRequest(
    params.sessionKeypair,
    params.claims,
    config.bootstrapGroup,
    messageHash,
  );

  const signRes = await fetch(config.nodeProxyUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-node-url": config.bootstrapNodes[0],
      "x-node-path": "/v1/sign",
    },
    body: JSON.stringify(signReq),
  });

  if (!signRes.ok) {
    const body = await signRes.text();
    throw new Error(`Threshold signing failed: ${signRes.status} — ${body}`);
  }

  const { ethereum_signature } = await signRes.json();
  userOp.signature = ethereum_signature as Hex;

  // 7. Submit to bundler
  onStatus?.("submitting");
  const { userOpHash } = await bundlerSendUserOp(
    config.bundlerProxyUrl, config.entryPointAddress, userOp
  );

  // 8. Poll for receipt
  onStatus?.("confirming");
  let receipt = null;
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    receipt = await bundlerGetUserOpReceipt(config.bundlerProxyUrl, userOpHash);
    if (receipt) break;
  }

  if (!receipt) throw new Error("Transaction confirmation timed out");
  if (!receipt.success) throw new Error("UserOperation reverted on-chain");

  return { userOpHash, transactionHash: receipt.transactionHash };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/**
 * Build an unsigned UserOperation for a SignetAccount.execute call.
 */
export function buildUserOp(params: {
  sender: Address;
  nonce: bigint;
  initCode?: Hex;
  dest: Address;
  value?: bigint;
  callData: Hex;
}): PackedUserOperation {
  const executeCallData = encodeFunctionData({
    abi: [
      {
        name: "execute",
        type: "function",
        inputs: [
          { name: "dest", type: "address" },
          { name: "value", type: "uint256" },
          { name: "data", type: "bytes" },
        ],
        outputs: [],
      },
    ],
    functionName: "execute",
    args: [params.dest, params.value ?? 0n, params.callData],
  });

  return {
    sender: params.sender,
    nonce: params.nonce,
    initCode: params.initCode ?? "0x",
    callData: executeCallData,
    accountGasLimits: "0x000000000000000000000000000f4240000000000000000000000000001e8480",
    preVerificationGas: 50000n,
    gasFees: "0x000000000000000000000000000000010000000000000000000000003b9aca00",
    paymasterAndData: "0x",
    signature: "0x",
  };
}

/**
 * Compute the UserOperation hash for signing.
 *
 * Matches EntryPoint v0.7 packed format:
 *   keccak256(abi.encode(keccak256(packedFields), entryPoint, chainId))
 */
export function getUserOpHash(
  userOp: PackedUserOperation,
  entryPoint: Address,
  chainId: number
): Hex {
  const packedHash = keccak256(
    encodeAbiParameters(
      [
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        userOp.sender,
        userOp.nonce,
        keccak256(userOp.initCode),
        keccak256(userOp.callData),
        userOp.accountGasLimits as Hex,
        userOp.preVerificationGas,
        userOp.gasFees as Hex,
        keccak256(userOp.paymasterAndData),
      ]
    )
  );

  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
      [packedHash, entryPoint, BigInt(chainId)]
    )
  );
}

/**
 * Fetch the current nonce for an account from the EntryPoint.
 */
export async function fetchNonce(
  rpcUrl: string,
  entryPointAddress: Address,
  account: Address
): Promise<bigint> {
  const client = createPublicClient({ transport: http(rpcUrl) });
  return client.readContract({
    address: entryPointAddress,
    abi: [{
      name: "getNonce",
      type: "function",
      inputs: [
        { name: "sender", type: "address" },
        { name: "key", type: "uint192" },
      ],
      outputs: [{ type: "uint256" }],
      stateMutability: "view",
    }],
    functionName: "getNonce",
    args: [account, 0n],
  }) as Promise<bigint>;
}

/**
 * Check if a SignetAccount is deployed at the given address.
 */
export async function isAccountDeployed(
  rpcUrl: string,
  account: Address
): Promise<boolean> {
  const client = createPublicClient({ transport: http(rpcUrl) });
  const code = await client.getCode({ address: account });
  return !!code && code !== "0x";
}

/**
 * Build initCode for deploying a SignetAccount via the account factory.
 * Returns "0x" if the account is already deployed.
 */
export async function buildInitCode(
  config: Pick<SignetWriteConfig, "rpcUrl" | "accountFactoryAddress" | "accountFactoryAbi" | "entryPointAddress">,
  account: Address,
  groupPublicKey: Hex
): Promise<Hex> {
  const deployed = await isAccountDeployed(config.rpcUrl, account);
  if (deployed) return "0x";

  const factoryCallData = encodeFunctionData({
    abi: config.accountFactoryAbi,
    functionName: "createAccount",
    args: [config.entryPointAddress, groupPublicKey, 0n],
  } as Parameters<typeof encodeFunctionData>[0]);

  return concat([config.accountFactoryAddress, factoryCallData]);
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: Hex): Uint8Array {
  return new Uint8Array(
    (hex.slice(2).match(/.{2}/g) ?? []).map((b) => parseInt(b, 16))
  );
}
