/**
 * Bundler RPC client for ERC-4337 UserOperations.
 *
 * Framework-agnostic — all config is passed in, no env imports.
 * Handles serialization between the packed UserOp format (used
 * internally and for hashing) and the unpacked v0.7 RPC format
 * expected by signet-min-bundler.
 */

import { type Address, type Hex, concat } from "viem";
import type { PackedUserOperation } from "./userop";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BundlerSendResult {
  userOpHash: Hex;
}

export interface UserOpReceipt {
  userOpHash: Hex;
  transactionHash: Hex;
  success: boolean;
}

export interface GasEstimate {
  preVerificationGas: Hex;
  verificationGasLimit: Hex;
  callGasLimit: Hex;
}

/**
 * ERC-7677 paymaster sponsorship result.
 *
 * The bundler returns paymaster gas limits as separate fields, but
 * signet-min-bundler's wire format for eth_sendUserOperation expects
 * them packed into the front of `paymasterData` (see packPaymasterData
 * and the note on the getHash comment in internal/paymaster/paymaster.go).
 */
export interface PaymasterSponsorship {
  paymaster: Address;
  paymasterData: Hex;
  paymasterVerificationGasLimit: Hex;
  paymasterPostOpGasLimit: Hex;
}

/**
 * ERC-7677 context object passed as the 4th parameter to
 * pm_getPaymasterStubData / pm_getPaymasterData.
 */
export interface PaymasterContext {
  invite_code?: string;
}

// ---------------------------------------------------------------------------
// Bundler RPC
// ---------------------------------------------------------------------------

export async function sendUserOp(
  bundlerUrl: string,
  entryPointAddress: Address,
  userOp: PackedUserOperation
): Promise<BundlerSendResult> {
  const json = await bundlerRpc(bundlerUrl, "eth_sendUserOperation", [
    serializeUserOp(userOp),
    entryPointAddress,
  ]);
  return { userOpHash: json.result };
}

export async function getUserOpReceipt(
  bundlerUrl: string,
  userOpHash: Hex
): Promise<UserOpReceipt | null> {
  const json = await bundlerRpc(bundlerUrl, "eth_getUserOperationReceipt", [
    userOpHash,
  ]);

  if (!json.result) return null;

  return {
    userOpHash: json.result.userOpHash,
    transactionHash: json.result.transactionHash,
    success: json.result.success,
  };
}

export async function estimateUserOpGas(
  bundlerUrl: string,
  entryPointAddress: Address,
  userOp: PackedUserOperation
): Promise<GasEstimate> {
  const json = await bundlerRpc(bundlerUrl, "eth_estimateUserOperationGas", [
    serializeUserOp(userOp),
    entryPointAddress,
  ]);
  return json.result;
}

// ---------------------------------------------------------------------------
// ERC-7677 Paymaster
// ---------------------------------------------------------------------------

/**
 * Call pm_getPaymasterStubData.
 *
 * Returns paymaster fields with a correctly-sized but zeroed signature,
 * suitable for gas estimation. Call this BEFORE eth_estimateUserOperationGas
 * so the estimate accounts for the paymaster's verification overhead.
 */
export async function getPaymasterStubData(
  bundlerUrl: string,
  entryPointAddress: Address,
  chainId: number,
  userOp: PackedUserOperation,
  context?: PaymasterContext,
): Promise<PaymasterSponsorship> {
  return paymasterCall(bundlerUrl, entryPointAddress, chainId, "pm_getPaymasterStubData", userOp, context);
}

/**
 * Call pm_getPaymasterData.
 *
 * Returns a real paymaster signature. The bundler first checks the
 * paymaster contract's shouldSponsor() policy via eth_call; if sponsorship
 * is rejected, this throws.
 *
 * IMPORTANT: call AFTER gas estimation, because the paymaster signs over
 * the gas fields. Changing gas after this call invalidates the signature.
 */
export async function getPaymasterData(
  bundlerUrl: string,
  entryPointAddress: Address,
  chainId: number,
  userOp: PackedUserOperation,
  context?: PaymasterContext,
): Promise<PaymasterSponsorship> {
  return paymasterCall(bundlerUrl, entryPointAddress, chainId, "pm_getPaymasterData", userOp, context);
}

/**
 * Pack an ERC-7677 sponsorship response into the on-chain paymasterAndData
 * layout expected by EntryPoint v0.7:
 *
 *   [paymaster:20][verifGasLimit:16][postOpGasLimit:16][paymasterData:rest]
 *
 * The paymaster's getHash function reads paymasterAndData[20:52] as the
 * packed (verifGasLimit || postOpGasLimit) uint128 pair — so the returned
 * layout must match exactly or the paymaster signature will not verify
 * on-chain (AA34 signature error).
 *
 * NOTE on the bundler's wire format: signet-min-bundler's FromRPC
 * concatenates the JSON `paymaster` + `paymasterData` fields directly
 * into paymasterAndData. It does NOT re-insert gas-limit bytes. So when
 * serializing for eth_sendUserOperation, the `paymasterData` on the wire
 * already includes the packed gas limits.
 */
export function applyPaymasterSponsorship(
  userOp: PackedUserOperation,
  s: PaymasterSponsorship
): PackedUserOperation {
  const verifGas = BigInt(s.paymasterVerificationGasLimit);
  const postOpGas = BigInt(s.paymasterPostOpGasLimit);
  const packedGas = (`0x${verifGas.toString(16).padStart(32, "0")}${postOpGas.toString(16).padStart(32, "0")}`) as Hex;
  return {
    ...userOp,
    paymasterAndData: concat([s.paymaster, packedGas, s.paymasterData]),
  };
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

async function paymasterCall(
  bundlerUrl: string,
  entryPointAddress: Address,
  chainId: number,
  method: "pm_getPaymasterStubData" | "pm_getPaymasterData",
  userOp: PackedUserOperation,
  context?: PaymasterContext,
): Promise<PaymasterSponsorship> {
  const json = await bundlerRpc(bundlerUrl, method, [
    serializeUserOp(userOp),
    entryPointAddress,
    `0x${chainId.toString(16)}`,
    context ?? {},
  ]);

  return {
    paymaster: json.result.paymaster as Address,
    paymasterData: json.result.paymasterData as Hex,
    paymasterVerificationGasLimit: json.result.paymasterVerificationGasLimit as Hex,
    paymasterPostOpGasLimit: json.result.paymasterPostOpGasLimit as Hex,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function bundlerRpc(bundlerUrl: string, method: string, params: any[]): Promise<any> {
  const res = await fetch(bundlerUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });

  const json = await res.json();
  if (json.error) {
    throw new Error(`${method} failed: ${json.error.message}`);
  }
  return json;
}

/**
 * Serialize a PackedUserOperation to the unpacked v0.7 RPC format
 * expected by signet-min-bundler.
 *
 * Paymaster handling: the bundler's FromRPC builds paymasterAndData by
 * concatenating `paymaster` + `paymasterData` with no re-insertion of gas
 * limits, so we send `paymasterData` as bytes 20..end of our stored
 * paymasterAndData (which already includes the packed gas limits written
 * by applyPaymasterSponsorship).
 */
function serializeUserOp(userOp: PackedUserOperation) {
  const gasLimitsHex = userOp.accountGasLimits.slice(2).padStart(64, "0");
  const verificationGasLimit = `0x${BigInt("0x" + gasLimitsHex.slice(0, 32)).toString(16)}`;
  const callGasLimit = `0x${BigInt("0x" + gasLimitsHex.slice(32, 64)).toString(16)}`;

  const gasFeesHex = (userOp.gasFees as string).slice(2).padStart(64, "0");
  const maxPriorityFeePerGas = `0x${BigInt("0x" + gasFeesHex.slice(0, 32)).toString(16)}`;
  const maxFeePerGas = `0x${BigInt("0x" + gasFeesHex.slice(32, 64)).toString(16)}`;

  const initCodeHex = userOp.initCode.slice(2);
  const factory = initCodeHex.length >= 40 ? `0x${initCodeHex.slice(0, 40)}` : "";
  const factoryData = initCodeHex.length > 40 ? `0x${initCodeHex.slice(40)}` : "";

  const pmHex = userOp.paymasterAndData.slice(2);
  const paymaster = pmHex.length >= 40 ? `0x${pmHex.slice(0, 40)}` : "";
  const paymasterData = pmHex.length > 40 ? `0x${pmHex.slice(40)}` : "";

  return {
    sender: userOp.sender,
    nonce: `0x${userOp.nonce.toString(16)}`,
    factory,
    factoryData,
    callData: userOp.callData,
    callGasLimit,
    verificationGasLimit,
    preVerificationGas: `0x${userOp.preVerificationGas.toString(16)}`,
    maxFeePerGas,
    maxPriorityFeePerGas,
    paymaster,
    paymasterData,
    signature: userOp.signature,
  };
}
