/**
 * x402 payment protocol client.
 *
 * Handles the HTTP 402 payment flow:
 * 1. Parse `payment-required` header from 402 response
 * 2. Build EIP-3009 TransferWithAuthorization typed data
 * 3. Construct PaymentPayload with signature
 * 4. Encode for `Payment-Signature` header
 */

// ---------------------------------------------------------------------------
// Types (matching x402 protocol spec)
// ---------------------------------------------------------------------------

export interface PaymentRequirements {
  scheme: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: Record<string, unknown>;
}

export interface PaymentRequired {
  x402Version: number;
  error?: string;
  resource: {
    url: string;
    description?: string;
    mimeType?: string;
  };
  accepts: PaymentRequirements[];
  extensions?: Record<string, unknown>;
}

export interface PaymentPayload {
  x402Version: number;
  resource?: { url: string };
  accepted: PaymentRequirements;
  payload: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Parse 402 response
// ---------------------------------------------------------------------------

/**
 * Parse the `payment-required` header from a 402 response.
 */
export function parsePaymentRequired(headerValue: string): PaymentRequired {
  const json = atob(headerValue);
  return JSON.parse(json);
}

/**
 * Find an EVM payment option (Base USDC by default).
 */
export function findEvmPaymentOption(
  required: PaymentRequired,
  preferredNetwork = "eip155:8453",
): PaymentRequirements | null {
  return required.accepts.find(
    (a) => a.scheme === "exact" && a.network === preferredNetwork,
  ) ?? null;
}

// ---------------------------------------------------------------------------
// Build EIP-3009 TransferWithAuthorization
// ---------------------------------------------------------------------------

/**
 * Build EIP-712 typed data for TransferWithAuthorization (EIP-3009).
 *
 * @param from - The sender's Ethereum address (sub-key's address)
 * @param payTo - Recipient address (from payment requirements)
 * @param amount - Amount in smallest unit (e.g. "10000" for $0.01 USDC)
 * @param asset - Token contract address
 * @param chainId - Chain ID (e.g. 8453 for Base)
 * @param tokenName - Token EIP-712 domain name (e.g. "USD Coin")
 * @param tokenVersion - Token EIP-712 domain version (e.g. "2")
 * @param validAfter - Unix timestamp (default: now - 60s)
 * @param validBefore - Unix timestamp (default: now + 300s)
 */
export function buildTransferAuthorization(
  from: string,
  payTo: string,
  amount: string,
  asset: string,
  chainId: number,
  tokenName: string,
  tokenVersion: string,
  validAfter?: number,
  validBefore?: number,
) {
  const now = Math.floor(Date.now() / 1000);
  const nonce = "0x" + Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map((b) => b.toString(16).padStart(2, "0")).join("");

  return {
    domain: {
      name: tokenName,
      version: tokenVersion,
      chainId,
      verifyingContract: asset,
    },
    types: {
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
    },
    primaryType: "TransferWithAuthorization" as const,
    message: {
      from,
      to: payTo,
      value: amount,
      validAfter: String(validAfter ?? now - 60),
      validBefore: String(validBefore ?? now + 300),
      nonce,
    },
  };
}

// ---------------------------------------------------------------------------
// Build x402 PaymentPayload
// ---------------------------------------------------------------------------

/**
 * Build the x402 PaymentPayload from a signed TransferWithAuthorization.
 *
 * @param accepted - The payment option we're fulfilling
 * @param authorization - The TransferWithAuthorization message fields
 * @param signature - The ECDSA signature (0x-prefixed, 65 bytes)
 * @param resourceUrl - The URL of the resource being paid for
 */
export function buildPaymentPayload(
  accepted: PaymentRequirements,
  authorization: {
    from: string;
    to: string;
    value: string;
    validAfter: string;
    validBefore: string;
    nonce: string;
  },
  signature: string,
  resourceUrl?: string,
): string {
  const payload: PaymentPayload = {
    x402Version: 2,
    resource: resourceUrl ? { url: resourceUrl } : undefined,
    accepted,
    payload: {
      signature,
      authorization: {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value,
        validAfter: authorization.validAfter,
        validBefore: authorization.validBefore,
        nonce: authorization.nonce,
      },
    },
  };

  // Base64-encode the payload for the Payment-Signature header
  return btoa(JSON.stringify(payload));
}

// ---------------------------------------------------------------------------
// Full x402 fetch wrapper
// ---------------------------------------------------------------------------

export interface X402FetchOptions {
  /** The sub-key's Ethereum address (from) */
  signerAddress: string;
  /** Preferred network (default: "eip155:8453" for Base) */
  preferredNetwork?: string;
  /** Called to sign the EIP-712 typed data. Returns the ECDSA signature. */
  signTypedData: (typedData: ReturnType<typeof buildTransferAuthorization>) => Promise<string>;
}

/**
 * Make an HTTP request with automatic x402 payment handling.
 *
 * If the server returns 402, automatically builds a payment authorization,
 * signs it, and retries the request with the Payment-Signature header.
 *
 * @returns The successful response (after payment if needed)
 */
export async function x402Fetch(
  url: string,
  init: RequestInit,
  options: X402FetchOptions,
): Promise<{ response: Response; paid: boolean; paymentDetails?: { amount: string; network: string; asset: string } }> {
  // First attempt
  const res = await fetch(url, init);

  if (res.status !== 402) {
    return { response: res, paid: false };
  }

  // Parse 402 payment requirements
  const paymentHeader = res.headers.get("payment-required");
  if (!paymentHeader) {
    throw new Error("402 response missing payment-required header");
  }

  const required = parsePaymentRequired(paymentHeader);
  const accepted = findEvmPaymentOption(required, options.preferredNetwork);
  if (!accepted) {
    throw new Error(`No compatible EVM payment option found (preferred: ${options.preferredNetwork ?? "eip155:8453"})`);
  }

  // Extract chain ID from network string (e.g. "eip155:8453" → 8453)
  const chainId = parseInt(accepted.network.split(":")[1]);
  const tokenName = (accepted.extra?.name as string) ?? "USD Coin";
  const tokenVersion = (accepted.extra?.version as string) ?? "2";

  // Build TransferWithAuthorization
  const typedData = buildTransferAuthorization(
    options.signerAddress,
    accepted.payTo,
    accepted.amount,
    accepted.asset,
    chainId,
    tokenName,
    tokenVersion,
  );

  // Sign via Signet
  const signature = await options.signTypedData(typedData);

  // Build payment payload
  const paymentSignature = buildPaymentPayload(
    accepted,
    typedData.message,
    signature,
    required.resource.url,
  );

  // Retry with payment
  const paidRes = await fetch(url, {
    ...init,
    headers: {
      ...Object.fromEntries(new Headers(init.headers).entries()),
      "Payment-Signature": paymentSignature,
    },
  });

  return {
    response: paidRes,
    paid: true,
    paymentDetails: {
      amount: accepted.amount,
      network: accepted.network,
      asset: accepted.asset,
    },
  };
}
