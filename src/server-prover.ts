/**
 * Server-side ZK proof generation via the bundler's /v1/prove endpoint.
 *
 * Delegates JWT proof generation to the bundler instead of running
 * noir + bb.js client-side via WASM. Faster (~2-3s vs 2-7s) and
 * avoids shipping heavy WASM binaries to the browser.
 *
 * The returned proof + claims + modulus are everything needed to
 * call authenticateWithBootstrap.
 */

export interface ServerProofResult {
  proof: Uint8Array;
  sub: string;
  iss: string;
  exp: number;
  aud: string;
  azp: string;
  jwksModulus: Uint8Array;
  sessionPub: string;
}

/**
 * Generate a ZK proof of a JWT via the bundler's server-side prover.
 *
 * @param bundlerProxyUrl - URL of the bundler proxy (e.g. "/api/bundler")
 * @param jwt - Raw JWT from OAuth provider
 * @param sessionPubHex - 33-byte compressed secp256k1 public key, hex-encoded
 */
export async function generateServerProof(
  bundlerProxyUrl: string,
  jwt: string,
  sessionPubHex: string,
): Promise<ServerProofResult> {
  const res = await fetch(bundlerProxyUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-bundler-path": "/v1/prove",
    },
    body: JSON.stringify({ jwt, session_pub: sessionPubHex }),
  });

  const result = await res.json();

  if (!res.ok) {
    const msg = result.error ?? JSON.stringify(result);
    throw new Error(`Server proof generation failed: ${res.status} — ${msg}`);
  }
  if (result.error) {
    const msg = typeof result.error === "string" ? result.error : JSON.stringify(result.error);
    throw new Error(`Server proof generation failed: ${msg}`);
  }

  return {
    proof: hexToBytes(result.proof),
    sub: result.sub,
    iss: result.iss,
    exp: result.exp,
    aud: result.aud,
    azp: result.azp,
    jwksModulus: hexToBytes(result.jwks_modulus),
    sessionPub: result.session_pub,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(
    (clean.match(/.{2}/g) ?? []).map((b) => parseInt(b, 16))
  );
}
