/**
 * ZK proof witness construction for the jwt_auth noir circuit.
 *
 * Uses generateInputs from noir-jwt for the core RSA/JWT witness,
 * then adds the claim assertions and session_pub binding that our
 * circuit requires.
 */

import { generateInputs } from "./generate-inputs";
import type { IdTokenClaims } from "./types";

/** Full witness for the jwt_auth circuit (Prover.toml format). */
export interface FullCircuitWitness {
  // From generateInputs (RSA + JWT data)
  data: { storage: number[]; len: number };
  base64_decode_offset: number;
  pubkey_modulus_limbs: string[];
  redc_params_limbs: string[];
  signature_limbs: string[];

  // Claim assertions (public inputs)
  expected_iss: { storage: number[]; len: number };
  expected_sub: { storage: number[]; len: number };
  expected_exp: number;
  expected_aud: { storage: number[]; len: number };
  expected_azp: { storage: number[]; len: number };

  // Session binding (public input)
  _session_pub: number[];
}

/**
 * Build full circuit witness from a JWT, JWKS key, and session public key.
 *
 * @param jwt — raw JWT string
 * @param jwksKey — the RSA public key from Google JWKS (as JsonWebKey)
 * @param claims — decoded JWT claims
 * @param sessionPubBytes — 33-byte compressed secp256k1 session public key
 */
export async function buildFullWitness(
  jwt: string,
  jwksKey: JsonWebKey,
  claims: IdTokenClaims,
  sessionPubBytes: number[]
): Promise<FullCircuitWitness> {
  // Generate core JWT/RSA inputs using noir-jwt library
  const inputs = await generateInputs({
    jwt,
    pubkey: jwksKey,
    maxSignedDataLength: 1024,
  });

  if (!inputs.data) {
    throw new Error("Expected full data mode (no partial SHA)");
  }

  return {
    // Core JWT/RSA witness
    data: inputs.data,
    base64_decode_offset: inputs.base64_decode_offset,
    pubkey_modulus_limbs: inputs.pubkey_modulus_limbs,
    redc_params_limbs: inputs.redc_params_limbs,
    signature_limbs: inputs.signature_limbs,

    // Claim assertions
    expected_iss: toBoundedVec(claims.iss, 128),
    expected_sub: toBoundedVec(claims.sub, 128),
    expected_exp: claims.exp,
    expected_aud: toBoundedVec(claims.aud, 128),
    expected_azp: toBoundedVec(claims.azp, 128),

    // Session binding
    _session_pub: sessionPubBytes,
  };
}

/**
 * Serialize a FullCircuitWitness to Prover.toml format for nargo.
 */
export function witnessToProverToml(w: FullCircuitWitness): string {
  const lines: string[] = [];

  // Bare keys must come before [table] sections in TOML
  lines.push(`base64_decode_offset = ${w.base64_decode_offset}`);
  lines.push(`expected_exp = ${w.expected_exp}`);
  lines.push(
    `redc_params_limbs = [${w.redc_params_limbs.map((l) => `"${l}"`).join(", ")}]`
  );
  lines.push(
    `signature_limbs = [${w.signature_limbs.map((l) => `"${l}"`).join(", ")}]`
  );
  lines.push(
    `pubkey_modulus_limbs = [${w.pubkey_modulus_limbs.map((l) => `"${l}"`).join(", ")}]`
  );
  lines.push(`_session_pub = [${w._session_pub.join(", ")}]`);
  lines.push("");

  // BoundedVec tables
  lines.push("[data]");
  lines.push(`storage = [${w.data.storage.join(", ")}]`);
  lines.push(`len = ${w.data.len}`);
  lines.push("");

  writeBoundedVecToml(lines, "expected_iss", w.expected_iss);
  writeBoundedVecToml(lines, "expected_sub", w.expected_sub);
  writeBoundedVecToml(lines, "expected_aud", w.expected_aud);
  writeBoundedVecToml(lines, "expected_azp", w.expected_azp);

  return lines.join("\n");
}

function toBoundedVec(
  value: string,
  maxLen: number
): { storage: number[]; len: number } {
  const storage = new Array(maxLen).fill(0);
  for (let i = 0; i < value.length; i++) {
    storage[i] = value.charCodeAt(i);
  }
  return { storage, len: value.length };
}

function writeBoundedVecToml(
  lines: string[],
  name: string,
  vec: { storage: number[]; len: number }
): void {
  lines.push(`[${name}]`);
  lines.push(`storage = [${vec.storage.join(", ")}]`);
  lines.push(`len = ${vec.len}`);
  lines.push("");
}
