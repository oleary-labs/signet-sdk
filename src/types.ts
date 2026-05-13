/**
 * Shared types for the Signet SDK.
 */

/** Decoded Google ID token claims. */
export interface IdTokenClaims {
  iss: string; // "https://accounts.google.com"
  sub: string; // stable numeric user ID
  email: string;
  name?: string;
  picture?: string;
  azp: string; // OAuth client ID
  aud: string;
  exp: number; // unix timestamp
  iat: number;
}

/** RSA public key from JWKS. */
export interface JWKSKey {
  kid: string;
  kty: string;
  alg: string;
  n: string; // base64url-encoded modulus
  e: string; // base64url-encoded exponent
}

/** Session keypair (secp256k1). */
export interface SessionKeypair {
  privateKey: Uint8Array;
  publicKeyHex: string; // 33-byte compressed, hex-encoded
}

/** Witness inputs for the jwt_auth noir circuit. */
export interface CircuitWitness {
  // Private witness
  data: number[]; // JWT signed data bytes, padded to 1024
  dataLen: number; // actual length of signed data
  base64DecodeOffset: number; // header length + 1
  redcParamsLimbs: string[]; // 18 limbs, decimal strings
  signatureLimbs: string[]; // 18 limbs, decimal strings

  // Public inputs
  pubkeyModulusLimbs: string[]; // 18 limbs, decimal strings
  iss: string;
  sub: string;
  exp: number;
  aud: string;
  azp: string;
  sessionPub: number[]; // 33 bytes
}

/** Auth request body for bootstrap node /v1/auth (OAuth/ZK path). */
export interface NodeAuthRequest {
  group_id: string;
  session_pub: string; // hex
  proof: string; // hex
  sub: string;
  iss: string;
  exp: number;
  aud: string;
  azp: string;
  jwks_modulus: string; // hex
}
