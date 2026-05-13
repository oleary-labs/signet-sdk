/**
 * Google OAuth PKCE flow.
 *
 * Framework-agnostic — uses browser APIs only (sessionStorage, crypto, location).
 * The token exchange itself is delegated to a caller-provided endpoint
 * so the client_secret stays server-side.
 */

import type { IdTokenClaims } from "./types";

function base64urlEncode(buf: ArrayBuffer | Uint8Array): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function generateVerifier(): string {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return base64urlEncode(buf);
}

async function generateChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(digest);
}

export interface OAuthConfig {
  clientId: string;
  callbackPath?: string; // defaults to "/auth/callback"
}

/**
 * Kick off the Google OAuth PKCE flow.
 * Stores PKCE state in sessionStorage and redirects to Google.
 */
export async function startGoogleOAuth(
  config: OAuthConfig,
  returnTo?: string
): Promise<void> {
  if (!config.clientId) {
    throw new Error("Google Client ID not configured");
  }

  const verifier = generateVerifier();
  const challenge = await generateChallenge(verifier);
  const state = base64urlEncode(
    crypto.getRandomValues(new Uint8Array(16))
  );

  sessionStorage.setItem("signet_oauth_verifier", verifier);
  sessionStorage.setItem("signet_oauth_state", state);
  sessionStorage.setItem(
    "signet_oauth_return_to",
    returnTo ?? window.location.pathname
  );

  const callbackPath = config.callbackPath ?? "/auth/callback";
  const redirectUri = `${window.location.origin}${callbackPath}`;

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid profile email",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  });

  window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

/**
 * Handle the OAuth callback: validate state, exchange code for tokens.
 *
 * @param tokenEndpoint — URL of the server-side token exchange endpoint
 * @returns The raw JWT id_token string, or throws on error.
 */
export async function handleOAuthCallback(
  tokenEndpoint: string
): Promise<string> {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");
  const error = params.get("error");

  if (error) {
    throw new Error(
      `Google OAuth error: ${error} — ${params.get("error_description") ?? ""}`
    );
  }

  if (!code) {
    throw new Error("No authorization code received");
  }

  const savedState = sessionStorage.getItem("signet_oauth_state");
  if (state !== savedState) {
    throw new Error("State mismatch — possible CSRF attack");
  }

  const verifier = sessionStorage.getItem("signet_oauth_verifier");
  const callbackUri = window.location.origin + window.location.pathname;

  // Clean up PKCE state
  sessionStorage.removeItem("signet_oauth_state");
  sessionStorage.removeItem("signet_oauth_verifier");

  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code,
      code_verifier: verifier,
      redirect_uri: callbackUri,
    }),
  });

  const data = await res.json();

  if (data.error) {
    throw new Error(
      `Token exchange failed: ${data.error} — ${data.error_description ?? ""}`
    );
  }

  return data.id_token;
}

/**
 * Decode a JWT payload without verification.
 * Signature verification happens via ZK proof.
 */
export function decodeIdToken(jwt: string): IdTokenClaims {
  const payload = jwt.split(".")[1];
  const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
  const claims = JSON.parse(decoded);
  // Preserve original aud/azp presence for ZK proof public input matching.
  // If the JWT doesn't have aud or azp, keep them empty so the prover
  // and verifier agree on the same (empty) public inputs.
  if (claims.aud === undefined) claims.aud = "";
  if (claims.azp === undefined) claims.azp = "";
  if (claims.email === undefined) claims.email = "";
  return claims;
}

/**
 * Get the return-to path stored before the OAuth redirect.
 */
export function getOAuthReturnTo(): string {
  const returnTo = sessionStorage.getItem("signet_oauth_return_to") ?? "/";
  sessionStorage.removeItem("signet_oauth_return_to");
  return returnTo;
}
