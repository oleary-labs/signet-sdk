# Better Auth Integration with Signet

## Overview

Better Auth is a self-hosted TypeScript auth framework that replaces Clerk/Auth0/NextAuth.
It issues its own RS256 JWTs, giving full control over token format, signing, and expiry.
The Signet ZK proof circuit works with any RSA-signed JWT — no circuit changes needed.

## Why Better Auth

- **Self-hosted** — no external auth service dependency
- **RS256 JWTs** — compatible with Signet's ZK proof circuit out of the box
- **JWKS endpoint** — serves public keys at `/api/auth/jwks` for node verification
- **Identity linking** — same email from Google/Apple/GitHub = same user ID = same keys
- **No short-lived tokens** — you control expiry (Clerk forces 60s session tokens)
- **Plugin-based** — passkeys, MCP auth, API keys, organizations, etc.

## Setup

### Install

```bash
bun add better-auth better-sqlite3
```

### Server config (`src/lib/auth.ts`)

```typescript
import { betterAuth } from "better-auth";
import { jwt } from "better-auth/plugins";
import Database from "better-sqlite3";

export const auth = betterAuth({
  database: new Database("./auth.db"),
  plugins: [
    jwt({
      jwks: {
        keyPairConfig: {
          alg: "RS256",         // Required for ZK proof compatibility
          modulusLength: 2048,
        },
      },
    }),
  ],
  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    },
  },
});
```

For production, swap SQLite for Postgres:
```typescript
database: { url: process.env.DATABASE_URL },
```

### API route (`src/app/api/auth/[...all]/route.ts`)

```typescript
import { auth } from "@/lib/auth";
import { toNextJsHandler } from "better-auth/next-js";

export const { GET, POST } = toNextJsHandler(auth.handler);
```

### Client (`src/lib/auth-client.ts`)

```typescript
import { createAuthClient } from "better-auth/react";
import { jwtClient } from "better-auth/client/plugins";

export const authClient = createAuthClient({
  plugins: [jwtClient()],
});
```

### OIDC Discovery (`src/app/.well-known/openid-configuration/route.ts`)

Better Auth doesn't serve a standard OIDC discovery document. Signet's server
prover needs one to find the JWKS URI. Add this route:

```typescript
import { NextRequest } from "next/server";

export function GET(request: NextRequest) {
  const origin = request.nextUrl.origin;
  return Response.json({
    issuer: origin,
    jwks_uri: `${origin}/api/auth/jwks`,
    id_token_signing_alg_values_supported: ["RS256"],
  });
}
```

### Database migration

```bash
bunx @better-auth/cli migrate --config src/lib/auth.ts -y
```

Or Better Auth auto-creates tables on first use with SQLite.

## Signet Integration Flow

```
1. User clicks "Sign In with Google"
   → authClient.signIn.social({ provider: "google", callbackURL: "/demo" })

2. Better Auth handles OAuth, creates user, issues session

3. Get JWT for Signet
   → const { data } = await authClient.token()
   → data.token is an RS256 JWT

4. JWT claims:
   {
     "iss": "https://your-app.com",     ← your domain, not Google's
     "sub": "user_abc123",               ← Better Auth user ID
     "aud": "https://your-app.com",
     "exp": ...,
     "iat": ...
   }

5. Generate ZK proof of the JWT (server-side or client-side)
   → const result = await generateServerProof("/api/bundler", jwt, sessionPubHex)

6. Authenticate with Signet nodes
   → await authenticateWithBootstrap(config, proof, sessionPubHex, claims, modulus)

7. Use session for keygen, signing, delegation, etc.
```

## Registering the issuer on-chain

The Signet group needs your Better Auth instance registered as a trusted issuer:

```bash
# On the group contract, add the issuer with the app's origin as the client ID
cast send <GROUP_ADDRESS> "addIssuer(string,string[])" \
  "https://your-app.com" '["https://your-app.com"]' \
  --rpc-url <RPC_URL> --private-key <KEY>
```

The nodes will then accept ZK proofs of JWTs from your Better Auth instance.

## Key differences from Clerk

| | Clerk | Better Auth |
|---|---|---|
| Hosting | SaaS | Self-hosted |
| JWT issuer | Clerk's domain | Your domain |
| Token expiry | 60s (fixed) | Configurable |
| JWKS | Clerk's endpoint | `/api/auth/jwks` |
| OIDC discovery | Built-in | Need custom route |
| Identity linking | Automatic | Automatic |
| `aud` claim | Missing (use `azp`) | Present |
| Price | Free tier + paid | Free (open source) |
| Setup | Dashboard config | Code config |

## Key differences from Google OAuth (vanilla)

| | Google OAuth | Better Auth |
|---|---|---|
| JWT issuer | `https://accounts.google.com` | Your domain |
| User ID (`sub`) | Google's numeric ID | Better Auth user ID |
| Identity linking | None (Google-only) | Google + Apple + GitHub = same user |
| Token format | Google's fixed format | You control claims |
| JWKS | Google's servers | Your server |

## Gotchas

1. **`BETTER_AUTH_SECRET`** must be at least 32 chars random. Use `openssl rand -base64 32`.

2. **`aud` claim** — Better Auth includes `aud` in JWTs. The ZK circuit (v0.3.0+) treats
   `aud` as optional. If `aud` is present, both prover and verifier must agree on the value.
   `decodeIdToken()` in the SDK handles this — empty `aud` stays empty, present `aud` is kept.

3. **OIDC discovery** — the server prover fetches `{iss}/.well-known/openid-configuration`
   to find the JWKS URI. Better Auth doesn't serve this by default — add the custom route above.

4. **`better-sqlite3`** is a native module. Add to `serverExternalPackages` in `next.config.ts`:
   ```typescript
   serverExternalPackages: ["better-sqlite3"],
   ```

5. **Existing `/api/auth/token` route** — Better Auth's catch-all `[...all]` route conflicts
   with any existing `/api/auth/*` routes. Rename them (e.g. `/api/auth/oauth-token`).
