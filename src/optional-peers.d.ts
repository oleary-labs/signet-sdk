/**
 * Fallback ambient declarations for the optional zero-knowledge proving peers.
 *
 * `src/proof.ts` is the browser ZK path and is deliberately not imported by
 * anything else in the package (`index.ts` documents it as direct-import only).
 * Its three peers are heavy and optional, so a plain `bun install` does not
 * provide them — which made `bun run build` fail on a clean checkout, and with
 * it `prepublishOnly`.
 *
 * These declarations let the package compile and publish without them. They are
 * a build fallback, not a type contract: consumers that actually use `./proof`
 * install the real packages and get the real types at their call sites.
 *
 * DELETE THIS FILE if the ZK peers are ever moved to dependencies or
 * optionalDependencies such that they are present at build time.
 */

declare module "@noir-lang/noir_js" {
	export class Noir {
		constructor(circuit: unknown);
		execute(inputs: unknown): Promise<{ witness: Uint8Array }>;
	}
}

declare module "@aztec/bb.js" {
	export class UltraHonkBackend {
		constructor(bytecode: unknown, options?: unknown);
		generateProof(witness: Uint8Array, options?: unknown): Promise<{
			proof: Uint8Array;
			publicInputs: string[];
		}>;
		destroy(): Promise<void>;
	}
}

declare module "@oleary-labs/signet-circuits" {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	export const jwt: any;
	export function assertBbJsVersion(version?: string): void;
}
