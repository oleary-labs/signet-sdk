/**
 * Transport-tier node failover.
 *
 * Nodes are symmetric: any one of them can serve any request, and for anything
 * decided by a pinned block read they all reach the same verdict. That makes
 * exactly one class of failure worth moving nodes for — the class that says
 * nothing about the request.
 *
 *   Transport tier — the node is unreachable or broken. `fetch` throws (DNS,
 *   connection refused, TLS, abort), or answers 5xx/429/408. Another node may
 *   well succeed, so advance.
 *
 *   Verdict tier — the node processed the request and decided. Every other
 *   node would decide the same way, so moving nodes turns one clear error into
 *   N identical ones and hides the cause. Fail immediately.
 *
 * The one timing failure that looks like it wants failover is not: authenticate
 * against node A, sign against node B before A's `msgAuth` broadcast reaches
 * it, and B answers 401. The fix is to retry *B* — the node that is catching up
 * — not to move to C. Encoding failover on 4xx would build exactly the wrong
 * loop, so this module does not offer it.
 *
 * Which 4xx are transient is a question about node semantics that nothing has
 * observed yet. Deliberately out of scope until a live node answers it.
 */

/**
 * A failure that carries no verdict — the node could not be reached, or failed
 * before deciding anything. The only error `withNodeFailover` advances on.
 */
export class NodeTransportError extends Error {
	readonly nodeUrl: string;
	readonly status?: number;

	constructor(nodeUrl: string, message: string, status?: number, cause?: unknown) {
		super(message, cause === undefined ? undefined : { cause });
		this.name = "NodeTransportError";
		this.nodeUrl = nodeUrl;
		this.status = status;
	}
}

/** One node's failure, kept so an exhausted fleet can report the whole picture. */
export interface NodeAttemptFailure {
	nodeUrl: string;
	message: string;
	status?: number;
}

/** Thrown when every node failed at the transport tier. */
export class AllNodesFailedError extends Error {
	readonly attempts: NodeAttemptFailure[];

	constructor(attempts: NodeAttemptFailure[]) {
		const detail = attempts.map((a) => `  ${a.nodeUrl}: ${a.message}`).join("\n");
		super(
			`all ${attempts.length} node${attempts.length === 1 ? "" : "s"} failed to respond:\n${detail}`,
		);
		this.name = "AllNodesFailedError";
		this.attempts = attempts;
	}
}

/**
 * HTTP statuses that mean "this node could not serve it", not "the answer is no".
 *
 * 5xx is the node or a proxy in front of it failing. 429 and 408 are load and
 * timeout — the same request may well succeed elsewhere. Everything else,
 * 4xx included, is a verdict.
 */
export function isTransportStatus(status: number): boolean {
	return status >= 500 || status === 429 || status === 408;
}

/**
 * Run `attempt` against each node in turn, advancing only on a transport-tier
 * failure. Any other error propagates from the first node that raises it.
 *
 * `attempt` signals the transport tier by throwing `NodeTransportError`;
 * `postJson` does that for you.
 *
 * @throws AllNodesFailedError if every node failed at the transport tier.
 * @throws whatever `attempt` throws, unchanged, for a verdict.
 */
export async function withNodeFailover<T>(
	nodeUrls: readonly string[],
	attempt: (nodeUrl: string) => Promise<T>,
): Promise<T> {
	if (nodeUrls.length === 0) {
		throw new Error("withNodeFailover needs at least one node url");
	}

	const failures: NodeAttemptFailure[] = [];
	for (const nodeUrl of nodeUrls) {
		try {
			return await attempt(nodeUrl);
		} catch (err) {
			if (!(err instanceof NodeTransportError)) throw err;
			failures.push({ nodeUrl, message: err.message, status: err.status });
		}
	}
	throw new AllNodesFailedError(failures);
}

/**
 * POST JSON to one node, raising `NodeTransportError` for transport-tier
 * failures and returning the `Response` untouched for everything else — so the
 * caller keeps its own reading of a verdict.
 *
 * When `proxyEndpoint` is set the request goes there instead, with the node in
 * `x-node-url` and the route in `x-node-path`.
 */
export async function postJson(
	nodeUrl: string,
	path: string,
	body: unknown,
	proxyEndpoint?: string,
): Promise<Response> {
	const headers: Record<string, string> = { "Content-Type": "application/json" };
	let url = `${nodeUrl}${path}`;
	if (proxyEndpoint) {
		url = proxyEndpoint;
		headers["x-node-url"] = nodeUrl;
		headers["x-node-path"] = path;
	}

	let res: Response;
	try {
		res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
	} catch (err) {
		throw new NodeTransportError(
			nodeUrl,
			`unreachable: ${err instanceof Error ? err.message : String(err)}`,
			undefined,
			err,
		);
	}

	if (isTransportStatus(res.status)) {
		throw new NodeTransportError(nodeUrl, `${res.status} ${await res.text()}`.trim(), res.status);
	}
	return res;
}
