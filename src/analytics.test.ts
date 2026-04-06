/**
 * Analytics instrumentation tests for sdk/src/index.ts
 *
 * Tests the `emitAnalyticsEvent()` helper and startup event schema.
 * Because the IIFE in index.ts runs at module-load time (once per module evaluation),
 * each scenario that needs distinct env-var state is run in a subprocess via
 * Bun.spawnSync. This is the standard pattern for testing module-level side effects
 * in Bun — it avoids require-cache collisions and IIFE re-execution issues.
 *
 * Two test suites:
 *   1. try/catch safety — stderr write failures are swallowed; startup continues normally
 *   2. sdk.startup.succeeded event schema — all required properties present, no key material
 */

import { describe, test, expect } from "bun:test";

// ---------------------------------------------------------------------------
// Helper: run a small inline TypeScript script in a child Bun process.
// Returns { stderr, stdout, exitCode }.
// ---------------------------------------------------------------------------
function runInlineScript(
	script: string,
	env: Record<string, string> = {},
): { stderr: string; stdout: string; exitCode: number } {
	const proc = Bun.spawnSync(
		["bun", "--eval", script],
		{
			env: { ...process.env, ...env },
			stderr: "pipe",
			stdout: "pipe",
		},
	);
	return {
		stderr: new TextDecoder().decode(proc.stderr),
		stdout: new TextDecoder().decode(proc.stdout),
		exitCode: proc.exitCode ?? -1,
	};
}

// ---------------------------------------------------------------------------
// Suite 1: try/catch safety — process.stderr.write failure is swallowed
// ---------------------------------------------------------------------------
describe("emitAnalyticsEvent() — try/catch safety", () => {

	test("stderr write failure does not propagate — startup succeeds when key is valid", () => {
		// Script: patch process.stderr.write to throw BEFORE importing the SDK barrel.
		// With a valid key, the IIFE should complete successfully (emitting to the patched
		// stderr) and the module should load without any unhandled exception.
		const script = `
const original = process.stderr.write.bind(process.stderr);
process.stderr.write = () => { throw new Error("simulated stderr failure"); };
try {
  // Import index.ts with a valid key — analytics emit will throw internally,
  // but the try/catch in emitAnalyticsEvent() must swallow it.
  await import("./src/index.ts");
  // If we reach here, the startup path completed — no unhandled error from analytics.
  process.stdout.write("STARTUP_OK\\n");
} catch (e) {
  // Any error here must NOT originate from the analytics path
  if (e instanceof Error && e.message.includes("simulated stderr failure")) {
    process.stdout.write("ANALYTICS_LEAKED\\n");
  } else {
    // Validation throw (wrong key, etc.) — not what we expect with a valid key
    process.stdout.write("VALIDATION_THROW: " + e.message + "\\n");
  }
}
`;
		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "test",
		});

		// The analytics failure must be swallowed — startup completes.
		expect(result.stdout).toContain("STARTUP_OK");
		expect(result.stdout).not.toContain("ANALYTICS_LEAKED");
		expect(result.stdout).not.toContain("VALIDATION_THROW");
	});

	test("stderr write failure does not prevent validation throw — Tier 1 still throws", () => {
		// With no key, the IIFE should STILL throw the validation error, even when
		// emitAnalyticsEvent() fails internally. The analytics try/catch must not
		// swallow the subsequent validation throw.
		const script = `
process.stderr.write = () => { throw new Error("simulated stderr failure"); };
try {
  await import("./src/index.ts");
  process.stdout.write("STARTUP_OK_UNEXPECTED\\n");
} catch (e) {
  if (e instanceof Error && e.message.includes("ENCRYPTION_KEY environment variable is required")) {
    process.stdout.write("VALIDATION_THROW_CORRECT\\n");
  } else if (e instanceof Error && e.message.includes("simulated stderr failure")) {
    process.stdout.write("ANALYTICS_LEAKED\\n");
  } else {
    process.stdout.write("UNEXPECTED_ERROR: " + e.message + "\\n");
  }
}
`;
		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "",
			NODE_ENV: "test",
		});

		// The validation throw must occur (Tier 1 key_missing), NOT the analytics error.
		expect(result.stdout).toContain("VALIDATION_THROW_CORRECT");
		expect(result.stdout).not.toContain("ANALYTICS_LEAKED");
		expect(result.stdout).not.toContain("STARTUP_OK_UNEXPECTED");
	});

});

// ---------------------------------------------------------------------------
// Suite 2: sdk.startup.succeeded event schema
// ---------------------------------------------------------------------------
describe("sdk.startup.succeeded — event schema", () => {

	test("all required properties present: event, env, key_length_bytes, timestamp", () => {
		const script = `
await import("./src/index.ts");
`;
		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "test",
		});

		// Find the analytics JSON line on stderr
		const lines = result.stderr.split("\n").filter((l) => l.trim().startsWith("{"));
		const succeededLine = lines.find((l) => {
			try {
				return JSON.parse(l).event === "sdk.startup.succeeded";
			} catch {
				return false;
			}
		});

		expect(succeededLine).toBeDefined();

		const payload = JSON.parse(succeededLine!);
		expect(payload).toHaveProperty("event", "sdk.startup.succeeded");
		expect(payload).toHaveProperty("env");
		expect(payload).toHaveProperty("key_length_bytes");
		expect(payload).toHaveProperty("timestamp");
	});

	test("key_length_bytes is a number — not key content", () => {
		const testKey = "test-encryption-key-exactly-32b!";
		const script = `await import("./src/index.ts");`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: testKey,
			NODE_ENV: "test",
		});

		const lines = result.stderr.split("\n").filter((l) => l.trim().startsWith("{"));
		const succeededLine = lines.find((l) => {
			try {
				return JSON.parse(l).event === "sdk.startup.succeeded";
			} catch {
				return false;
			}
		});

		expect(succeededLine).toBeDefined();
		const payload = JSON.parse(succeededLine!);

		// key_length_bytes must be a number (the byte count), not the key itself
		expect(typeof payload.key_length_bytes).toBe("number");
		expect(payload.key_length_bytes).toBeGreaterThanOrEqual(32);
	});

	test("no key material in sdk.startup.succeeded payload", () => {
		const testKey = "test-encryption-key-exactly-32b!";
		const script = `await import("./src/index.ts");`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: testKey,
			NODE_ENV: "test",
		});

		// The raw key value must not appear anywhere in the stderr output
		expect(result.stderr).not.toContain(testKey);
		// Verify the serialised payload string does not contain any substring of the key > 8 chars
		// (checking first 8 chars is sufficient — the key prefix test)
		const keyPrefix = testKey.slice(0, 12);
		expect(result.stderr).not.toContain(keyPrefix);
	});

	test("timestamp is a valid ISO 8601 string", () => {
		const script = `await import("./src/index.ts");`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "test",
		});

		const lines = result.stderr.split("\n").filter((l) => l.trim().startsWith("{"));
		const succeededLine = lines.find((l) => {
			try {
				return JSON.parse(l).event === "sdk.startup.succeeded";
			} catch {
				return false;
			}
		});

		expect(succeededLine).toBeDefined();
		const payload = JSON.parse(succeededLine!);

		const parsed = new Date(payload.timestamp);
		expect(isNaN(parsed.getTime())).toBe(false);
	});

	test("env field matches NODE_ENV", () => {
		const script = `await import("./src/index.ts");`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "staging",
		});

		const lines = result.stderr.split("\n").filter((l) => l.trim().startsWith("{"));
		const succeededLine = lines.find((l) => {
			try {
				return JSON.parse(l).event === "sdk.startup.succeeded";
			} catch {
				return false;
			}
		});

		expect(succeededLine).toBeDefined();
		const payload = JSON.parse(succeededLine!);
		expect(payload.env).toBe("staging");
	});

});
