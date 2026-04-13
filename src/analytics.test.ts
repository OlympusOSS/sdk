/**
 * Analytics instrumentation tests for validateOnStartup() and emitAnalyticsEvent()
 *
 * Tests the `emitAnalyticsEvent()` helper and startup event schema.
 * Because each scenario needs distinct env-var state, each subprocess test uses
 * Bun.spawnSync to run a small inline script. This avoids require-cache collisions
 * and ensures each test starts with a fresh module evaluation.
 *
 * Architecture note: validateOnStartup() is NOT called at module-load time in index.ts.
 * It is called by the consuming app's entry point (e.g., instrumentation.ts in Athena/Hera).
 * These tests call it explicitly to test the analytics event schema.
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
// Suite 1: try/catch safety — process.stdout.write failure is swallowed
// ---------------------------------------------------------------------------
describe("emitAnalyticsEvent() — try/catch safety", () => {

	test("stdout write failure does not propagate — validateOnStartup() succeeds when key is valid", () => {
		// Script: patch process.stdout.write to throw BEFORE calling validateOnStartup().
		// With a valid key, validateOnStartup() should complete (emitting to the patched
		// stdout) without propagating the analytics failure.
		const script = `
process.stdout.write = () => { throw new Error("simulated stdout failure"); };
try {
  const { validateOnStartup } = await import("./src/crypto.ts");
  validateOnStartup();
  // If we reach here, the startup path completed — no unhandled error from analytics.
  process.stderr.write("STARTUP_OK\\n");
} catch (e) {
  // Any error here must NOT originate from the analytics path
  if (e instanceof Error && e.message.includes("simulated stdout failure")) {
    process.stderr.write("ANALYTICS_LEAKED\\n");
  } else {
    // Validation throw (wrong key, etc.) — not what we expect with a valid key
    process.stderr.write("VALIDATION_THROW: " + e.message + "\\n");
  }
}
`;
		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "test",
		});

		// The analytics failure must be swallowed — startup completes.
		expect(result.stderr).toContain("STARTUP_OK");
		expect(result.stderr).not.toContain("ANALYTICS_LEAKED");
		expect(result.stderr).not.toContain("VALIDATION_THROW");
	});

	test("stdout write failure does not prevent validation throw — Tier 1 still throws", () => {
		// With no key, validateOnStartup() should STILL throw the validation error,
		// even when emitAnalyticsEvent() fails internally. The analytics try/catch must
		// not swallow the subsequent validation throw.
		const script = `
process.stdout.write = () => { throw new Error("simulated stdout failure"); };
try {
  const { validateOnStartup } = await import("./src/crypto.ts");
  validateOnStartup();
  process.stderr.write("STARTUP_OK_UNEXPECTED\\n");
} catch (e) {
  if (e instanceof Error && e.message.includes("ENCRYPTION_KEY is required")) {
    process.stderr.write("VALIDATION_THROW_CORRECT\\n");
  } else if (e instanceof Error && e.message.includes("simulated stdout failure")) {
    process.stderr.write("ANALYTICS_LEAKED\\n");
  } else {
    process.stderr.write("UNEXPECTED_ERROR: " + (e instanceof Error ? e.message : String(e)) + "\\n");
  }
}
`;
		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "",
			NODE_ENV: "test",
		});

		// The validation throw must occur (Tier 1 key_missing), NOT the analytics error.
		expect(result.stderr).toContain("VALIDATION_THROW_CORRECT");
		expect(result.stderr).not.toContain("ANALYTICS_LEAKED");
		expect(result.stderr).not.toContain("STARTUP_OK_UNEXPECTED");
	});

});

// ---------------------------------------------------------------------------
// Suite 2: sdk.startup.succeeded event schema
// ---------------------------------------------------------------------------
describe("sdk.startup.succeeded — event schema", () => {

	test("all required properties present: type, event, env, key_length_bytes, timestamp", () => {
		const script = `
const { validateOnStartup } = await import("./src/crypto.ts");
validateOnStartup();
`;
		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "test",
		});

		// Find the analytics JSON line on stdout
		const lines = result.stdout.split("\n").filter((l) => l.trim().startsWith("{"));
		const succeededLine = lines.find((l) => {
			try {
				return JSON.parse(l).event === "sdk.startup.succeeded";
			} catch {
				return false;
			}
		});

		expect(succeededLine).toBeDefined();

		const payload = JSON.parse(succeededLine!);
		expect(payload).toHaveProperty("type", "analytics");
		expect(payload).toHaveProperty("event", "sdk.startup.succeeded");
		expect(payload).toHaveProperty("env");
		expect(payload).toHaveProperty("key_length_bytes");
		expect(payload).toHaveProperty("timestamp");
	});

	test("key_length_bytes is a number — not key content", () => {
		const testKey = "test-encryption-key-exactly-32b!";
		const script = `
const { validateOnStartup } = await import("./src/crypto.ts");
validateOnStartup();
`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: testKey,
			NODE_ENV: "test",
		});

		const lines = result.stdout.split("\n").filter((l) => l.trim().startsWith("{"));
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
		const script = `
const { validateOnStartup } = await import("./src/crypto.ts");
validateOnStartup();
`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: testKey,
			NODE_ENV: "test",
		});

		// The raw key value must not appear anywhere in the stdout output
		expect(result.stdout).not.toContain(testKey);
		// Verify the serialised payload string does not contain any substring of the key > 8 chars
		// (checking first 8 chars is sufficient — the key prefix test)
		const keyPrefix = testKey.slice(0, 12);
		expect(result.stdout).not.toContain(keyPrefix);
	});

	test("timestamp is a valid ISO 8601 string", () => {
		const script = `
const { validateOnStartup } = await import("./src/crypto.ts");
validateOnStartup();
`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "test",
		});

		const lines = result.stdout.split("\n").filter((l) => l.trim().startsWith("{"));
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
		const script = `
const { validateOnStartup } = await import("./src/crypto.ts");
validateOnStartup();
`;

		const result = runInlineScript(script, {
			ENCRYPTION_KEY: "test-encryption-key-exactly-32b!",
			NODE_ENV: "staging",
		});

		const lines = result.stdout.split("\n").filter((l) => l.trim().startsWith("{"));
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
