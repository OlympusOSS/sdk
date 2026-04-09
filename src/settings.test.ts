/**
 * Settings module tests.
 *
 * These tests run in a child Bun process to avoid mock.module() contamination
 * of the module registry. Bun evaluates all test files in a single process
 * before running any tests, so top-level mock.module() calls leak into other
 * test files (e.g., crypto.test.ts). Subprocess isolation eliminates this.
 */
import { describe, expect, test } from "bun:test";

// ---------------------------------------------------------------------------
// Helper: run an inline TypeScript snippet in a child Bun process with
// module mocks applied inside that process. Returns parsed JSON output.
// ---------------------------------------------------------------------------
function runSettingsTest(
	script: string,
): { stdout: string; stderr: string; exitCode: number } {
	const proc = Bun.spawnSync(
		["bun", "--eval", script],
		{
			env: { ...process.env, ENCRYPTION_KEY: "test-encryption-key-exactly-32b!" },
			stderr: "pipe",
			stdout: "pipe",
			cwd: import.meta.dir,
		},
	);
	return {
		stderr: new TextDecoder().decode(proc.stderr),
		stdout: new TextDecoder().decode(proc.stdout),
		exitCode: proc.exitCode ?? -1,
	};
}

/**
 * Build the inline script that sets up mocks + runs a single test scenario.
 * The mock setup and import happen inside the child process, so they cannot
 * leak into the parent's module registry.
 */
function buildScript(testBody: string): string {
	return `
import { mock } from "bun:test";

let upsertedRows = [];
let invalidatedKeys = [];
let txShouldFail = false;

mock.module("./db", () => ({
	getDb: () => ({
		unsafe: async () => [],
		begin: async (fn) => {
			if (txShouldFail) {
				throw new Error("simulated transaction failure");
			}
			const tx = {
				unsafe: async (_query, params) => {
					upsertedRows.push({
						key: params[0],
						value: params[1],
						encrypted: params[2],
						category: params[3],
					});
					return [];
				},
			};
			await fn(tx);
		},
	}),
	getSettingsTable: () => "test_settings",
	ensureTable: async () => {},
}));

mock.module("./crypto", () => ({
	encrypt: (value) => \`encrypted:\${value}:mock\`,
	decrypt: (value) => value,
	isEncryptedFormat: () => false,
	deriveLegacyKeyForMigration: () => Buffer.alloc(32),
	deriveHkdfKeyForMigration: () => Buffer.alloc(32),
	validateOnStartup: () => {},
}));

let mockCacheStore = new Map();

mock.module("./cache", () => ({
	settingsCache: {
		get: (key) => {
			if (mockCacheStore.has(key)) return mockCacheStore.get(key);
			return undefined;
		},
		set: () => {},
		invalidate: (key) => {
			invalidatedKeys.push(key);
		},
	},
	SettingsCache: class {},
}));

const { getSettingOrDefault, batchSetSettings } = await import("./settings");

// Reset state helper
function resetState() {
	mockCacheStore.clear();
	upsertedRows = [];
	invalidatedKeys = [];
	txShouldFail = false;
}

try {
	${testBody}
	process.stdout.write(JSON.stringify({ pass: true }) + "\\n");
} catch (e) {
	process.stdout.write(JSON.stringify({ pass: false, error: e.message }) + "\\n");
}
`;
}

// ---------------------------------------------------------------------------
// Helper to parse subprocess result
// ---------------------------------------------------------------------------
function parseResult(r: { stdout: string; stderr: string; exitCode: number }): { pass: boolean; error?: string } {
	const lines = r.stdout.trim().split("\n");
	const lastJson = lines.filter(l => l.startsWith("{")).pop();
	if (!lastJson) {
		return { pass: false, error: `No JSON output. stderr: ${r.stderr}` };
	}
	return JSON.parse(lastJson);
}

function expectPass(r: { stdout: string; stderr: string; exitCode: number }) {
	const result = parseResult(r);
	if (!result.pass) {
		throw new Error(`Subprocess test failed: ${result.error}`);
	}
}

// ---------------------------------------------------------------------------
// getSettingOrDefault
// ---------------------------------------------------------------------------
describe("getSettingOrDefault", () => {
	test("returns stored value (not fallback) when key exists", () => {
		const r = runSettingsTest(buildScript(`
			mockCacheStore.set("captcha.enabled", "true");
			const result = await getSettingOrDefault("captcha.enabled", "false");
			if (result !== "true") throw new Error("Expected 'true', got '" + result + "'");
		`));
		expectPass(r);
	});

	test("returns fallback when key is missing", () => {
		const r = runSettingsTest(buildScript(`
			const result = await getSettingOrDefault("missing.key", "default-val");
			if (result !== "default-val") throw new Error("Expected 'default-val', got '" + result + "'");
		`));
		expectPass(r);
	});

	test("returns empty string (not fallback) when value is empty string", () => {
		const r = runSettingsTest(buildScript(`
			mockCacheStore.set("some.key", "");
			const result = await getSettingOrDefault("some.key", "should-not-use");
			if (result !== "") throw new Error("Expected empty string, got '" + result + "'");
		`));
		expectPass(r);
	});

	test('returns "0" (not fallback) when value is "0"', () => {
		const r = runSettingsTest(buildScript(`
			mockCacheStore.set("feature.limit", "0");
			const result = await getSettingOrDefault("feature.limit", "10");
			if (result !== "0") throw new Error("Expected '0', got '" + result + "'");
		`));
		expectPass(r);
	});

	test("returns null-cached value as fallback", () => {
		const r = runSettingsTest(buildScript(`
			mockCacheStore.set("no.value", null);
			const result = await getSettingOrDefault("no.value", "fallback");
			if (result !== "fallback") throw new Error("Expected 'fallback', got '" + result + "'");
		`));
		expectPass(r);
	});
});

// ---------------------------------------------------------------------------
// batchSetSettings
// ---------------------------------------------------------------------------
describe("batchSetSettings", () => {
	test("no-op when entries array is empty", () => {
		const r = runSettingsTest(buildScript(`
			await batchSetSettings([], "test_settings");
			if (upsertedRows.length !== 0) throw new Error("Expected 0 upserted rows");
			if (invalidatedKeys.length !== 0) throw new Error("Expected 0 invalidated keys");
		`));
		expectPass(r);
	});

	test("writes all entries in a single transaction", () => {
		const r = runSettingsTest(buildScript(`
			const entries = [
				{ key: "mfa.enabled", value: "true" },
				{ key: "mfa.methods", value: "totp,sms" },
			];
			await batchSetSettings(entries, "test_settings");
			if (upsertedRows.length !== 2) throw new Error("Expected 2 rows, got " + upsertedRows.length);
			if (upsertedRows[0].key !== "mfa.enabled") throw new Error("Wrong key[0]");
			if (upsertedRows[0].value !== "true") throw new Error("Wrong value[0]");
			if (upsertedRows[0].encrypted !== false) throw new Error("Wrong encrypted[0]");
			if (upsertedRows[0].category !== "general") throw new Error("Wrong category[0]");
			if (upsertedRows[1].key !== "mfa.methods") throw new Error("Wrong key[1]");
			if (upsertedRows[1].value !== "totp,sms") throw new Error("Wrong value[1]");
		`));
		expectPass(r);
	});

	test("encrypts entries marked as encrypted", () => {
		const r = runSettingsTest(buildScript(`
			const entries = [
				{ key: "mfa.secret", value: "supersecret", encrypted: true },
				{ key: "mfa.enabled", value: "true", encrypted: false },
			];
			await batchSetSettings(entries, "test_settings");
			if (upsertedRows[0].encrypted !== true) throw new Error("Expected encrypted[0]=true");
			if (upsertedRows[0].value !== "encrypted:supersecret:mock") throw new Error("Wrong encrypted value: " + upsertedRows[0].value);
			if (upsertedRows[1].encrypted !== false) throw new Error("Expected encrypted[1]=false");
			if (upsertedRows[1].value !== "true") throw new Error("Wrong plain value");
		`));
		expectPass(r);
	});

	test("respects category field per entry", () => {
		const r = runSettingsTest(buildScript(`
			const entries = [
				{ key: "mfa.enabled", value: "true", category: "mfa" },
				{ key: "captcha.enabled", value: "false", category: "captcha" },
			];
			await batchSetSettings(entries, "test_settings");
			if (upsertedRows[0].category !== "mfa") throw new Error("Wrong category[0]");
			if (upsertedRows[1].category !== "captcha") throw new Error("Wrong category[1]");
		`));
		expectPass(r);
	});

	test("defaults category to 'general' when not provided", () => {
		const r = runSettingsTest(buildScript(`
			await batchSetSettings([{ key: "some.key", value: "val" }], "test_settings");
			if (upsertedRows[0].category !== "general") throw new Error("Expected 'general', got '" + upsertedRows[0].category + "'");
		`));
		expectPass(r);
	});

	test("invalidates cache for all written keys after successful commit", () => {
		const r = runSettingsTest(buildScript(`
			const entries = [
				{ key: "mfa.enabled", value: "true" },
				{ key: "mfa.methods", value: "totp" },
				{ key: "mfa.max_attempts", value: "3" },
			];
			await batchSetSettings(entries, "test_settings");
			if (!invalidatedKeys.includes("mfa.enabled")) throw new Error("Missing mfa.enabled in invalidated");
			if (!invalidatedKeys.includes("mfa.methods")) throw new Error("Missing mfa.methods in invalidated");
			if (!invalidatedKeys.includes("mfa.max_attempts")) throw new Error("Missing mfa.max_attempts in invalidated");
			if (invalidatedKeys.length !== 3) throw new Error("Expected 3 invalidated keys, got " + invalidatedKeys.length);
		`));
		expectPass(r);
	});

	test("throws a descriptive error and does not invalidate cache when transaction fails", () => {
		const r = runSettingsTest(buildScript(`
			txShouldFail = true;
			const entries = [
				{ key: "mfa.enabled", value: "true" },
				{ key: "mfa.methods", value: "totp" },
			];
			let threw = false;
			try {
				await batchSetSettings(entries, "test_settings");
			} catch (e) {
				threw = true;
				if (!e.message.includes("batchSetSettings failed")) {
					throw new Error("Wrong error: " + e.message);
				}
			}
			if (!threw) throw new Error("Expected batchSetSettings to throw");
			if (invalidatedKeys.length !== 0) throw new Error("Cache should not be invalidated on failure");
			if (upsertedRows.length !== 0) throw new Error("No rows should be written on failure");
		`));
		expectPass(r);
	});

	test("rejects invalid table name to prevent SQL injection", () => {
		const r = runSettingsTest(buildScript(`
			let threw = false;
			try {
				await batchSetSettings([{ key: "k", value: "v" }], "bad; DROP TABLE users--");
			} catch (e) {
				threw = true;
				if (!e.message.includes("Invalid table name")) {
					throw new Error("Wrong error: " + e.message);
				}
			}
			if (!threw) throw new Error("Expected batchSetSettings to throw for invalid table name");
		`));
		expectPass(r);
	});
});
