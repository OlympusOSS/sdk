import { describe, expect, test, mock, beforeEach } from "bun:test";

// Track upserted rows and invalidated cache keys across tests
let upsertedRows: Array<{ key: string; value: string; encrypted: boolean; category: string }> = [];
let invalidatedKeys: string[] = [];
// Controls whether the transaction should throw (to simulate rollback)
let txShouldFail = false;

// Mock the database module before importing settings
// We test getSettingOrDefault logic without needing a real DB
mock.module("./db", () => ({
	getDb: () => ({
		unsafe: async () => [],
		// sql.begin(fn) — executes fn with a tx object; throws if txShouldFail is set
		begin: async (fn: (tx: { unsafe: (...args: unknown[]) => Promise<unknown[]> }) => Promise<void>) => {
			if (txShouldFail) {
				throw new Error("simulated transaction failure");
			}
			const tx = {
				unsafe: async (_query: string, params: [string, string, boolean, string]) => {
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

// Mock the crypto module so we can observe encryption calls without real keys
mock.module("./crypto", () => ({
	encrypt: (value: string) => `encrypted:${value}:mock`,
	decrypt: (value: string) => value,
	isEncryptedFormat: () => false,
	deriveLegacyKeyForMigration: () => Buffer.alloc(32),
	deriveHkdfKeyForMigration: () => Buffer.alloc(32),
	validateOnStartup: () => {},
}));

// Mock the cache to give us control over returned values
let mockCacheStore = new Map<string, string | null>();

mock.module("./cache", () => ({
	settingsCache: {
		get: (key: string) => {
			if (mockCacheStore.has(key)) return mockCacheStore.get(key);
			return undefined; // cache miss
		},
		set: () => {},
		invalidate: (key: string) => {
			invalidatedKeys.push(key);
		},
	},
	SettingsCache: class {},
}));

// Now import after mocks are in place
const { getSettingOrDefault, batchSetSettings } = await import("./settings");

beforeEach(() => {
	mockCacheStore.clear();
	upsertedRows = [];
	invalidatedKeys = [];
	txShouldFail = false;
});

describe("getSettingOrDefault", () => {
	test("returns stored value (not fallback) when key exists", async () => {
		mockCacheStore.set("captcha.enabled", "true");
		const result = await getSettingOrDefault("captcha.enabled", "false");
		expect(result).toBe("true");
	});

	test("returns fallback when key is missing", async () => {
		// Key not in cache and DB mock returns empty rows -> null -> fallback
		const result = await getSettingOrDefault("missing.key", "default-val");
		expect(result).toBe("default-val");
	});

	test("returns empty string (not fallback) when value is empty string", async () => {
		// This tests the ?? fix: empty string is a valid value, not nullish
		mockCacheStore.set("some.key", "");
		const result = await getSettingOrDefault("some.key", "should-not-use");
		expect(result).toBe("");
	});

	test('returns "0" (not fallback) when value is "0"', async () => {
		// This tests the ?? fix: "0" is a valid string value, not nullish
		mockCacheStore.set("feature.limit", "0");
		const result = await getSettingOrDefault("feature.limit", "10");
		expect(result).toBe("0");
	});

	test("returns null-cached value as fallback", async () => {
		// When the DB lookup found nothing, cache stores null
		mockCacheStore.set("no.value", null);
		const result = await getSettingOrDefault("no.value", "fallback");
		expect(result).toBe("fallback");
	});
});

describe("batchSetSettings", () => {
	test("no-op when entries array is empty", async () => {
		await batchSetSettings([], "test_settings");
		expect(upsertedRows).toHaveLength(0);
		expect(invalidatedKeys).toHaveLength(0);
	});

	test("writes all entries in a single transaction", async () => {
		const entries = [
			{ key: "mfa.enabled", value: "true" },
			{ key: "mfa.methods", value: "totp,sms" },
		];

		await batchSetSettings(entries, "test_settings");

		expect(upsertedRows).toHaveLength(2);
		expect(upsertedRows[0].key).toBe("mfa.enabled");
		expect(upsertedRows[0].value).toBe("true");
		expect(upsertedRows[0].encrypted).toBe(false);
		expect(upsertedRows[0].category).toBe("general");

		expect(upsertedRows[1].key).toBe("mfa.methods");
		expect(upsertedRows[1].value).toBe("totp,sms");
	});

	test("encrypts entries marked as encrypted", async () => {
		const entries = [
			{ key: "mfa.secret", value: "supersecret", encrypted: true },
			{ key: "mfa.enabled", value: "true", encrypted: false },
		];

		await batchSetSettings(entries, "test_settings");

		// Encrypted entry should have mocked encrypted format
		expect(upsertedRows[0].encrypted).toBe(true);
		expect(upsertedRows[0].value).toBe("encrypted:supersecret:mock");

		// Plain entry should store value as-is
		expect(upsertedRows[1].encrypted).toBe(false);
		expect(upsertedRows[1].value).toBe("true");
	});

	test("respects category field per entry", async () => {
		const entries = [
			{ key: "mfa.enabled", value: "true", category: "mfa" },
			{ key: "captcha.enabled", value: "false", category: "captcha" },
		];

		await batchSetSettings(entries, "test_settings");

		expect(upsertedRows[0].category).toBe("mfa");
		expect(upsertedRows[1].category).toBe("captcha");
	});

	test("defaults category to 'general' when not provided", async () => {
		await batchSetSettings([{ key: "some.key", value: "val" }], "test_settings");
		expect(upsertedRows[0].category).toBe("general");
	});

	test("invalidates cache for all written keys after successful commit", async () => {
		const entries = [
			{ key: "mfa.enabled", value: "true" },
			{ key: "mfa.methods", value: "totp" },
			{ key: "mfa.max_attempts", value: "3" },
		];

		await batchSetSettings(entries, "test_settings");

		expect(invalidatedKeys).toContain("mfa.enabled");
		expect(invalidatedKeys).toContain("mfa.methods");
		expect(invalidatedKeys).toContain("mfa.max_attempts");
		expect(invalidatedKeys).toHaveLength(3);
	});

	test("throws a descriptive error and does not invalidate cache when transaction fails", async () => {
		txShouldFail = true;

		const entries = [
			{ key: "mfa.enabled", value: "true" },
			{ key: "mfa.methods", value: "totp" },
		];

		await expect(batchSetSettings(entries, "test_settings")).rejects.toThrow(
			"batchSetSettings failed — transaction rolled back",
		);

		// Cache should NOT be invalidated because the transaction rolled back
		expect(invalidatedKeys).toHaveLength(0);
		// No rows should have been written
		expect(upsertedRows).toHaveLength(0);
	});

	test("rejects invalid table name to prevent SQL injection", async () => {
		await expect(
			batchSetSettings([{ key: "k", value: "v" }], "bad; DROP TABLE users--"),
		).rejects.toThrow("Invalid table name");
	});
});
