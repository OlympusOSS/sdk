import { describe, expect, test, mock, beforeEach } from "bun:test";

// Mock the database module before importing settings
// We test getSettingOrDefault logic without needing a real DB
mock.module("./db", () => ({
	getDb: () => ({
		unsafe: async () => [],
	}),
	getSettingsTable: () => "test_settings",
	ensureTable: async () => {},
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
		invalidate: () => {},
	},
	SettingsCache: class {},
}));

// Now import after mocks are in place
const { getSettingOrDefault } = await import("./settings");

beforeEach(() => {
	mockCacheStore.clear();
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
