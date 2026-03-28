import { describe, expect, test, beforeEach } from "bun:test";
import { SettingsCache } from "./cache";

let cache: SettingsCache;

beforeEach(() => {
	cache = new SettingsCache(1); // 1-second TTL for fast expiry tests
});

describe("SettingsCache", () => {
	test("set/get returns correct value", () => {
		cache.set("key1", "value1");
		expect(cache.get("key1")).toBe("value1");
	});

	test("get returns undefined for missing keys", () => {
		expect(cache.get("nonexistent")).toBeUndefined();
	});

	test("can store null values", () => {
		cache.set("nullable", null);
		expect(cache.get("nullable")).toBeNull();
	});

	test("returns undefined for expired entries", async () => {
		// Use a very short TTL override
		cache.set("expiring", "gone-soon", 50); // 50ms TTL
		expect(cache.get("expiring")).toBe("gone-soon");

		await new Promise((r) => setTimeout(r, 60));
		expect(cache.get("expiring")).toBeUndefined();
	});

	test("invalidate(key) removes a single entry", () => {
		cache.set("a", "1");
		cache.set("b", "2");
		cache.invalidate("a");
		expect(cache.get("a")).toBeUndefined();
		expect(cache.get("b")).toBe("2");
	});

	test("invalidate() with no args clears all entries", () => {
		cache.set("a", "1");
		cache.set("b", "2");
		cache.invalidate();
		expect(cache.get("a")).toBeUndefined();
		expect(cache.get("b")).toBeUndefined();
		expect(cache.size).toBe(0);
	});

	test("size reflects number of stored entries", () => {
		expect(cache.size).toBe(0);
		cache.set("a", "1");
		expect(cache.size).toBe(1);
		cache.set("b", "2");
		expect(cache.size).toBe(2);
	});

	test("overwriting a key updates the value", () => {
		cache.set("key", "old");
		cache.set("key", "new");
		expect(cache.get("key")).toBe("new");
		expect(cache.size).toBe(1);
	});
});
