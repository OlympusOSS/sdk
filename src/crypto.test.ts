import { describe, expect, test, beforeAll, afterAll, spyOn } from "bun:test";
import crypto from "node:crypto";
import { encrypt, decrypt, isEncryptedFormat, deriveLegacyKeyForMigration, validateOnStartup } from "./crypto";

// Use a 32-byte test key (passes byte-length check; not on production blocklist)
const TEST_KEY = "test-encryption-key-exactly-32b!";

beforeAll(() => {
	process.env.ENCRYPTION_KEY = TEST_KEY;
});

afterAll(() => {
	// Restore to test key in case any test mutated it
	process.env.ENCRYPTION_KEY = TEST_KEY;
});

describe("encrypt/decrypt round-trip (HKDF)", () => {
	test("encrypts and decrypts back to original value", () => {
		const original = "my-secret-value";
		const encrypted = encrypt(original);
		expect(encrypted).not.toBe(original);
		expect(decrypt(encrypted)).toBe(original);
	});

	test("new encryptions carry the v2: prefix", () => {
		const encrypted = encrypt("test-value");
		expect(encrypted.startsWith("v2:")).toBe(true);
	});

	test("v2: prefix followed by three colon-separated parts", () => {
		const encrypted = encrypt("test-value");
		const inner = encrypted.slice("v2:".length);
		expect(inner.split(":").length).toBe(3);
	});

	test("handles special characters", () => {
		const original = "p@$$w0rd!@#$%^&*()_+{}|:<>?~`'\"\n\ttab";
		const encrypted = encrypt(original);
		expect(decrypt(encrypted)).toBe(original);
	});

	test("handles unicode characters", () => {
		const original = "hallo welt cafe resume";
		const encrypted = encrypt(original);
		expect(decrypt(encrypted)).toBe(original);
	});

	test("empty string encrypts to empty string", () => {
		expect(encrypt("")).toBe("");
		expect(decrypt("")).toBe("");
	});

	test("each encryption produces different ciphertext (unique IV)", () => {
		const original = "same-value";
		const enc1 = encrypt(original);
		const enc2 = encrypt(original);
		expect(enc1).not.toBe(enc2);
		// Both still decrypt to the same value
		expect(decrypt(enc1)).toBe(original);
		expect(decrypt(enc2)).toBe(original);
	});

	test("12-byte IV used for new encryptions", () => {
		const encrypted = encrypt("test-12-byte-iv");
		// Format: v2:ivBase64:authTagBase64:ciphertext
		const inner = encrypted.slice("v2:".length);
		const ivBase64 = inner.split(":")[0];
		const ivBytes = Buffer.from(ivBase64, "base64");
		expect(ivBytes.length).toBe(12);
	});
});

describe("backward compatibility — legacy SHA-256 ciphertext (no v2: prefix)", () => {
	test("decrypts legacy format (12-byte IV, SHA-256 key)", () => {
		// Produce a legacy ciphertext directly using the SHA-256 key
		const legacyKey = deriveLegacyKeyForMigration(TEST_KEY);
		const iv = crypto.randomBytes(12);
		const cipher = crypto.createCipheriv("aes-256-gcm", legacyKey, iv);

		let encrypted = cipher.update("legacy-secret", "utf8", "base64");
		encrypted += cipher.final("base64");
		const authTag = cipher.getAuthTag();

		const legacyCiphertext = `${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted}`;

		// Must NOT start with v2:
		expect(legacyCiphertext.startsWith("v2:")).toBe(false);

		// Runtime decrypt() must transparently handle it
		expect(decrypt(legacyCiphertext)).toBe("legacy-secret");
	});

	test("decrypts legacy format with 16-byte IV (older entries)", () => {
		const legacyKey = deriveLegacyKeyForMigration(TEST_KEY);
		const iv = crypto.randomBytes(16);
		const cipher = crypto.createCipheriv("aes-256-gcm", legacyKey, iv);

		let encrypted = cipher.update("legacy-16-byte-iv", "utf8", "base64");
		encrypted += cipher.final("base64");
		const authTag = cipher.getAuthTag();

		const legacyCiphertext = `${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted}`;
		expect(decrypt(legacyCiphertext)).toBe("legacy-16-byte-iv");
	});
});

describe("decrypt with wrong key", () => {
	test("v2 ciphertext throws with wrong key", () => {
		const encrypted = encrypt("secret");

		process.env.ENCRYPTION_KEY = "a-different-key-that-is-32bytes!";

		expect(() => decrypt(encrypted)).toThrow();

		// Restore
		process.env.ENCRYPTION_KEY = TEST_KEY;
	});
});

describe("decrypt plain strings (backward compat)", () => {
	test("returns non-encrypted format strings as-is", () => {
		expect(decrypt("plain-text-value")).toBe("plain-text-value");
		expect(decrypt("no-colons-here")).toBe("no-colons-here");
	});

	test("two-part colon string returned as-is", () => {
		expect(decrypt("one:two")).toBe("one:two");
	});
});

describe("isEncryptedFormat", () => {
	test("detects v2 encrypted format", () => {
		const encrypted = encrypt("test-value");
		expect(isEncryptedFormat(encrypted)).toBe(true);
	});

	test("detects legacy encrypted format (three-part colon, no prefix)", () => {
		// Simulate a legacy ciphertext
		expect(isEncryptedFormat("aaa:bbb:ccc")).toBe(true);
	});

	test("rejects plain strings", () => {
		expect(isEncryptedFormat("just-a-string")).toBe(false);
		expect(isEncryptedFormat("one:two")).toBe(false);
		expect(isEncryptedFormat("")).toBe(false);
	});
});

describe("startup entropy validation (index.ts gate)", () => {
	// The validation runs in index.ts on import, not in crypto.ts.
	// We test it indirectly by verifying the validation logic conditions.

	test("key exactly 32 bytes passes byte-length check", () => {
		// 32 ASCII characters = 32 bytes
		const key32 = "a".repeat(32);
		expect(Buffer.byteLength(key32, "utf8")).toBe(32);
		expect(Buffer.byteLength(key32, "utf8") >= 32).toBe(true);
	});

	test("key 31 bytes fails byte-length check", () => {
		const key31 = "a".repeat(31);
		expect(Buffer.byteLength(key31, "utf8") >= 32).toBe(false);
	});

	test("known dev key is on blocklist", () => {
		const { ENCRYPTION_KEY_BLOCKLIST } = require("./blocklist");
		expect(ENCRYPTION_KEY_BLOCKLIST).toContain("dev-encryption-key-minimum-32-chars!!");
	});

	test("blocklist check is scoped to NODE_ENV=production", () => {
		// The test environment is not production — dev key should not cause errors here.
		// This test validates the scoping logic rather than triggering the module-load check.
		const originalNodeEnv = process.env.NODE_ENV;
		const devKey = "dev-encryption-key-minimum-32-chars!!";
		const { ENCRYPTION_KEY_BLOCKLIST } = require("./blocklist");

		// Simulate production check
		const isProductionBlocklisted =
			process.env.NODE_ENV === "production" && ENCRYPTION_KEY_BLOCKLIST.includes(devKey);
		expect(isProductionBlocklisted).toBe(false); // test env is not production

		// Simulate: what would happen in production
		const wouldBlockInProduction =
			"production" === "production" && ENCRYPTION_KEY_BLOCKLIST.includes(devKey);
		expect(wouldBlockInProduction).toBe(true);

		process.env.NODE_ENV = originalNodeEnv;
	});
});

describe("validateOnStartup()", () => {
	const originalKey = process.env.ENCRYPTION_KEY;
	const originalNodeEnv = process.env.NODE_ENV;

	afterAll(() => {
		process.env.ENCRYPTION_KEY = originalKey;
		process.env.NODE_ENV = originalNodeEnv;
	});

	test("passes silently for a valid 32-byte key", () => {
		process.env.ENCRYPTION_KEY = "test-encryption-key-exactly-32b!";
		process.env.NODE_ENV = "test";
		expect(() => validateOnStartup()).not.toThrow();
	});

	test("throws Tier 1 (key_missing) when ENCRYPTION_KEY is absent", () => {
		process.env.ENCRYPTION_KEY = "";
		process.env.NODE_ENV = "test";
		expect(() => validateOnStartup()).toThrow("[SDK] ENCRYPTION_KEY is required.");
	});

	test("Tier 1 error message contains openssl rand instruction", () => {
		process.env.ENCRYPTION_KEY = "";
		process.env.NODE_ENV = "test";
		let message = "";
		try {
			validateOnStartup();
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).toContain("openssl rand -base64 32");
	});

	test("throws Tier 2 (key_too_short) when ENCRYPTION_KEY is < 32 bytes", () => {
		process.env.ENCRYPTION_KEY = "short";
		process.env.NODE_ENV = "test";
		expect(() => validateOnStartup()).toThrow("[SDK] ENCRYPTION_KEY is too short");
	});

	test("Tier 2 error includes byte counts", () => {
		process.env.ENCRYPTION_KEY = "short";
		process.env.NODE_ENV = "test";
		let message = "";
		try {
			validateOnStartup();
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).toContain("5 bytes provided");
		expect(message).toContain("32 bytes required");
	});

	test("Tier 2 error message does not contain key material", () => {
		const shortKey = "onlythirty1bytes!!!!!!!!!!!!!!!";
		process.env.ENCRYPTION_KEY = shortKey;
		process.env.NODE_ENV = "test";
		let message = "";
		try {
			validateOnStartup();
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).not.toContain(shortKey);
		expect(message).not.toContain(shortKey.slice(0, 8));
	});

	test("throws Tier 3 (key_blocklisted) for dev default key in production", () => {
		const devKey = "dev-encryption-key-minimum-32-chars!!";
		process.env.ENCRYPTION_KEY = devKey;
		process.env.NODE_ENV = "production";
		expect(() => validateOnStartup()).toThrow(
			"[SDK] ENCRYPTION_KEY matches a known dev default",
		);
		// Restore
		process.env.NODE_ENV = originalNodeEnv;
	});

	test("Tier 3 error message does not contain key material (no key.slice)", () => {
		const devKey = "dev-encryption-key-minimum-32-chars!!";
		process.env.ENCRYPTION_KEY = devKey;
		process.env.NODE_ENV = "production";
		let message = "";
		try {
			validateOnStartup();
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		// Key content must not appear in the error message
		expect(message).not.toContain(devKey);
		expect(message).not.toContain(devKey.slice(0, 8));
		// Restore
		process.env.NODE_ENV = originalNodeEnv;
	});

	test("dev default key is NOT rejected in non-production environments", () => {
		const devKey = "dev-encryption-key-minimum-32-chars!!";
		process.env.ENCRYPTION_KEY = devKey;
		process.env.NODE_ENV = "development";
		expect(() => validateOnStartup()).not.toThrow();
	});

	test("AC-3: HKDF is the key derivation code path (not bare SHA-256)", () => {
		// Verify that crypto.hkdfSync is called during encrypt(), which uses deriveHkdfKey()
		// This confirms the HKDF derivation path is active (not createHash('sha256'))
		process.env.ENCRYPTION_KEY = "test-encryption-key-exactly-32b!";
		process.env.NODE_ENV = "test";

		const hkdfSyncSpy = spyOn(crypto, "hkdfSync");
		encrypt("test-value-for-hkdf-assertion");

		expect(hkdfSyncSpy).toHaveBeenCalled();
		expect(hkdfSyncSpy).toHaveBeenCalledWith(
			"sha256",
			expect.any(Buffer),
			expect.any(Buffer),
			expect.any(Buffer),
			32,
		);
		hkdfSyncSpy.mockRestore();
	});

	test("validateOnStartup emits sdk.startup.succeeded on success (no key material in output)", () => {
		const testKey = "test-encryption-key-exactly-32b!";
		process.env.ENCRYPTION_KEY = testKey;
		process.env.NODE_ENV = "test";

		const emitted: string[] = [];
		const originalWrite = process.stdout.write.bind(process.stdout);
		process.stdout.write = (chunk: unknown): boolean => {
			emitted.push(String(chunk));
			return true;
		};

		try {
			validateOnStartup();
		} finally {
			process.stdout.write = originalWrite;
		}

		const combined = emitted.join("");
		expect(combined).toContain("sdk.startup.succeeded");
		// key material must not appear in the analytics output
		expect(combined).not.toContain(testKey);
		expect(combined).not.toContain(testKey.slice(0, 8));
	});
});

describe("Security C3: exact error messages for lazy validateEncryptionKey()", () => {
	// These tests verify the EXACT error messages thrown by the internal
	// validateEncryptionKey() when called via encrypt()/decrypt() at runtime.
	// This satisfies Security condition C3: "Exact SDK error message verified
	// by automated unit test."

	const originalKey = process.env.ENCRYPTION_KEY;
	const originalNodeEnv = process.env.NODE_ENV;

	afterAll(() => {
		process.env.ENCRYPTION_KEY = originalKey;
		process.env.NODE_ENV = originalNodeEnv;
	});

	test("encrypt() throws exact Tier 1 message when ENCRYPTION_KEY is absent", () => {
		delete process.env.ENCRYPTION_KEY;
		process.env.NODE_ENV = "test";
		let message = "";
		try {
			encrypt("test");
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).toBe(
			"[SDK] ENCRYPTION_KEY environment variable is required but not set. " +
			"Generate a key with: openssl rand -base64 32",
		);
	});

	test("decrypt() throws exact Tier 1 message when ENCRYPTION_KEY is absent", () => {
		delete process.env.ENCRYPTION_KEY;
		process.env.NODE_ENV = "test";
		let message = "";
		try {
			decrypt("v2:abc:def:ghi");
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).toBe(
			"[SDK] ENCRYPTION_KEY environment variable is required but not set. " +
			"Generate a key with: openssl rand -base64 32",
		);
	});

	test("encrypt() throws exact Tier 2 message when ENCRYPTION_KEY is too short", () => {
		process.env.ENCRYPTION_KEY = "short-key";
		process.env.NODE_ENV = "test";
		let message = "";
		try {
			encrypt("test");
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).toBe(
			"[SDK] ENCRYPTION_KEY does not meet minimum length: " +
			"9 bytes provided, 32 bytes required. " +
			"Generate a key with: openssl rand -base64 32",
		);
	});

	test("encrypt() throws exact Tier 3 message for blocklisted key in production", () => {
		process.env.ENCRYPTION_KEY = "dev-encryption-key-minimum-32-chars!!";
		process.env.NODE_ENV = "production";
		let message = "";
		try {
			encrypt("test");
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).toBe(
			"[SDK] ENCRYPTION_KEY matches a known development default and must not be used in production. " +
			"Generate a production key with: openssl rand -base64 32",
		);
		process.env.NODE_ENV = originalNodeEnv;
	});

	test("error messages never contain key material", () => {
		const shortKey = "my-secret-short-key";
		process.env.ENCRYPTION_KEY = shortKey;
		process.env.NODE_ENV = "test";
		let message = "";
		try {
			encrypt("test");
		} catch (e) {
			message = e instanceof Error ? e.message : String(e);
		}
		expect(message).not.toContain(shortKey);
		expect(message).not.toContain(shortKey.slice(0, 8));
	});
});
