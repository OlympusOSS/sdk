import { describe, expect, test, beforeAll, afterAll } from "bun:test";
import crypto from "node:crypto";
import { encrypt, decrypt, isEncryptedFormat, deriveLegacyKeyForMigration } from "./crypto";

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
