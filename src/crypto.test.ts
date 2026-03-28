import { describe, expect, test, beforeAll } from "bun:test";
import crypto from "node:crypto";
import { encrypt, decrypt, isEncryptedFormat } from "./crypto";

beforeAll(() => {
	process.env.ENCRYPTION_KEY = "test-encryption-key-for-unit-tests";
});

describe("encrypt/decrypt round-trip", () => {
	test("encrypts and decrypts back to original value", () => {
		const original = "my-secret-value";
		const encrypted = encrypt(original);
		expect(encrypted).not.toBe(original);
		expect(decrypt(encrypted)).toBe(original);
	});

	test("handles special characters", () => {
		const original = "p@$$w0rd!@#$%^&*()_+{}|:<>?~`'\"\n\ttab";
		const encrypted = encrypt(original);
		expect(decrypt(encrypted)).toBe(original);
	});

	test("handles unicode and emoji", () => {
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
});

describe("decrypt with wrong key", () => {
	test("throws error instead of silently returning ciphertext", () => {
		const encrypted = encrypt("secret");

		// Switch to a different key
		process.env.ENCRYPTION_KEY = "different-key-entirely";

		expect(() => decrypt(encrypted)).toThrow();

		// Restore original key
		process.env.ENCRYPTION_KEY = "test-encryption-key-for-unit-tests";
	});
});

describe("decrypt plain strings (backward compat)", () => {
	test("returns non-encrypted format strings as-is", () => {
		expect(decrypt("plain-text-value")).toBe("plain-text-value");
		expect(decrypt("no-colons-here")).toBe("no-colons-here");
	});
});

describe("isEncryptedFormat", () => {
	test("detects encrypted format (three colon-separated parts)", () => {
		const encrypted = encrypt("test-value");
		expect(isEncryptedFormat(encrypted)).toBe(true);
	});

	test("rejects plain strings", () => {
		expect(isEncryptedFormat("just-a-string")).toBe(false);
		expect(isEncryptedFormat("one:two")).toBe(false);
		expect(isEncryptedFormat("")).toBe(false);
	});

	test("returns true for any three-part colon string", () => {
		expect(isEncryptedFormat("a:b:c")).toBe(true);
	});
});

describe("12-byte IV (current) encryptions", () => {
	test("new encryptions use 12-byte IV and decrypt correctly", () => {
		const original = "test-12-byte-iv";
		const encrypted = encrypt(original);
		const ivBase64 = encrypted.split(":")[0];
		const ivBytes = Buffer.from(ivBase64, "base64");
		expect(ivBytes.length).toBe(12);
		expect(decrypt(encrypted)).toBe(original);
	});
});

describe("legacy 16-byte IV backward compatibility", () => {
	test("decrypts values encrypted with 16-byte IV", () => {
		// Manually create a ciphertext with a 16-byte IV to simulate legacy data
		const key = crypto.createHash("sha256").update("test-encryption-key-for-unit-tests").digest();
		const iv = crypto.randomBytes(16);
		const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

		let encrypted = cipher.update("legacy-secret", "utf8", "base64");
		encrypted += cipher.final("base64");
		const authTag = cipher.getAuthTag();

		const legacyCiphertext = `${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted}`;

		// The current decrypt function should handle 16-byte IVs
		expect(decrypt(legacyCiphertext)).toBe("legacy-secret");
	});
});
