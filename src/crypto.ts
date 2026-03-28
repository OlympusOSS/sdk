import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // NIST SP 800-38D recommended 96-bit IV for AES-GCM

function getEncryptionKey(): Buffer {
	const key = process.env.ENCRYPTION_KEY;
	if (!key) {
		throw new Error("ENCRYPTION_KEY environment variable is required");
	}
	// Use SHA-256 to ensure we have exactly 32 bytes for AES-256
	return crypto.createHash("sha256").update(key).digest();
}

/**
 * Encrypts a plaintext value using AES-256-GCM.
 * Returns format: iv:authTag:encryptedData (all base64 encoded)
 */
export function encrypt(plaintext: string): string {
	if (!plaintext) return "";

	const key = getEncryptionKey();
	const iv = crypto.randomBytes(IV_LENGTH);
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

	let encrypted = cipher.update(plaintext, "utf8", "base64");
	encrypted += cipher.final("base64");
	const authTag = cipher.getAuthTag();

	return `${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted}`;
}

/**
 * Decrypts a value that was encrypted with AES-256-GCM.
 * Format expected: iv:authTag:encryptedData (all base64 encoded)
 *
 * Supports both legacy 16-byte IVs and current 12-byte IVs for
 * backward compatibility with existing encrypted data.
 *
 * If the value doesn't match the encrypted format, returns it as-is
 * for backwards compatibility with plain-text env vars.
 *
 * Throws on decryption failure to prevent ciphertext leaking to callers.
 */
export function decrypt(encryptedValue: string): string {
	if (!encryptedValue) return "";

	// Check if it's an encrypted value (format: iv:authTag:data)
	const parts = encryptedValue.split(":");
	if (parts.length !== 3) {
		// Not encrypted, return as-is (backwards compatibility)
		return encryptedValue;
	}

	const [ivBase64, authTagBase64, encryptedData] = parts;
	const key = getEncryptionKey();
	const iv = Buffer.from(ivBase64, "base64");
	const authTag = Buffer.from(authTagBase64, "base64");

	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
	decipher.setAuthTag(authTag);

	let decrypted = decipher.update(encryptedData, "base64", "utf8");
	decrypted += decipher.final("utf8");

	return decrypted;
}

/**
 * Checks whether a value appears to be in the encrypted format.
 */
export function isEncryptedFormat(value: string): boolean {
	const parts = value.split(":");
	return parts.length === 3;
}
