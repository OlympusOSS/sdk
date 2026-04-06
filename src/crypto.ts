import crypto from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // NIST SP 800-38D recommended 96-bit IV for AES-GCM

/**
 * Ciphertext version prefix for HKDF-derived key encryptions.
 *
 * v2: — current format, AES-256-GCM with HKDF-SHA-256-derived key.
 *       Full format: v2:ivBase64:authTagBase64:ciphertextBase64
 *
 * (no prefix) — legacy format, AES-256-GCM with bare SHA-256-derived key.
 *       Full format: ivBase64:authTagBase64:ciphertextBase64
 *
 * Note: the v2: prefix implicitly encodes the HKDF info string
 * ('olympus-settings-aes-256-gcm') as a constant. If the info string ever
 * changes, a new version prefix must be introduced (v3:, etc.) to distinguish
 * ciphertexts encrypted under different derivations.
 */
const V2_PREFIX = "v2:";

/**
 * HKDF info string for domain-separated AES key derivation.
 * Distinct from any other key derived from the same ENCRYPTION_KEY IKM.
 */
const HKDF_INFO = "olympus-settings-aes-256-gcm";

/**
 * Derives the AES-256 key using HKDF-SHA-256.
 *
 * Parameters:
 *   Hash:   SHA-256
 *   IKM:    ENCRYPTION_KEY raw bytes
 *   Salt:   absent (zero-length) — correct when IKM is uniformly random
 *           (openssl rand -base64 32). A hard-coded constant salt adds no
 *           security and would be misleading. Absent salt is the specified,
 *           documented choice for this SDK.
 *   Info:   'olympus-settings-aes-256-gcm' — domain separation
 *   Length: 32 bytes — AES-256
 *
 * IMPORTANT: Entropy validation (byte-length + blocklist) is enforced at
 * SDK initialisation time in index.ts, not here. This function assumes a
 * validated key is provided.
 *
 * Scope limitation: if sdk/src/crypto.ts is imported directly without going
 * through the SDK barrel (index.ts), the startup entropy check does not fire.
 * All current SDK consumers import via the barrel. Future consumers importing
 * crypto.ts directly bypass this check — see README for details.
 */
function deriveHkdfKey(rawKey: string): Buffer {
	const ikm = Buffer.from(rawKey, "utf8");
	const salt = Buffer.alloc(0); // absent salt — see JSDoc above
	const info = Buffer.from(HKDF_INFO, "utf8");
	return Buffer.from(
		crypto.hkdfSync("sha256", ikm, salt, info, 32),
	);
}

/**
 * Derives the AES-256 key using bare SHA-256.
 * Legacy path only — used by decrypt() for backward compatibility and by
 * the migration script. Do NOT use for new encryptions.
 */
function deriveLegacySha256Key(rawKey: string): Buffer {
	return crypto.createHash("sha256").update(rawKey).digest();
}

/**
 * Returns the current HKDF-derived AES key from ENCRYPTION_KEY.
 * Throws if ENCRYPTION_KEY is not set.
 */
function getEncryptionKey(): Buffer {
	const key = process.env.ENCRYPTION_KEY;
	if (!key) {
		throw new Error("ENCRYPTION_KEY environment variable is required");
	}
	return deriveHkdfKey(key);
}

/**
 * Returns the legacy SHA-256-derived AES key from ENCRYPTION_KEY.
 * Used only for decrypting legacy (no-prefix) ciphertext and migration.
 */
function getLegacyEncryptionKey(): Buffer {
	const key = process.env.ENCRYPTION_KEY;
	if (!key) {
		throw new Error("ENCRYPTION_KEY environment variable is required");
	}
	return deriveLegacySha256Key(key);
}

/**
 * Encrypts a plaintext value using AES-256-GCM with HKDF-derived key.
 * Returns format: v2:iv:authTag:encryptedData (all base64 encoded)
 *
 * The v2: prefix distinguishes HKDF-encrypted values from legacy SHA-256-
 * encrypted values (no prefix). The decrypt() function uses this prefix to
 * select the correct key derivation path.
 */
export function encrypt(plaintext: string): string {
	if (!plaintext) return "";

	const key = getEncryptionKey();
	const iv = crypto.randomBytes(IV_LENGTH);
	const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

	let encrypted = cipher.update(plaintext, "utf8", "base64");
	encrypted += cipher.final("base64");
	const authTag = cipher.getAuthTag();

	return `${V2_PREFIX}${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted}`;
}

/**
 * Decrypts a value encrypted with AES-256-GCM.
 *
 * Format detection:
 *   - 'v2:iv:authTag:data' → HKDF-derived key (current)
 *   - 'iv:authTag:data'    → SHA-256-derived key (legacy, backward compat)
 *
 * If the value doesn't match any encrypted format, returns it as-is for
 * backward compatibility with plain-text env vars.
 *
 * Throws on decryption failure to prevent ciphertext leaking to callers.
 *
 * Note: After a successful Option A migration, all rows carry the v2: prefix
 * and the legacy path becomes a read-only backward-compat path. It is NOT
 * removed — it must remain to support any deployment that has not run the
 * migration script.
 */
export function decrypt(encryptedValue: string): string {
	if (!encryptedValue) return "";

	// Detect v2 format: v2:iv:authTag:data
	if (encryptedValue.startsWith(V2_PREFIX)) {
		const inner = encryptedValue.slice(V2_PREFIX.length);
		const parts = inner.split(":");
		if (parts.length !== 3) {
			throw new Error("Invalid v2 ciphertext format: expected v2:iv:authTag:data");
		}
		const [ivBase64, authTagBase64, encryptedData] = parts;
		const key = getEncryptionKey();
		return aesGcmDecrypt(key, ivBase64, authTagBase64, encryptedData);
	}

	// Detect legacy format: iv:authTag:data (three colon-separated parts, no prefix)
	const parts = encryptedValue.split(":");
	if (parts.length !== 3) {
		// Not encrypted — return as-is (backward compatibility with plain-text values)
		return encryptedValue;
	}

	const [ivBase64, authTagBase64, encryptedData] = parts;
	const legacyKey = getLegacyEncryptionKey();
	return aesGcmDecrypt(legacyKey, ivBase64, authTagBase64, encryptedData);
}

/**
 * Internal AES-256-GCM decryption helper.
 * Supports both 12-byte (current) and 16-byte (legacy) IVs.
 */
function aesGcmDecrypt(
	key: Buffer,
	ivBase64: string,
	authTagBase64: string,
	encryptedData: string,
): string {
	const iv = Buffer.from(ivBase64, "base64");
	const authTag = Buffer.from(authTagBase64, "base64");

	const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
	decipher.setAuthTag(authTag);

	let decrypted = decipher.update(encryptedData, "base64", "utf8");
	decrypted += decipher.final("utf8");

	return decrypted;
}

/**
 * Checks whether a value appears to be in an encrypted format.
 * Detects both v2 (HKDF) and legacy (SHA-256) formats.
 */
export function isEncryptedFormat(value: string): boolean {
	if (value.startsWith(V2_PREFIX)) {
		// v2: prefix followed by three colon-separated parts
		const inner = value.slice(V2_PREFIX.length);
		return inner.split(":").length === 3;
	}
	// Legacy: exactly three colon-separated parts
	return value.split(":").length === 3;
}

/**
 * Exposed for use by the migration script only.
 * Returns the legacy SHA-256-derived key for a given raw key string.
 * Do NOT use this in application code — new encryptions must use HKDF.
 */
export function deriveLegacyKeyForMigration(rawKey: string): Buffer {
	return deriveLegacySha256Key(rawKey);
}

/**
 * Exposed for use by the migration script only.
 * Returns the HKDF-derived key for a given raw key string.
 */
export function deriveHkdfKeyForMigration(rawKey: string): Buffer {
	return deriveHkdfKey(rawKey);
}
