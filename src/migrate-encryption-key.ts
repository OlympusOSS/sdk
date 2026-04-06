/**
 * Migration script: re-encrypt all encrypted settings from SHA-256-derived key to HKDF-derived key.
 *
 * This script is required when upgrading from SDK < 1.0.41 (bare SHA-256 key derivation)
 * to SDK >= 1.0.41 (HKDF key derivation). Existing encrypted settings were stored with a
 * SHA-256-derived AES key. After the SDK upgrade, the runtime decrypt() function uses the
 * HKDF-derived key and can no longer decrypt legacy ciphertext.
 *
 * This script bridges the gap by:
 *   1. Reading all encrypted rows from ciam_settings and iam_settings
 *   2. Skipping rows already carrying the v2: prefix (already migrated)
 *   3. Decrypting legacy rows using the OLD SHA-256-derived key (direct, not via SDK decrypt())
 *   4. Re-encrypting with the NEW HKDF-derived key, writing v2:-prefixed ciphertext
 *
 * IMPORTANT: This script does NOT call the runtime SDK encrypt() or decrypt() functions.
 * The runtime decrypt() function errors on pre-v2 ciphertext after the SDK upgrade.
 * This script uses direct key derivation to avoid that contradiction.
 *
 * Idempotency: rows already carrying v2: prefix are skipped. Safe to re-run.
 *
 * Usage:
 *   DATABASE_URL=... ENCRYPTION_KEY=... bun run src/migrate-encryption-key.ts
 *
 * Run BEFORE upgrading the SDK in production containers. If run after upgrade, the
 * runtime decrypt() will fail on legacy rows until this script completes.
 *
 * Migration path choice: Option A (this script) was chosen and approved by CIAM Architect.
 * See sdk#5 for the full migration plan and approval record.
 */

import crypto from "node:crypto";
import postgres from "postgres";
import { deriveLegacyKeyForMigration, deriveHkdfKeyForMigration } from "./crypto";

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;
const V2_PREFIX = "v2:";

const TABLES = ["ciam_settings", "iam_settings"] as const;

interface EncryptedRow {
	key: string;
	value: string;
}

/**
 * Decrypt a legacy (no v2: prefix) ciphertext using the SHA-256-derived key.
 * Supports both 12-byte and 16-byte IVs for full backward compatibility.
 */
function legacyDecrypt(ciphertext: string, legacyKey: Buffer): string {
	const parts = ciphertext.split(":");
	if (parts.length !== 3) {
		throw new Error(`Not a valid legacy ciphertext format: ${ciphertext.slice(0, 20)}...`);
	}

	const [ivBase64, authTagBase64, encryptedData] = parts;
	const iv = Buffer.from(ivBase64, "base64");
	const authTag = Buffer.from(authTagBase64, "base64");

	const decipher = crypto.createDecipheriv(ALGORITHM, legacyKey, iv);
	decipher.setAuthTag(authTag);

	let decrypted = decipher.update(encryptedData, "base64", "utf8");
	decrypted += decipher.final("utf8");

	return decrypted;
}

/**
 * Encrypt a plaintext value using the HKDF-derived key.
 * Produces v2:-prefixed ciphertext.
 */
function hkdfEncrypt(plaintext: string, hkdfKey: Buffer): string {
	const iv = crypto.randomBytes(IV_LENGTH);
	const cipher = crypto.createCipheriv(ALGORITHM, hkdfKey, iv);

	let encrypted = cipher.update(plaintext, "utf8", "base64");
	encrypted += cipher.final("base64");
	const authTag = cipher.getAuthTag();

	return `${V2_PREFIX}${iv.toString("base64")}:${authTag.toString("base64")}:${encrypted}`;
}

async function migrate(): Promise<void> {
	const databaseUrl = process.env.DATABASE_URL;
	const encryptionKey = process.env.ENCRYPTION_KEY;

	if (!databaseUrl) {
		console.error("[migrate] DATABASE_URL is required");
		process.exit(1);
	}
	if (!encryptionKey) {
		console.error("[migrate] ENCRYPTION_KEY is required");
		process.exit(1);
	}

	// Derive both keys upfront
	const legacyKey = deriveLegacyKeyForMigration(encryptionKey);
	const hkdfKey = deriveHkdfKeyForMigration(encryptionKey);

	console.log("[migrate] Keys derived. Starting migration...");

	const sql = postgres(databaseUrl, { max: 2 });

	let totalProcessed = 0;
	let totalSkipped = 0;
	let totalMigrated = 0;
	let totalFailed = 0;

	try {
		for (const table of TABLES) {
			console.log(`[migrate] Processing table: ${table}`);

			// Check if table exists before querying
			const tableExists = await sql`
				SELECT EXISTS (
					SELECT FROM information_schema.tables
					WHERE table_name = ${table}
				) AS exists
			`;
			if (!tableExists[0]?.exists) {
				console.log(`[migrate]   Table ${table} does not exist — skipping`);
				continue;
			}

			const rows = await sql.unsafe<EncryptedRow[]>(
				`SELECT key, value FROM ${table} WHERE encrypted = true`,
			);

			console.log(`[migrate]   Found ${rows.length} encrypted rows`);

			for (const row of rows) {
				totalProcessed++;

				// Skip already-migrated rows (v2: prefix present)
				if (row.value.startsWith(V2_PREFIX)) {
					totalSkipped++;
					console.log(`[migrate]   SKIP key=${row.key} (already v2)`);
					continue;
				}

				// Decrypt legacy ciphertext using SHA-256-derived key
				let plaintext: string;
				try {
					plaintext = legacyDecrypt(row.value, legacyKey);
				} catch (err) {
					totalFailed++;
					console.error(`[migrate]   FAIL key=${row.key} — legacy decrypt failed:`, err instanceof Error ? err.message : String(err));
					continue;
				}

				// Re-encrypt with HKDF-derived key
				const newCiphertext = hkdfEncrypt(plaintext, hkdfKey);

				// Write back
				try {
					await sql.unsafe(
						`UPDATE ${table} SET value = $1, updated_at = NOW() WHERE key = $2`,
						[newCiphertext, row.key],
					);
					totalMigrated++;
					console.log(`[migrate]   OK key=${row.key}`);
				} catch (err) {
					totalFailed++;
					console.error(`[migrate]   FAIL key=${row.key} — write failed:`, err instanceof Error ? err.message : String(err));
				}
			}
		}
	} finally {
		await sql.end();
	}

	console.log("\n[migrate] Summary:");
	console.log(`  Processed : ${totalProcessed}`);
	console.log(`  Migrated  : ${totalMigrated}`);
	console.log(`  Skipped   : ${totalSkipped} (already v2)`);
	console.log(`  Failed    : ${totalFailed}`);

	if (totalFailed > 0) {
		console.error("[migrate] Migration completed with failures. Re-run to retry failed rows.");
		process.exit(1);
	} else {
		console.log("[migrate] Migration complete. All encrypted rows are now using HKDF-derived key.");
	}
}

migrate().catch((err) => {
	console.error("[migrate] Unhandled error:", err);
	process.exit(1);
});
