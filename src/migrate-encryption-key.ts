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
 *   DATABASE_URL=... ENCRYPTION_KEY=... bun run src/migrate-encryption-key.ts [--dry-run]
 *
 * Flags:
 *   --dry-run   Scan and validate all rows without writing. Prints counts and per-row
 *               status. Use to verify the migration is safe before running in production.
 *               Required review step: include dry-run output in the PR description and
 *               have it reviewed by the CIAM Architect before running production migration.
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
	const isDryRun = process.argv.includes("--dry-run");

	if (!databaseUrl) {
		console.error("[migrate] DATABASE_URL is required");
		process.exit(1);
	}
	if (!encryptionKey) {
		console.error("[migrate] ENCRYPTION_KEY is required");
		process.exit(1);
	}

	if (isDryRun) {
		console.log("[migrate] DRY RUN mode — no rows will be written");
	}

	// Derive both keys upfront
	const legacyKey = deriveLegacyKeyForMigration(encryptionKey);
	const hkdfKey = deriveHkdfKeyForMigration(encryptionKey);

	// Suppress TS unused-variable warning for hkdfKey in dry-run paths
	void hkdfKey;

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
			if (isDryRun) {
				const legacyCount = rows.filter((r) => !r.value.startsWith(V2_PREFIX)).length;
				const v2Count = rows.filter((r) => r.value.startsWith(V2_PREFIX)).length;
				console.log(`[migrate]   Legacy (needs migration): ${legacyCount}`);
				console.log(`[migrate]   Already v2 (skip):        ${v2Count}`);
			}

			for (const row of rows) {
				totalProcessed++;

				// Skip already-migrated rows (v2: prefix present)
				if (row.value.startsWith(V2_PREFIX)) {
					totalSkipped++;
					if (isDryRun) {
						console.log(`[migrate]   DRY SKIP key=${row.key} (already v2, value_length=${row.value.length})`);
					} else {
						console.log(`[migrate]   SKIP key=${row.key} (already v2)`);
					}
					continue;
				}

				// Validate: attempt legacy decrypt to confirm the row is decryptable
				let plaintext: string;
				try {
					plaintext = legacyDecrypt(row.value, legacyKey);
				} catch (err) {
					totalFailed++;
					// Log only the error message — never log the ciphertext or decrypted value
					console.error(`[migrate]   FAIL key=${row.key} — legacy decrypt failed:`, err instanceof Error ? err.message : String(err));
					continue;
				}

				if (isDryRun) {
					// Dry-run: report decryptable row by key name and plaintext length only
					// (never log plaintext value itself)
					totalMigrated++;
					console.log(`[migrate]   DRY OK key=${row.key} (decryptable, plaintext_length=${plaintext.length})`);
					continue;
				}

				// Re-encrypt with HKDF-derived key inside a per-row transaction
				// If the write fails, the row is left in its original state (idempotent).
				try {
					const newCiphertext = hkdfEncrypt(plaintext, hkdfKey);
					await sql.begin(async (tx) => {
						await tx.unsafe(
							`UPDATE ${table} SET value = $1, updated_at = NOW() WHERE key = $2`,
							[newCiphertext, row.key],
						);
					});
					totalMigrated++;
					console.log(`[migrate]   OK key=${row.key}`);
				} catch (err) {
					totalFailed++;
					// Log only key name and error message — never log the plaintext or ciphertext
					console.error(`[migrate]   FAIL key=${row.key} — write failed:`, err instanceof Error ? err.message : String(err));
				}
			}
		}
	} finally {
		await sql.end();
	}

	if (isDryRun) {
		console.log("\n[migrate] DRY RUN Summary:");
		console.log(`  Processed       : ${totalProcessed}`);
		console.log(`  Decryptable     : ${totalMigrated} (would migrate)`);
		console.log(`  Already v2      : ${totalSkipped} (would skip)`);
		console.log(`  Failed decrypt  : ${totalFailed} (would fail)`);
		console.log("\n[migrate] DRY RUN complete. No rows were written.");
		if (totalFailed > 0) {
			process.exit(1);
		}
	} else {
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
}

migrate().catch((err) => {
	console.error("[migrate] Unhandled error:", err);
	process.exit(1);
});
