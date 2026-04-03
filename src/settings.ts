import { settingsCache } from "./cache";
import { decrypt, encrypt } from "./crypto";
import { ensureTable, getDb, getSettingsTable } from "./db";

export interface Setting {
	key: string;
	value: string;
	encrypted: boolean;
	category: string;
	updated_at: Date;
}

export interface SetSettingOptions {
	encrypted?: boolean;
	category?: string;
}

/**
 * Get a single setting value by key. Returns null if not found.
 * Does NOT decrypt encrypted values — use `getSecretSetting` for that.
 */
export async function getSetting(key: string): Promise<string | null> {
	// Check cache first
	const cached = settingsCache.get(key);
	if (cached !== undefined) return cached;

	await ensureTable();
	const sql = getDb();
	const table = getSettingsTable();
	const rows = await sql.unsafe(
		`SELECT value FROM ${table} WHERE key = $1`,
		[key],
	);

	const value = rows.length > 0 ? (rows[0].value as string) : null;
	settingsCache.set(key, value);
	return value;
}

/**
 * Get a setting value, returning a default if not found.
 */
export async function getSettingOrDefault(
	key: string,
	fallback: string,
): Promise<string> {
	const value = await getSetting(key);
	return value ?? fallback;
}

/**
 * Get a secret setting — automatically decrypts if stored encrypted.
 */
export async function getSecretSetting(key: string): Promise<string | null> {
	await ensureTable();
	const sql = getDb();
	const table = getSettingsTable();
	const rows = await sql.unsafe(
		`SELECT value, encrypted FROM ${table} WHERE key = $1`,
		[key],
	);

	if (rows.length === 0) return null;

	const row = rows[0];
	if (row.encrypted) {
		try {
			return decrypt(row.value as string);
		} catch (error) {
			console.error(`Failed to decrypt setting "${key}":`, error);
			return null;
		}
	}
	return row.value as string;
}

/**
 * Upsert a setting. If `opts.encrypted` is true, the value is encrypted before storing.
 */
export async function setSetting(
	key: string,
	value: string,
	opts?: SetSettingOptions,
): Promise<void> {
	await ensureTable();
	const sql = getDb();
	const table = getSettingsTable();
	const isEncrypted = opts?.encrypted ?? false;
	const category = opts?.category ?? "general";

	const storedValue = isEncrypted ? encrypt(value) : value;

	await sql.unsafe(
		`INSERT INTO ${table} (key, value, encrypted, category, updated_at)
		 VALUES ($1, $2, $3, $4, NOW())
		 ON CONFLICT (key) DO UPDATE SET
		   value = EXCLUDED.value,
		   encrypted = EXCLUDED.encrypted,
		   category = EXCLUDED.category,
		   updated_at = NOW()`,
		[key, storedValue, isEncrypted, category],
	);

	// Invalidate cache for this key
	settingsCache.invalidate(key);
}

/**
 * Delete a setting by key.
 */
export async function deleteSetting(key: string): Promise<void> {
	await ensureTable();
	const sql = getDb();
	const table = getSettingsTable();

	await sql.unsafe(`DELETE FROM ${table} WHERE key = $1`, [key]);

	settingsCache.invalidate(key);
}

/**
 * List all settings, optionally filtered by category.
 * Encrypted values are returned as-is (ciphertext).
 */
export async function listSettings(category?: string): Promise<Setting[]> {
	await ensureTable();
	const sql = getDb();
	const table = getSettingsTable();

	let rows: Setting[];
	if (category) {
		rows = await sql.unsafe(
			`SELECT key, value, encrypted, category, updated_at FROM ${table} WHERE category = $1 ORDER BY category, key`,
			[category],
		) as unknown as Setting[];
	} else {
		rows = await sql.unsafe(
			`SELECT key, value, encrypted, category, updated_at FROM ${table} ORDER BY category, key`,
		) as unknown as Setting[];
	}

	return rows;
}

/**
 * List settings for display in the admin UI.
 * Encrypted values are masked (only first 8 chars of ciphertext shown).
 */
export async function listSettingsForDisplay(
	category?: string,
): Promise<Setting[]> {
	const settings = await listSettings(category);

	return settings.map((s) => ({
		...s,
		value: s.encrypted ? `${s.value.slice(0, 8)}${"•".repeat(8)}` : s.value,
	}));
}

export interface BatchSettingEntry {
	key: string;
	value: string;
	encrypted?: boolean;
	category?: string;
}

/**
 * Atomically write multiple settings in a single Postgres transaction.
 * Either all writes commit or none do.
 *
 * Reuses the same upsert logic as setSetting() for each entry.
 * Cache entries for all written keys are invalidated after a successful commit.
 *
 * **Concurrent write behavior**: This transaction runs under READ COMMITTED isolation.
 * Concurrent calls to batchSetSettings() targeting overlapping keys will interleave
 * at the row level — PostgreSQL's ON CONFLICT upsert serializes individual row writes,
 * but there is no cross-call ordering guarantee across concurrent transactions. Callers
 * requiring strict last-write-wins ordering across concurrent batch operations must
 * coordinate at the application layer (e.g., serialized queue or distributed lock).
 *
 * **Empty-value encryption behavior**: Entries with `encrypted: true` and `value: ""`
 * will store an empty string — crypto.ts `encrypt()` returns `""` for empty input without
 * performing encryption. Callers must ensure that any entry marked encrypted has a
 * non-empty value before calling this function.
 *
 * **Post-commit staleness window**: After a successful commit, cache entries for the
 * written keys are invalidated immediately. However, other SDK consumers in separate
 * processes share no in-memory cache, so they may serve stale values for up to the TTL
 * window (default 60s). Security-sensitive settings (e.g., `mfa.enabled` set to `false`)
 * may continue to be read as their prior value from cache for up to 60s after a successful
 * batch commit. Design callers of security-critical settings accordingly.
 *
 * **Max batch size**: No upper bound is enforced in this function. If any caller can
 * produce a batch exceeding 20 entries, an upper bound guard should be added at the
 * call site. This is tracked as a confirmation gate in athena#48.
 *
 * @param entries - Array of settings to write atomically.
 * @param table - The settings table to write to (`ciam_settings` or `iam_settings`).
 *   Must match lowercase letters and underscores only (SQL injection guard).
 *   // @future: consider domain-scoped wrapper if widely consumed
 */
export async function batchSetSettings(
	entries: BatchSettingEntry[],
	table: string,
): Promise<void> {
	if (entries.length === 0) return;

	// Validate table name to prevent SQL injection (same pattern as getSettingsTable)
	if (!/^[a-z_]+$/.test(table)) {
		throw new Error(`Invalid table name: ${table}`);
	}

	await ensureTable();
	const sql = getDb();

	try {
		await sql.begin(async (tx) => {
			for (const entry of entries) {
				const isEncrypted = entry.encrypted ?? false;
				const category = entry.category ?? "general";
				const storedValue = isEncrypted ? encrypt(entry.value) : entry.value;

				await tx.unsafe(
					`INSERT INTO ${table} (key, value, encrypted, category, updated_at)
					 VALUES ($1, $2, $3, $4, NOW())
					 ON CONFLICT (key) DO UPDATE SET
					   value = EXCLUDED.value,
					   encrypted = EXCLUDED.encrypted,
					   category = EXCLUDED.category,
					   updated_at = NOW()`,
					[entry.key, storedValue, isEncrypted, category],
				);
			}
		});
	} catch (error) {
		throw new Error(
			`batchSetSettings failed — transaction rolled back: ${error instanceof Error ? error.message : String(error)}`,
		);
	}

	// Invalidate cache for all written keys after successful commit
	for (const entry of entries) {
		settingsCache.invalidate(entry.key);
	}
}
