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
		return decrypt(row.value as string);
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
