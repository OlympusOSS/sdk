import postgres from "postgres";

let sql: ReturnType<typeof postgres> | null = null;
let migrated = false;

/**
 * Returns a shared postgres.js connection pool.
 * Reads DATABASE_URL from the environment on first call.
 *
 * All containers point to the `olympus` database;
 * `SETTINGS_TABLE` determines which domain table to query.
 */
export function getDb() {
	if (!sql) {
		const url = process.env.DATABASE_URL;
		if (!url) {
			throw new Error("DATABASE_URL environment variable is required");
		}
		sql = postgres(url, {
			max: 5,
			idle_timeout: 30,
			connect_timeout: 10,
		});
	}
	return sql;
}

/**
 * Returns the domain-scoped settings table name.
 * Reads SETTINGS_TABLE from the environment (e.g. "ciam_settings" or "iam_settings").
 */
export function getSettingsTable(): string {
	const table = process.env.SETTINGS_TABLE;
	if (!table) {
		throw new Error("SETTINGS_TABLE environment variable is required");
	}
	// Validate table name to prevent SQL injection
	if (!/^[a-z_]+$/.test(table)) {
		throw new Error(`Invalid SETTINGS_TABLE value: ${table}`);
	}
	return table;
}

/**
 * Auto-creates the settings table if it doesn't exist.
 * Runs once per process lifetime, idempotent via CREATE TABLE IF NOT EXISTS.
 */
export async function ensureTable(): Promise<void> {
	if (migrated) return;

	const db = getDb();
	const table = getSettingsTable();

	await db.unsafe(`
		CREATE TABLE IF NOT EXISTS ${table} (
			key        TEXT PRIMARY KEY,
			value      TEXT NOT NULL,
			encrypted  BOOLEAN NOT NULL DEFAULT FALSE,
			category   TEXT NOT NULL DEFAULT 'general',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`);

	migrated = true;
}

/**
 * Gracefully close the connection pool (for clean shutdown).
 */
export async function closeDb() {
	if (sql) {
		await sql.end();
		sql = null;
		migrated = false;
	}
}
