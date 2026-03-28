import postgres from "postgres";

let sql: ReturnType<typeof postgres> | null = null;
let migrated = false;
let locationsMigrated = false;

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
 * Returns the domain-scoped session locations table name.
 * Derived from SETTINGS_TABLE: "ciam_settings" → "ciam_session_locations".
 */
export function getLocationsTable(): string {
	const settingsTable = getSettingsTable();
	// Replace "_settings" suffix with "_session_locations"
	return settingsTable.replace(/_settings$/, "_session_locations");
}

/**
 * Auto-creates the session locations table if it doesn't exist.
 * Runs once per process lifetime, idempotent via CREATE TABLE IF NOT EXISTS.
 */
export async function ensureLocationsTable(): Promise<void> {
	if (locationsMigrated) return;

	const db = getDb();
	const table = getLocationsTable();

	await db.unsafe(`
		CREATE TABLE IF NOT EXISTS ${table} (
			id          SERIAL PRIMARY KEY,
			session_id  TEXT NOT NULL,
			identity_id TEXT NOT NULL,
			ip_address  TEXT,
			lat         DOUBLE PRECISION,
			lng         DOUBLE PRECISION,
			city        TEXT,
			country     TEXT,
			source      TEXT NOT NULL DEFAULT 'ip',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`);

	// Index for efficient querying by source and date
	await db.unsafe(`
		CREATE INDEX IF NOT EXISTS idx_${table}_source_created
		ON ${table} (source, created_at DESC)
	`);

	// Index for efficient retention cleanup (DELETE WHERE created_at < ?)
	await db.unsafe(`
		CREATE INDEX IF NOT EXISTS idx_${table}_created_at
		ON ${table} (created_at)
	`);

	locationsMigrated = true;
}

/**
 * Gracefully close the connection pool (for clean shutdown).
 */
export async function closeDb() {
	if (sql) {
		await sql.end();
		sql = null;
		migrated = false;
		locationsMigrated = false;
	}
}
