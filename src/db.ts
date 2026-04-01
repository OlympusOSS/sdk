import postgres from "postgres";

let sql: ReturnType<typeof postgres> | null = null;
let migrated = false;
let locationsMigrated = false;
let bruteForceTablesMigrated = false;

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
 * Returns the domain-scoped login attempts table name.
 * Derived from SETTINGS_TABLE: "ciam_settings" → "ciam_login_attempts".
 */
export function getLoginAttemptsTable(): string {
	const settingsTable = getSettingsTable();
	return settingsTable.replace(/_settings$/, "_login_attempts");
}

/**
 * Returns the domain-scoped lockouts table name.
 * Derived from SETTINGS_TABLE: "ciam_settings" → "ciam_lockouts".
 */
export function getLockoutsTable(): string {
	const settingsTable = getSettingsTable();
	return settingsTable.replace(/_settings$/, "_lockouts");
}

/**
 * Returns the domain-scoped security audit log table name.
 * Derived from SETTINGS_TABLE: "ciam_settings" → "ciam_security_audit_log".
 */
export function getSecurityAuditTable(): string {
	const settingsTable = getSettingsTable();
	return settingsTable.replace(/_settings$/, "_security_audit_log");
}

/**
 * Auto-creates the three brute-force protection tables if they don't exist.
 * Runs once per process lifetime, idempotent via CREATE TABLE IF NOT EXISTS.
 *
 * Tables created:
 *   - {prefix}_login_attempts  — one row per failed attempt (sliding window)
 *   - {prefix}_lockouts        — explicit lockout state (append-only on unlock)
 *   - {prefix}_security_audit_log — append-only admin action audit log
 */
export async function ensureBruteForceTables(): Promise<void> {
	if (bruteForceTablesMigrated) return;

	const db = getDb();
	const attemptsTable = getLoginAttemptsTable();
	const lockoutsTable = getLockoutsTable();
	const auditTable = getSecurityAuditTable();

	// login_attempts: append-only per-identifier failed login records
	await db.unsafe(`
		CREATE TABLE IF NOT EXISTS ${attemptsTable} (
			id           BIGSERIAL PRIMARY KEY,
			identifier   TEXT NOT NULL,
			ip_address   INET,
			attempt_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`);

	await db.unsafe(`
		CREATE INDEX IF NOT EXISTS idx_${attemptsTable}_identifier_time
		ON ${attemptsTable} (identifier, attempt_time DESC)
	`);

	await db.unsafe(`
		CREATE INDEX IF NOT EXISTS idx_${attemptsTable}_attempt_time
		ON ${attemptsTable} (attempt_time)
	`);

	// lockouts: explicit lockout state; rows kept on unlock for audit history
	await db.unsafe(`
		CREATE TABLE IF NOT EXISTS ${lockoutsTable} (
			id                   BIGSERIAL PRIMARY KEY,
			identifier           TEXT NOT NULL,
			identity_id          TEXT,
			locked_at            TIMESTAMPTZ DEFAULT NOW(),
			locked_until         TIMESTAMPTZ,
			unlocked_at          TIMESTAMPTZ,
			unlock_reason        TEXT,
			unlocked_by_admin_id TEXT,
			lock_reason          TEXT DEFAULT 'brute_force',
			auto_threshold_at    SMALLINT
		)
	`);

	await db.unsafe(`
		CREATE INDEX IF NOT EXISTS idx_${lockoutsTable}_identifier_locked_until
		ON ${lockoutsTable} (identifier, locked_until DESC)
	`);

	// security_audit_log: append-only log of security-relevant admin actions
	await db.unsafe(`
		CREATE TABLE IF NOT EXISTS ${auditTable} (
			id                BIGSERIAL PRIMARY KEY,
			event_type        TEXT NOT NULL,
			identifier        TEXT,
			identity_id       TEXT,
			admin_identity_id TEXT,
			metadata          JSONB,
			created_at        TIMESTAMPTZ DEFAULT NOW()
		)
	`);

	await db.unsafe(`
		CREATE INDEX IF NOT EXISTS idx_${auditTable}_identifier_created
		ON ${auditTable} (identifier, created_at DESC)
	`);

	bruteForceTablesMigrated = true;
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
		bruteForceTablesMigrated = false;
	}
}
