import crypto from "node:crypto";
import { SettingsCache } from "./cache";
import {
	ensureBruteForceTables,
	getDb,
	getLoginAttemptsTable,
	getLockoutsTable,
	getSecurityAuditTable,
} from "./db";
import { getSettingOrDefault } from "./settings";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BruteForceConfig {
	/** Number of failed attempts before triggering a lockout. Default: 5. */
	maxAttempts: number;
	/** Sliding window in seconds for counting attempts. Default: 600 (10 min). */
	windowSeconds: number;
	/** Lockout duration in seconds. Minimum enforced: 60. Default: 900 (15 min). */
	lockoutDurationSeconds: number;
}

export interface LockoutState {
	locked: boolean;
	lockedUntil?: Date;
}

export interface LockedAccount {
	id: number;
	identifier: string;
	identity_id: string | null;
	locked_at: Date | null;
	locked_until: Date | null;
	lock_reason: string | null;
	auto_threshold_at: number | null;
}

export interface LoginAttempt {
	id: number;
	identifier: string;
	ip_address: string | null;
	attempt_time: Date;
}

export interface AuditLogEvent {
	event_type: string;
	identifier?: string;
	identity_id?: string;
	admin_identity_id?: string;
	/** Keys are validated against AUDIT_METADATA_ALLOWLIST; values truncated to 500 chars. */
	metadata?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_WINDOW_SECONDS = 600;
const DEFAULT_LOCKOUT_DURATION_SECONDS = 900;
const MIN_LOCKOUT_DURATION_SECONDS = 60;

/** 5% probability of running inline cleanup on each recordFailedAttempt call. */
const CLEANUP_PROBABILITY = 0.05;

/**
 * Allowlist for metadata keys written to the security audit log.
 * Any key not in this list is silently dropped.
 */
const AUDIT_METADATA_ALLOWLIST = new Set<string>([
	"ip",
	"reason",
	"locked_until",
	"lock_reason",
]);

/** Maximum length for any single metadata string value. */
const AUDIT_METADATA_MAX_VALUE_LENGTH = 500;

// ---------------------------------------------------------------------------
// Config cache — reuses the same 60s TTL pattern as settingsCache
// ---------------------------------------------------------------------------

const bruteForceConfigCache = new SettingsCache(60);
const CONFIG_CACHE_KEY = "__brute_force_config__";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Normalize an identifier before any SQL operation.
 * MUST be applied to every caller-supplied identifier.
 */
function normalizeIdentifier(identifier: string): string {
	return identifier.toLowerCase().trim();
}

/**
 * Returns a SHA-256 hash of the normalized identifier for safe log output.
 * Prevents plaintext email addresses from appearing in logs.
 */
function hashIdentifier(normalizedIdentifier: string): string {
	return crypto
		.createHash("sha256")
		.update(normalizedIdentifier)
		.digest("hex")
		.slice(0, 16); // first 16 hex chars — enough for correlation, not reversible
}

// ---------------------------------------------------------------------------
// getBruteForceConfig
// ---------------------------------------------------------------------------

/**
 * Reads brute-force configuration from the settings table.
 * Results are cached for 60 seconds to avoid per-login DB hits.
 *
 * Settings keys (category: "security"):
 *   security.brute_force.max_attempts            (default: 5)
 *   security.brute_force.window_seconds          (default: 600)
 *   security.brute_force.lockout_duration_seconds (default: 900)
 *
 * Validation: if lockoutDurationSeconds < 60, the minimum (60) is enforced
 * and a warning is logged.
 */
export async function getBruteForceConfig(): Promise<BruteForceConfig> {
	const cached = bruteForceConfigCache.get(CONFIG_CACHE_KEY);
	if (cached !== undefined && cached !== null) {
		return JSON.parse(cached) as BruteForceConfig;
	}

	const [maxAttemptsStr, windowStr, lockoutStr] = await Promise.all([
		getSettingOrDefault(
			"security.brute_force.max_attempts",
			String(DEFAULT_MAX_ATTEMPTS),
		),
		getSettingOrDefault(
			"security.brute_force.window_seconds",
			String(DEFAULT_WINDOW_SECONDS),
		),
		getSettingOrDefault(
			"security.brute_force.lockout_duration_seconds",
			String(DEFAULT_LOCKOUT_DURATION_SECONDS),
		),
	]);

	const maxAttempts = Math.max(1, Number.parseInt(maxAttemptsStr, 10) || DEFAULT_MAX_ATTEMPTS);
	const windowSeconds = Math.max(1, Number.parseInt(windowStr, 10) || DEFAULT_WINDOW_SECONDS);
	let lockoutDurationSeconds = Number.parseInt(lockoutStr, 10) || DEFAULT_LOCKOUT_DURATION_SECONDS;

	if (lockoutDurationSeconds < MIN_LOCKOUT_DURATION_SECONDS) {
		console.warn(
			`[security][brute_force] lockout_duration_seconds value ${lockoutDurationSeconds} is below minimum ${MIN_LOCKOUT_DURATION_SECONDS}. Using default: ${DEFAULT_LOCKOUT_DURATION_SECONDS}`,
		);
		lockoutDurationSeconds = DEFAULT_LOCKOUT_DURATION_SECONDS;
	}

	const config: BruteForceConfig = { maxAttempts, windowSeconds, lockoutDurationSeconds };
	bruteForceConfigCache.set(CONFIG_CACHE_KEY, JSON.stringify(config));
	return config;
}

// ---------------------------------------------------------------------------
// checkLockout
// ---------------------------------------------------------------------------

/**
 * Checks whether the given identifier is currently locked out.
 *
 * FAIL-OPEN: if the database throws, logs at ERROR level (with hashed identifier,
 * never plaintext) and returns { locked: false } to allow the login to proceed.
 * A DB outage is already a P0 incident; blocking all logins compounds the failure.
 *
 * @param identifier - Email or username. Normalized to lowercase before SQL.
 */
export async function checkLockout(identifier: string): Promise<LockoutState> {
	const normalized = normalizeIdentifier(identifier);

	if (!normalized) {
		// empty/whitespace identifier — cannot create or look up a meaningful lockout
		return { locked: false };
	}

	try {
		await ensureBruteForceTables();
		const db = getDb();
		const table = getLockoutsTable();

		const rows = await db.unsafe(
			`SELECT locked_until
			 FROM ${table}
			 WHERE identifier = $1
			   AND locked_until > NOW()
			   AND unlocked_at IS NULL
			 ORDER BY locked_until DESC
			 LIMIT 1`,
			[normalized],
		);

		if (rows.length === 0) {
			return { locked: false };
		}

		return {
			locked: true,
			lockedUntil: new Date(rows[0].locked_until as string),
		};
	} catch (err) {
		console.error(
			`[security][brute_force][fail_open] checkLockout DB error for identifier_hash=${hashIdentifier(normalized)}:`,
			err instanceof Error ? err.message : String(err),
		);
		return { locked: false };
	}
}

// ---------------------------------------------------------------------------
// recordFailedAttempt
// ---------------------------------------------------------------------------

/**
 * Records a failed login attempt for the given identifier.
 *
 * After inserting the attempt row, counts all attempts within the configured
 * sliding window. If the count reaches maxAttempts, a lockout row is inserted.
 *
 * Inline probabilistic cleanup (5% probability): deletes attempt rows older than
 * 2× the window to keep the table bounded. This is mandatory — not a future task.
 *
 * FAIL-OPEN: if the database throws, logs at ERROR level (with hashed identifier)
 * and returns { shouldLockout: false, attemptCount: 0 }.
 *
 * @param identifier - Email or username. Normalized to lowercase before SQL.
 * @param ipAddress  - Should come from the `X-Real-IP` header set by the reverse
 *                     proxy (nginx / Caddy), NOT from raw `X-Forwarded-For` which
 *                     can be spoofed by the client. Fall back to the direct
 *                     connection IP only when no trusted proxy header is present.
 */
export async function recordFailedAttempt(
	identifier: string,
	ipAddress?: string | null,
): Promise<{ shouldLockout: boolean; attemptCount: number }> {
	const normalized = normalizeIdentifier(identifier);

	if (!normalized) {
		// empty/whitespace identifier — cannot create or look up a meaningful lockout
		return { shouldLockout: false, attemptCount: 0 };
	}

	try {
		await ensureBruteForceTables();
		const db = getDb();
		const attemptsTable = getLoginAttemptsTable();
		const config = await getBruteForceConfig();

		// Insert the failed attempt
		await db.unsafe(
			`INSERT INTO ${attemptsTable} (identifier, ip_address) VALUES ($1, $2)`,
			[normalized, ipAddress ?? null],
		);

		// Count attempts within the sliding window
		const countRows = await db.unsafe(
			`SELECT COUNT(*)::int AS cnt
			 FROM ${attemptsTable}
			 WHERE identifier = $1
			   AND attempt_time > NOW() - INTERVAL '1 second' * $2`,
			[normalized, config.windowSeconds],
		);

		const attemptCount = (countRows[0]?.cnt as number) ?? 0;
		const shouldLockout = attemptCount >= config.maxAttempts;

		// Inline probabilistic cleanup: 5% of calls clean up old records
		if (Math.random() < CLEANUP_PROBABILITY) {
			const cutoffSeconds = 2 * config.windowSeconds;
			db.unsafe(
				`DELETE FROM ${attemptsTable}
				 WHERE attempt_time < NOW() - INTERVAL '1 second' * $1`,
				[cutoffSeconds],
			).catch((err: unknown) => {
				console.warn(
					"[security][brute_force] inline cleanup failed:",
					err instanceof Error ? err.message : String(err),
				);
			});
		}

		// If threshold reached, insert a lockout row
		if (shouldLockout) {
			const lockoutsTable = getLockoutsTable();
			await db.unsafe(
				`INSERT INTO ${lockoutsTable}
				   (identifier, locked_until, lock_reason, auto_threshold_at)
				 VALUES ($1, NOW() + INTERVAL '1 second' * $2, 'brute_force', $3)`,
				[normalized, config.lockoutDurationSeconds, attemptCount],
			);

			// Append audit log for lockout creation (fire-and-forget)
			appendAuditLog({
				event_type: "lockout_created",
				identifier: normalized,
				metadata: {
					reason: "auto_threshold",
					ip: ipAddress ?? "",
					lock_reason: "brute_force",
				},
			}).catch((err: unknown) => {
				console.warn(
					"[security][brute_force] appendAuditLog(lockout_created) failed:",
					err instanceof Error ? err.message : String(err),
				);
			});
		}

		return { shouldLockout, attemptCount };
	} catch (err) {
		console.error(
			`[security][brute_force][fail_open] recordFailedAttempt DB error for identifier_hash=${hashIdentifier(normalized)}:`,
			err instanceof Error ? err.message : String(err),
		);
		return { shouldLockout: false, attemptCount: 0 };
	}
}

// ---------------------------------------------------------------------------
// clearAttempts
// ---------------------------------------------------------------------------

/**
 * Deletes all failed attempt records for the given identifier.
 * Called on successful login. Errors are logged at WARN and not re-thrown
 * (fire-and-forget — a cleanup failure must not block a successful login).
 *
 * @param identifier - Email or username. Normalized to lowercase before SQL.
 */
export async function clearAttempts(identifier: string): Promise<void> {
	const normalized = normalizeIdentifier(identifier);

	if (!normalized) {
		// empty/whitespace identifier — cannot create or look up a meaningful lockout
		return;
	}

	try {
		await ensureBruteForceTables();
		const db = getDb();
		const table = getLoginAttemptsTable();

		await db.unsafe(
			`DELETE FROM ${table} WHERE identifier = $1`,
			[normalized],
		);
	} catch (err) {
		console.warn(
			`[security][brute_force] clearAttempts failed for identifier_hash=${hashIdentifier(normalized)}:`,
			err instanceof Error ? err.message : String(err),
		);
	}
}

// ---------------------------------------------------------------------------
// listLockedAccounts
// ---------------------------------------------------------------------------

/**
 * Returns all accounts that are currently locked (not expired, not manually unlocked).
 * Used by the Athena admin UI to display the locked accounts list.
 */
export async function listLockedAccounts(): Promise<LockedAccount[]> {
	await ensureBruteForceTables();
	const db = getDb();
	const table = getLockoutsTable();

	const rows = await db.unsafe(
		`SELECT id, identifier, identity_id, locked_at, locked_until, lock_reason, auto_threshold_at
		 FROM ${table}
		 WHERE locked_until > NOW()
		   AND unlocked_at IS NULL
		 ORDER BY locked_until DESC`,
	);

	return rows as unknown as LockedAccount[];
}

// ---------------------------------------------------------------------------
// unlockAccount
// ---------------------------------------------------------------------------

/**
 * Manually unlocks an account by setting `unlocked_at` on the active lockout row.
 *
 * Returns true if an active lockout was found and unlocked.
 * Returns false for all not-found cases (no distinction between "no lockout" and
 * "wrong identifier" to prevent enumeration attacks).
 *
 * Also appends an entry to the security audit log.
 *
 * @param identifier      - Email or username. Normalized to lowercase before SQL.
 * @param adminIdentityId - Kratos identity UUID of the admin performing the unlock.
 */
export async function unlockAccount(
	identifier: string,
	adminIdentityId: string,
): Promise<boolean> {
	const normalized = normalizeIdentifier(identifier);

	if (!normalized) {
		// empty/whitespace identifier — cannot create or look up a meaningful lockout
		return false;
	}

	await ensureBruteForceTables();
	const db = getDb();
	const table = getLockoutsTable();

	// Fetch the active lockout first so we can capture metadata for the audit log.
	// The AND locked_until > NOW() guard ensures we only unlock accounts that are
	// actively locked — not ones whose lockout has already expired naturally.
	const existing = await db.unsafe(
		`SELECT id, identity_id, locked_until, lock_reason
		 FROM ${table}
		 WHERE identifier = $1
		   AND unlocked_at IS NULL
		   AND locked_until > NOW()
		 ORDER BY locked_at DESC
		 LIMIT 1`,
		[normalized],
	);

	if (existing.length === 0) {
		return false;
	}

	const lockout = existing[0];

	const result = await db.unsafe(
		`UPDATE ${table}
		 SET unlocked_at          = NOW(),
		     unlock_reason        = 'admin_manual',
		     unlocked_by_admin_id = $1
		 WHERE identifier = $2
		   AND unlocked_at IS NULL`,
		[adminIdentityId, normalized],
	);

	if (result.count === 0) {
		return false;
	}

	// Append audit log — fire-and-forget; unlock must not fail if audit write fails
	appendAuditLog({
		event_type: "account_unlocked",
		identifier: normalized,
		identity_id: lockout.identity_id as string | undefined,
		admin_identity_id: adminIdentityId,
		metadata: {
			locked_until: lockout.locked_until
				? new Date(lockout.locked_until as string).toISOString()
				: "",
			lock_reason: String(lockout.lock_reason ?? ""),
			reason: "admin_manual",
		},
	}).catch((err: unknown) => {
		console.warn(
			"[security][brute_force] appendAuditLog(account_unlocked) failed:",
			err instanceof Error ? err.message : String(err),
		);
	});

	return true;
}

// ---------------------------------------------------------------------------
// appendAuditLog
// ---------------------------------------------------------------------------

/**
 * Appends a row to the security audit log table.
 *
 * Metadata keys are validated against an allowlist:
 *   'ip', 'reason', 'locked_until', 'lock_reason'
 * Keys not in the allowlist are silently dropped.
 * String values are truncated to 500 characters.
 *
 * @param event - The audit event to record.
 */
export async function appendAuditLog(event: AuditLogEvent): Promise<void> {
	await ensureBruteForceTables();
	const db = getDb();
	const table = getSecurityAuditTable();

	// Sanitize metadata: allowlist keys, truncate values
	let sanitizedMetadata: Record<string, string> | null = null;
	if (event.metadata) {
		const filtered: Record<string, string> = {};
		for (const [key, value] of Object.entries(event.metadata)) {
			if (AUDIT_METADATA_ALLOWLIST.has(key)) {
				filtered[key] = String(value).slice(0, AUDIT_METADATA_MAX_VALUE_LENGTH);
			}
		}
		if (Object.keys(filtered).length > 0) {
			sanitizedMetadata = filtered;
		}
	}

	await db.unsafe(
		`INSERT INTO ${table}
		   (event_type, identifier, identity_id, admin_identity_id, metadata)
		 VALUES ($1, $2, $3, $4, $5)`,
		[
			event.event_type,
			event.identifier ?? null,
			event.identity_id ?? null,
			event.admin_identity_id ?? null,
			sanitizedMetadata ? JSON.stringify(sanitizedMetadata) : null,
		],
	);
}
