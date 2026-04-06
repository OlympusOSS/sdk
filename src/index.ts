// Module-load validation: ENCRYPTION_KEY entropy checks run at import time.
// Any consumer that imports the SDK via this barrel gets the validation automatically.
// Containers (ciam-hera, iam-hera, ciam-athena, iam-athena) import this module on startup —
// failures surface in container logs immediately, before any request is served.
//
// Scope limitation: if sdk/src/crypto.ts is imported DIRECTLY (bypassing this barrel),
// the entropy check below does NOT fire. All current Olympus consumers import via the barrel.
// Future SDK consumers that import crypto.ts directly must implement their own validation
// or use the SDK barrel. This limitation is documented in the README.
//
// Validation:
//   1. Presence check: ENCRYPTION_KEY must be set (all environments)
//   2. Byte-length check: raw length must be >= 32 bytes (all environments)
//   3. Blocklist check: key must not match a known dev/example default (production only)
//
// The byte-length check is a necessary condition, not sufficient — it prevents accidentally
// short keys but cannot detect zero-randomness keys (e.g., 32 identical characters) unless
// they appear on the blocklist. See README for key generation guidance.
import { ENCRYPTION_KEY_BLOCKLIST } from "./blocklist";

(function validateEncryptionKey(): void {
	const key = process.env.ENCRYPTION_KEY;

	// 1. Presence check
	if (!key) {
		throw new Error(
			"[SDK] ENCRYPTION_KEY environment variable is required but not set. " +
			"Generate a key with: openssl rand -base64 32",
		);
	}

	// 2. Byte-length check (all environments)
	const byteLength = Buffer.byteLength(key, "utf8");
	if (byteLength < 32) {
		throw new Error(
			`[SDK] ENCRYPTION_KEY does not meet minimum length: ` +
			`${byteLength} bytes provided, 32 bytes required. ` +
			"Generate a key with: openssl rand -base64 32",
		);
	}

	// 3. Blocklist check (production only)
	// Dev operators regularly use the known dev key; blocking it in all environments
	// would break the standard dev workflow. The blocklist is a production-only gate.
	if (process.env.NODE_ENV === "production") {
		if (ENCRYPTION_KEY_BLOCKLIST.includes(key)) {
			throw new Error(
				`[SDK] ENCRYPTION_KEY matches a known development default and must not be used in production. ` +
				`The value "${key.slice(0, 8)}..." is on the blocklist. ` +
				"Generate a production key with: openssl rand -base64 32",
			);
		}
	}
})();

// Blocklist
export { ENCRYPTION_KEY_BLOCKLIST } from "./blocklist";

// Database
export {
	getDb,
	getSettingsTable,
	getLocationsTable,
	getLoginAttemptsTable,
	getLockoutsTable,
	getSecurityAuditTable,
	ensureTable,
	ensureLocationsTable,
	ensureBruteForceTables,
	closeDb,
} from "./db";

// Settings CRUD
export {
	getSetting,
	getSettingOrDefault,
	getSecretSetting,
	setSetting,
	batchSetSettings,
	deleteSetting,
	listSettings,
	listSettingsForDisplay,
} from "./settings";
export type { Setting, SetSettingOptions, BatchSettingEntry } from "./settings";

// Session Locations
export { addSessionLocation, getSessionLocations, cleanupOldLocations } from "./locations";
export type { SessionLocation, AddSessionLocationData, GetSessionLocationsOptions } from "./locations";

// Encryption
export {
	encrypt,
	decrypt,
	isEncryptedFormat,
	deriveLegacyKeyForMigration,
	deriveHkdfKeyForMigration,
} from "./crypto";

// Cache
export { SettingsCache, settingsCache } from "./cache";

// Brute force protection
export {
	getBruteForceConfig,
	checkLockout,
	recordFailedAttempt,
	clearAttempts,
	listLockedAccounts,
	unlockAccount,
	appendAuditLog,
} from "./brute-force";
export type {
	BruteForceConfig,
	LockoutState,
	LockedAccount,
	LoginAttempt,
	AuditLogEvent,
} from "./brute-force";
