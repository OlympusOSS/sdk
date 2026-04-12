// Startup diagnostics — non-throwing ERROR log if ENCRYPTION_KEY is absent.
// This runs at import time (module evaluation) but does NOT throw, so Next.js
// build-time page-data collection can import the barrel without crashing.
// The actual throw is deferred to the first encrypt()/decrypt() call.
if (!process.env.ENCRYPTION_KEY) {
	console.error(
		"[SDK] ERROR: ENCRYPTION_KEY environment variable is not set. " +
		"Encryption operations will fail at runtime. " +
		"Generate a key with: openssl rand -base64 32",
	);
}

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
	validateOnStartup,
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
