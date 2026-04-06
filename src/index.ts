// Module-load validation: ENCRYPTION_KEY must be present before any SDK function is called.
// This ensures a deployment with a missing ENCRYPTION_KEY fails at startup, not at first use.
// Containers (ciam-hera, iam-hera, ciam-athena, iam-athena) import this module on startup —
// the error surfaces in container logs immediately, before any request is served.
if (!process.env.ENCRYPTION_KEY) {
	throw new Error(
		"[SDK] ENCRYPTION_KEY environment variable is required but not set. " +
		"Set this variable to a strong random string before starting the service.",
	);
}

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
export { encrypt, decrypt, isEncryptedFormat } from "./crypto";

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
