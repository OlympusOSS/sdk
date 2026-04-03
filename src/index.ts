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
