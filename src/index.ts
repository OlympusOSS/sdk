// Database
export { getDb, getSettingsTable, getLocationsTable, ensureTable, ensureLocationsTable, closeDb } from "./db";

// Settings CRUD
export {
	getSetting,
	getSettingOrDefault,
	getSecretSetting,
	setSetting,
	deleteSetting,
	listSettings,
	listSettingsForDisplay,
} from "./settings";
export type { Setting, SetSettingOptions } from "./settings";

// Session Locations
export { addSessionLocation, getSessionLocations } from "./locations";
export type { SessionLocation, AddSessionLocationData, GetSessionLocationsOptions } from "./locations";

// Encryption
export { encrypt, decrypt, isEncryptedFormat } from "./crypto";

// Cache
export { SettingsCache, settingsCache } from "./cache";
