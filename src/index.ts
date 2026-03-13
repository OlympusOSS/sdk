// Database
export { getDb, getSettingsTable, ensureTable, closeDb } from "./db";

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

// Encryption
export { encrypt, decrypt, isEncryptedFormat } from "./crypto";

// Cache
export { SettingsCache, settingsCache } from "./cache";
