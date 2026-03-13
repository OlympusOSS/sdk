interface CacheEntry<T> {
	value: T;
	expiresAt: number;
}

/**
 * Simple in-memory TTL cache.
 * Prevents hitting the database on every request for frequently-read settings.
 *
 * Default TTL: 60 seconds.
 */
export class SettingsCache {
	private store = new Map<string, CacheEntry<string | null>>();
	private defaultTtlMs: number;

	constructor(defaultTtlSeconds = 60) {
		this.defaultTtlMs = defaultTtlSeconds * 1000;
	}

	get(key: string): string | null | undefined {
		const entry = this.store.get(key);
		if (!entry) return undefined;

		if (Date.now() > entry.expiresAt) {
			this.store.delete(key);
			return undefined;
		}

		return entry.value;
	}

	set(key: string, value: string | null, ttlMs?: number): void {
		this.store.set(key, {
			value,
			expiresAt: Date.now() + (ttlMs ?? this.defaultTtlMs),
		});
	}

	/**
	 * Invalidate a single key or all keys.
	 */
	invalidate(key?: string): void {
		if (key) {
			this.store.delete(key);
		} else {
			this.store.clear();
		}
	}

	/**
	 * Returns the number of cached entries (including expired ones not yet pruned).
	 */
	get size(): number {
		return this.store.size;
	}
}

/** Shared singleton cache instance */
export const settingsCache = new SettingsCache();
