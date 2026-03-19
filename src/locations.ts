import { ensureLocationsTable, getDb, getLocationsTable } from "./db";

export interface SessionLocation {
	id: number;
	session_id: string;
	identity_id: string;
	ip_address: string | null;
	lat: number | null;
	lng: number | null;
	city: string | null;
	country: string | null;
	source: "ip" | "browser";
	created_at: Date;
}

export interface AddSessionLocationData {
	session_id: string;
	identity_id: string;
	ip_address?: string | null;
	lat?: number | null;
	lng?: number | null;
	city?: string | null;
	country?: string | null;
	source: "ip" | "browser";
}

export interface GetSessionLocationsOptions {
	source?: "ip" | "browser";
	since?: Date;
	limit?: number;
}

/**
 * Insert a session location record.
 * Called by Hera on login/registration to record the user's IP and/or browser location.
 */
export async function addSessionLocation(data: AddSessionLocationData): Promise<void> {
	await ensureLocationsTable();
	const db = getDb();
	const table = getLocationsTable();

	await db.unsafe(
		`INSERT INTO ${table} (session_id, identity_id, ip_address, lat, lng, city, country, source)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		[
			data.session_id,
			data.identity_id,
			data.ip_address ?? null,
			data.lat ?? null,
			data.lng ?? null,
			data.city ?? null,
			data.country ?? null,
			data.source,
		],
	);
}

/**
 * Query session location records with optional filters.
 * Used by Athena to populate the Session Locations heat map.
 */
export async function getSessionLocations(options?: GetSessionLocationsOptions): Promise<SessionLocation[]> {
	await ensureLocationsTable();
	const db = getDb();
	const table = getLocationsTable();

	const conditions: string[] = [];
	const params: (string | number | boolean | null | Date)[] = [];
	let paramIndex = 1;

	if (options?.source) {
		conditions.push(`source = $${paramIndex++}`);
		params.push(options.source);
	}

	if (options?.since) {
		conditions.push(`created_at >= $${paramIndex++}`);
		params.push(options.since.toISOString());
	}

	const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
	const limit = options?.limit ? `LIMIT ${Math.min(options.limit, 10000)}` : "LIMIT 5000";

	const rows = await db.unsafe(
		`SELECT id, session_id, identity_id, ip_address, lat, lng, city, country, source, created_at
		 FROM ${table}
		 ${where}
		 ORDER BY created_at DESC
		 ${limit}`,
		params,
	);

	return rows as unknown as SessionLocation[];
}
