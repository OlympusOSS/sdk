import { describe, expect, test, mock, beforeEach } from "bun:test";

// ---------------------------------------------------------------------------
// Mutable state that test cases drive
// ---------------------------------------------------------------------------

// Controls what db.unsafe() returns for each call in sequence.
// Each element is consumed in FIFO order per test.
let mockDbResults: unknown[][] = [];

// Tracks all db.unsafe() call arguments for assertion.
let dbUnsafeCalls: { sql: string; params: unknown[] }[] = [];

// Controls whether db.unsafe() throws on the next call.
let mockDbError: Error | null = null;

// Controls ensureBruteForceTables — set to true to make it throw.
let ensureBruteForceTablesError: Error | null = null;

// Controls getSettingOrDefault return values (keyed by setting key).
let mockSettingsValues: Record<string, string> = {};

// Controls the config cache — simulates a cache hit or miss.
let mockConfigCacheValue: string | null | undefined = undefined;

// ---------------------------------------------------------------------------
// Mock: ./db
// ---------------------------------------------------------------------------

mock.module("./db", () => ({
	getDb: () => ({
		unsafe: async (sql: string, params: unknown[] = []) => {
			dbUnsafeCalls.push({ sql, params });
			if (mockDbError) {
				const err = mockDbError;
				mockDbError = null; // consume the error
				throw err;
			}
			// Return the next queued result, or empty array if exhausted.
			return (mockDbResults.shift() as unknown[]) ?? [];
		},
	}),
	getLoginAttemptsTable: () => "ciam_login_attempts",
	getLockoutsTable: () => "ciam_lockouts",
	getSecurityAuditTable: () => "ciam_security_audit_log",
	ensureBruteForceTables: async () => {
		if (ensureBruteForceTablesError) {
			const err = ensureBruteForceTablesError;
			ensureBruteForceTablesError = null;
			throw err;
		}
	},
}));

// ---------------------------------------------------------------------------
// Mock: ./settings
// ---------------------------------------------------------------------------

mock.module("./settings", () => ({
	getSettingOrDefault: async (key: string, defaultValue: string) => {
		return mockSettingsValues[key] ?? defaultValue;
	},
}));

// ---------------------------------------------------------------------------
// Mock: ./cache  (controls the bruteForceConfigCache behaviour)
// ---------------------------------------------------------------------------

mock.module("./cache", () => ({
	// SettingsCache class — returned instance wraps our controllable state.
	SettingsCache: class {
		get(_key: string): string | null | undefined {
			return mockConfigCacheValue;
		}
		set(_key: string, _value: string | null): void {
			// no-op for most tests; we control cache via mockConfigCacheValue
		}
	},
	settingsCache: {
		get: (_key: string) => undefined,
		set: () => {},
		invalidate: () => {},
	},
}));

// ---------------------------------------------------------------------------
// Import module under test AFTER mocks are registered
// ---------------------------------------------------------------------------

const {
	getBruteForceConfig,
	checkLockout,
	recordFailedAttempt,
	clearAttempts,
	listLockedAccounts,
	unlockAccount,
	appendAuditLog,
} = await import("./brute-force");

// ---------------------------------------------------------------------------
// Reset helpers
// ---------------------------------------------------------------------------

beforeEach(() => {
	mockDbResults = [];
	dbUnsafeCalls = [];
	mockDbError = null;
	ensureBruteForceTablesError = null;
	mockSettingsValues = {};
	mockConfigCacheValue = undefined; // cache miss by default
});

// ---------------------------------------------------------------------------
// getBruteForceConfig
// ---------------------------------------------------------------------------

describe("getBruteForceConfig", () => {
	test("returns defaults when settings return their default values", async () => {
		// mockSettingsValues is empty — getSettingOrDefault returns its default arg
		mockConfigCacheValue = undefined; // cache miss

		const config = await getBruteForceConfig();

		expect(config.maxAttempts).toBe(5);
		expect(config.windowSeconds).toBe(600);
		expect(config.lockoutDurationSeconds).toBe(900);
	});

	test("returns overridden values when settings keys are set", async () => {
		mockSettingsValues["security.brute_force.max_attempts"] = "10";
		mockSettingsValues["security.brute_force.window_seconds"] = "300";
		mockSettingsValues["security.brute_force.lockout_duration_seconds"] = "1800";
		mockConfigCacheValue = undefined; // cache miss

		const config = await getBruteForceConfig();

		expect(config.maxAttempts).toBe(10);
		expect(config.windowSeconds).toBe(300);
		expect(config.lockoutDurationSeconds).toBe(1800);
	});

	test("returns cached result and does not call getSettingOrDefault again", async () => {
		// Simulate a cache hit with known values.
		const cachedConfig = JSON.stringify({ maxAttempts: 3, windowSeconds: 120, lockoutDurationSeconds: 180 });
		mockConfigCacheValue = cachedConfig;

		// Override settings to a different value — if caching works, they won't be read.
		mockSettingsValues["security.brute_force.max_attempts"] = "99";

		const config = await getBruteForceConfig();

		// Should come from cache, not from settings.
		expect(config.maxAttempts).toBe(3);
		expect(config.windowSeconds).toBe(120);
		expect(config.lockoutDurationSeconds).toBe(180);
	});

	test("enforces minimum lockout duration of 60 seconds", async () => {
		mockSettingsValues["security.brute_force.lockout_duration_seconds"] = "30";
		mockConfigCacheValue = undefined;

		const config = await getBruteForceConfig();

		// Below-minimum value must fall back to the default (900), not the minimum (60).
		expect(config.lockoutDurationSeconds).toBe(900);
	});
});

// ---------------------------------------------------------------------------
// checkLockout
// ---------------------------------------------------------------------------

describe("checkLockout", () => {
	test("returns { locked: false } when no active lockout row exists", async () => {
		mockDbResults = [[]]; // DB returns zero rows

		const result = await checkLockout("user@example.com");

		expect(result.locked).toBe(false);
		expect(result.lockedUntil).toBeUndefined();
	});

	test("returns { locked: true, lockedUntil } when an active lockout is found", async () => {
		const lockedUntilDate = new Date(Date.now() + 600_000); // 10 minutes from now
		mockDbResults = [[{ locked_until: lockedUntilDate.toISOString() }]];

		const result = await checkLockout("user@example.com");

		expect(result.locked).toBe(true);
		expect(result.lockedUntil).toBeInstanceOf(Date);
		expect(result.lockedUntil!.getTime()).toBe(lockedUntilDate.getTime());
	});

	test("normalizes identifier to lowercase before querying", async () => {
		mockDbResults = [[]];

		await checkLockout("User@Example.COM");

		// The SQL call should have the normalized identifier as the first param.
		expect(dbUnsafeCalls.length).toBe(1);
		expect(dbUnsafeCalls[0].params[0]).toBe("user@example.com");
	});

	test("returns { locked: false } (fail-open) on DB error", async () => {
		mockDbError = new Error("connection refused");

		const result = await checkLockout("user@example.com");

		expect(result.locked).toBe(false);
		expect(result.lockedUntil).toBeUndefined();
	});

	test("returns { locked: false } (fail-open) when ensureBruteForceTables throws", async () => {
		ensureBruteForceTablesError = new Error("migration failed");

		const result = await checkLockout("user@example.com");

		expect(result.locked).toBe(false);
	});

	// E1: empty/whitespace identifier guard
	test("returns { locked: false } without hitting the DB for a whitespace-only identifier", async () => {
		const result = await checkLockout("   ");

		expect(result.locked).toBe(false);
		expect(result.lockedUntil).toBeUndefined();
		// No DB call should have been made.
		expect(dbUnsafeCalls.length).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// recordFailedAttempt
// ---------------------------------------------------------------------------

describe("recordFailedAttempt", () => {
	test("returns { shouldLockout: false, attemptCount: N } when below threshold", async () => {
		// INSERT result (no rows returned), then COUNT result.
		mockDbResults = [[], [{ cnt: 3 }]];

		const result = await recordFailedAttempt("user@example.com", "1.2.3.4");

		expect(result.shouldLockout).toBe(false);
		expect(result.attemptCount).toBe(3);
	});

	test("returns { shouldLockout: true } when attempt count reaches maxAttempts", async () => {
		// INSERT attempt row, COUNT = 5 (== maxAttempts default), INSERT lockout row.
		mockDbResults = [[], [{ cnt: 5 }], []];

		const result = await recordFailedAttempt("user@example.com", "1.2.3.4");

		expect(result.shouldLockout).toBe(true);
		expect(result.attemptCount).toBe(5);
	});

	test("returns { shouldLockout: true } when attempt count exceeds maxAttempts", async () => {
		mockDbResults = [[], [{ cnt: 8 }], []];

		const result = await recordFailedAttempt("user@example.com");

		expect(result.shouldLockout).toBe(true);
	});

	test("normalizes identifier to lowercase before inserting", async () => {
		mockDbResults = [[], [{ cnt: 1 }]];

		await recordFailedAttempt("ADMIN@EXAMPLE.COM", "10.0.0.1");

		// First unsafe call is the INSERT — first param is the identifier.
		expect(dbUnsafeCalls[0].params[0]).toBe("admin@example.com");
	});

	test("passes null ip_address when none is provided", async () => {
		mockDbResults = [[], [{ cnt: 1 }]];

		await recordFailedAttempt("user@example.com");

		// Second param of INSERT should be null.
		expect(dbUnsafeCalls[0].params[1]).toBeNull();
	});

	test("returns fail-open result { shouldLockout: false, attemptCount: 0 } on DB error", async () => {
		mockDbError = new Error("timeout");

		const result = await recordFailedAttempt("user@example.com", "1.2.3.4");

		expect(result.shouldLockout).toBe(false);
		expect(result.attemptCount).toBe(0);
	});

	test("returns fail-open result when ensureBruteForceTables throws", async () => {
		ensureBruteForceTablesError = new Error("pg down");

		const result = await recordFailedAttempt("user@example.com");

		expect(result.shouldLockout).toBe(false);
		expect(result.attemptCount).toBe(0);
	});

	// E1: empty/whitespace identifier guard
	test("returns { shouldLockout: false, attemptCount: 0 } without hitting the DB for a whitespace-only identifier", async () => {
		const result = await recordFailedAttempt("   ", "1.2.3.4");

		expect(result.shouldLockout).toBe(false);
		expect(result.attemptCount).toBe(0);
		// No DB call should have been made.
		expect(dbUnsafeCalls.length).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// clearAttempts
// ---------------------------------------------------------------------------

describe("clearAttempts", () => {
	test("calls DELETE on the login attempts table", async () => {
		mockDbResults = [[]]; // DELETE returns empty

		await clearAttempts("user@example.com");

		expect(dbUnsafeCalls.length).toBe(1);
		expect(dbUnsafeCalls[0].sql).toContain("DELETE");
		expect(dbUnsafeCalls[0].sql).toContain("ciam_login_attempts");
		expect(dbUnsafeCalls[0].params[0]).toBe("user@example.com");
	});

	test("normalizes identifier to lowercase", async () => {
		mockDbResults = [[]];

		await clearAttempts("ADMIN@EXAMPLE.COM");

		expect(dbUnsafeCalls[0].params[0]).toBe("admin@example.com");
	});

	test("does not throw on DB error (fire-and-forget semantics)", async () => {
		mockDbError = new Error("connection reset");

		// Should resolve cleanly — a cleanup failure must not block a successful login.
		await expect(clearAttempts("user@example.com")).resolves.toBeUndefined();
	});

	test("does not throw when ensureBruteForceTables fails", async () => {
		ensureBruteForceTablesError = new Error("no tables");

		await expect(clearAttempts("user@example.com")).resolves.toBeUndefined();
	});

	// E1: empty/whitespace identifier guard
	test("returns early without hitting the DB for a whitespace-only identifier", async () => {
		await expect(clearAttempts("   ")).resolves.toBeUndefined();
		// No DB call should have been made.
		expect(dbUnsafeCalls.length).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// listLockedAccounts
// ---------------------------------------------------------------------------

describe("listLockedAccounts", () => {
	test("returns empty array when no active lockouts exist", async () => {
		mockDbResults = [[]]; // DB returns zero rows

		const result = await listLockedAccounts();

		expect(result).toEqual([]);
	});

	test("returns all rows when active lockouts exist", async () => {
		const now = new Date();
		const lockedUntil1 = new Date(now.getTime() + 900_000).toISOString();
		const lockedUntil2 = new Date(now.getTime() + 300_000).toISOString();

		const rows = [
			{
				id: 1,
				identifier: "user1@example.com",
				identity_id: "uuid-001",
				locked_at: now.toISOString(),
				locked_until: lockedUntil1,
				lock_reason: "brute_force",
				auto_threshold_at: 5,
			},
			{
				id: 2,
				identifier: "user2@example.com",
				identity_id: null,
				locked_at: now.toISOString(),
				locked_until: lockedUntil2,
				lock_reason: "brute_force",
				auto_threshold_at: null,
			},
		];
		mockDbResults = [rows];

		const result = await listLockedAccounts();

		expect(result).toHaveLength(2);
		expect(result[0]).toMatchObject({ id: 1, identifier: "user1@example.com" });
		expect(result[1]).toMatchObject({ id: 2, identifier: "user2@example.com" });
	});

	test("passes through the DB result unchanged (SQL filter is in the query)", async () => {
		// The WHERE clause (locked_until > NOW() AND unlocked_at IS NULL) runs in Postgres.
		// The function must return exactly what the mock returns — no client-side filtering.
		const row = {
			id: 3,
			identifier: "user3@example.com",
			identity_id: "uuid-003",
			locked_at: new Date().toISOString(),
			locked_until: new Date(Date.now() + 600_000).toISOString(),
			lock_reason: "brute_force",
			auto_threshold_at: null,
		};
		mockDbResults = [[row]];

		const result = await listLockedAccounts();

		expect(result).toHaveLength(1);
		expect(result[0]).toMatchObject(row);
	});

	test("calls ensureBruteForceTables before querying the DB", async () => {
		mockDbResults = [[]];

		// If ensureBruteForceTables throws, the function should propagate the error
		// rather than proceeding to query an unmigrated table.
		ensureBruteForceTablesError = new Error("migration failed");

		await expect(listLockedAccounts()).rejects.toThrow("migration failed");

		// The DB must not have been queried after the migration failure.
		expect(dbUnsafeCalls.length).toBe(0);
	});
});

// ---------------------------------------------------------------------------
// unlockAccount
// ---------------------------------------------------------------------------

describe("unlockAccount", () => {
	test("returns false when no active lockout row is found", async () => {
		mockDbResults = [[/* existing SELECT returns empty */], []];

		const result = await unlockAccount("user@example.com", "admin-uuid");

		expect(result).toBe(false);
	});

	test("returns true when an active lockout is found and updated", async () => {
		// SELECT returns one lockout row; UPDATE returns count > 0.
		const lockoutRow = {
			id: 1,
			identity_id: null,
			locked_until: new Date(Date.now() + 900_000).toISOString(),
			lock_reason: "brute_force",
		};
		const updateResult = Object.assign([], { count: 1 });
		// Audit log INSERT returns empty — fire-and-forget.
		mockDbResults = [[lockoutRow], updateResult, []];

		const result = await unlockAccount("user@example.com", "admin-uuid-123");

		expect(result).toBe(true);
	});

	test("passes adminIdentityId as the first UPDATE param", async () => {
		const lockoutRow = {
			id: 1,
			identity_id: null,
			locked_until: new Date(Date.now() + 900_000).toISOString(),
			lock_reason: "brute_force",
		};
		const updateResult = Object.assign([], { count: 1 });
		mockDbResults = [[lockoutRow], updateResult, []];

		await unlockAccount("user@example.com", "admin-uuid-123");

		// Second db.unsafe call is the UPDATE; first param is adminIdentityId.
		const updateCall = dbUnsafeCalls.find((c) => c.sql.includes("UPDATE"));
		expect(updateCall).toBeDefined();
		expect(updateCall!.params[0]).toBe("admin-uuid-123");
	});

	test("normalizes identifier to lowercase for SELECT and UPDATE", async () => {
		const lockoutRow = {
			id: 1,
			identity_id: null,
			locked_until: new Date(Date.now() + 900_000).toISOString(),
			lock_reason: "brute_force",
		};
		const updateResult = Object.assign([], { count: 1 });
		mockDbResults = [[lockoutRow], updateResult, []];

		await unlockAccount("USER@EXAMPLE.COM", "admin-uuid");

		// All db.unsafe calls should use the lowercase identifier.
		for (const call of dbUnsafeCalls) {
			if (call.params.length > 0) {
				const identifierParams = call.params.filter(
					(p) => typeof p === "string" && p.includes("@"),
				);
				for (const id of identifierParams) {
					expect(id).toBe("user@example.com");
				}
			}
		}
	});

	test("returns false when UPDATE affects 0 rows (race condition)", async () => {
		// SELECT returns a row, but UPDATE affects 0 (already unlocked by concurrent request).
		const lockoutRow = {
			id: 1,
			identity_id: null,
			locked_until: new Date(Date.now() + 900_000).toISOString(),
			lock_reason: "brute_force",
		};
		const updateResult = Object.assign([], { count: 0 });
		mockDbResults = [[lockoutRow], updateResult];

		const result = await unlockAccount("user@example.com", "admin-uuid");

		expect(result).toBe(false);
	});

	// E1: empty/whitespace identifier guard
	test("returns false without hitting the DB for a whitespace-only identifier", async () => {
		const result = await unlockAccount("   ", "admin-uuid");

		expect(result).toBe(false);
		// No DB call should have been made.
		expect(dbUnsafeCalls.length).toBe(0);
	});

	// E2: unlockAccount must not unlock already-expired lockouts
	test("returns false when the only matching row is an expired lockout (locked_until in the past)", async () => {
		// The SELECT query now includes AND locked_until > NOW(), so an expired lockout
		// returns no rows — simulate that by having the mock return an empty array.
		mockDbResults = [[]];

		const result = await unlockAccount("user@example.com", "admin-uuid");

		expect(result).toBe(false);
		// Confirm the SELECT was actually issued (one DB call) and no UPDATE followed.
		expect(dbUnsafeCalls.length).toBe(1);
		const selectCall = dbUnsafeCalls[0];
		expect(selectCall.sql).toContain("SELECT");
		expect(selectCall.sql).toContain("locked_until > NOW()");
	});
});

// ---------------------------------------------------------------------------
// appendAuditLog
// ---------------------------------------------------------------------------

describe("appendAuditLog", () => {
	test("inserts a row with the correct event_type", async () => {
		mockDbResults = [[]];

		await appendAuditLog({ event_type: "login_success", identifier: "user@example.com" });

		expect(dbUnsafeCalls.length).toBe(1);
		expect(dbUnsafeCalls[0].sql).toContain("INSERT INTO");
		expect(dbUnsafeCalls[0].sql).toContain("ciam_security_audit_log");
		expect(dbUnsafeCalls[0].params[0]).toBe("login_success");
	});

	test("passes identifier as the second SQL parameter", async () => {
		mockDbResults = [[]];

		await appendAuditLog({ event_type: "lockout_created", identifier: "user@example.com" });

		expect(dbUnsafeCalls[0].params[1]).toBe("user@example.com");
	});

	test("passes null for optional fields when not provided", async () => {
		mockDbResults = [[]];

		await appendAuditLog({ event_type: "test_event" });

		const params = dbUnsafeCalls[0].params;
		expect(params[1]).toBeNull(); // identifier
		expect(params[2]).toBeNull(); // identity_id
		expect(params[3]).toBeNull(); // admin_identity_id
	});

	test("drops non-allowlisted metadata keys", async () => {
		mockDbResults = [[]];

		await appendAuditLog({
			event_type: "lockout_created",
			metadata: {
				ip: "1.2.3.4",
				reason: "auto_threshold",
				secret_key: "should-be-dropped",
				user_agent: "also-dropped",
			},
		});

		const metadataParam = dbUnsafeCalls[0].params[4];
		expect(metadataParam).not.toBeNull();

		const parsed = JSON.parse(metadataParam as string) as Record<string, string>;
		expect(parsed.ip).toBe("1.2.3.4");
		expect(parsed.reason).toBe("auto_threshold");
		expect(parsed.secret_key).toBeUndefined();
		expect(parsed.user_agent).toBeUndefined();
	});

	test("keeps all four allowlisted keys: ip, reason, locked_until, lock_reason", async () => {
		mockDbResults = [[]];

		await appendAuditLog({
			event_type: "account_unlocked",
			metadata: {
				ip: "10.0.0.1",
				reason: "admin_manual",
				locked_until: "2025-01-01T00:00:00.000Z",
				lock_reason: "brute_force",
			},
		});

		const parsed = JSON.parse(dbUnsafeCalls[0].params[4] as string) as Record<string, string>;
		expect(Object.keys(parsed)).toHaveLength(4);
		expect(parsed.ip).toBe("10.0.0.1");
		expect(parsed.reason).toBe("admin_manual");
		expect(parsed.locked_until).toBe("2025-01-01T00:00:00.000Z");
		expect(parsed.lock_reason).toBe("brute_force");
	});

	test("truncates metadata values longer than 500 characters", async () => {
		mockDbResults = [[]];

		const longValue = "x".repeat(600);

		await appendAuditLog({
			event_type: "test_event",
			metadata: { reason: longValue },
		});

		const parsed = JSON.parse(dbUnsafeCalls[0].params[4] as string) as Record<string, string>;
		expect(parsed.reason.length).toBe(500);
	});

	test("passes null for metadata param when no allowlisted keys remain", async () => {
		mockDbResults = [[]];

		await appendAuditLog({
			event_type: "test_event",
			metadata: { forbidden_key: "value", another_bad_key: "value2" },
		});

		// All keys are dropped — metadata should be null.
		expect(dbUnsafeCalls[0].params[4]).toBeNull();
	});

	test("passes null for metadata param when metadata is not provided", async () => {
		mockDbResults = [[]];

		await appendAuditLog({ event_type: "test_event" });

		expect(dbUnsafeCalls[0].params[4]).toBeNull();
	});
});
