# Brute Force Protection Module

## Overview

The brute force protection module in `@olympusoss/sdk` provides per-account login attempt tracking, lockout management, and security audit logging. It stores state in the `olympus` PostgreSQL database (same database as SDK settings) and is domain-scoped by the `SETTINGS_TABLE` environment variable.

Hera uses this module to gate login attempts before contacting Kratos. Athena uses it to list locked accounts and perform manual unlocks. All lockout logic executes inside SDK functions — neither Hera nor Athena implements lockout decisions directly.

## How It Works

```
User submits login
     |
     v
Hera loginAction: normalize identifier to lowercase
     |
     v
SDK checkLockout(identifier)
     |-- LOCKED --> return lockout message (do NOT contact Kratos)
     |
     +-- NOT LOCKED --> continue
          |
          v
     Kratos: submit credentials
          |
          |-- SUCCESS --> SDK clearAttempts(identifier) [fire-and-forget] --> redirect
          |
          +-- FAILURE --> SDK recordFailedAttempt(identifier, ip)
                              |
                              +-- { shouldLockout: true }
                              |       --> lockout row inserted inside recordFailedAttempt
                              |       --> appendAuditLog called inside recordFailedAttempt
                              |
                              +-- { shouldLockout: false }
                                      --> return generic "Invalid email or password."
```

The lockout check runs before Kratos credential submission. This prevents timing-based username enumeration and avoids unnecessary load on Kratos during brute-force attacks.

Lockout creation is automatic: `recordFailedAttempt` inserts the lockout row itself when the attempt count reaches `maxAttempts`. There is no separate `createLockout` function in the public API.

## API / Technical Details

### Function Signatures

```typescript
// Check whether an account is currently locked out.
// FAIL-OPEN: returns { locked: false } if the database is unavailable.
checkLockout(identifier: string): Promise<LockoutState>

// Record a failed login attempt. If the count within the sliding window
// reaches maxAttempts, inserts a lockout row and appends an audit log entry.
// FAIL-OPEN: returns { shouldLockout: false, attemptCount: 0 } if the database is unavailable.
recordFailedAttempt(
  identifier: string,
  ipAddress?: string | null
): Promise<{ shouldLockout: boolean; attemptCount: number }>

// Delete all failed attempt rows for the identifier.
// Call on successful login. Errors are logged at WARN and not re-thrown.
clearAttempts(identifier: string): Promise<void>

// List all accounts that are currently locked (locked_until > NOW(), unlocked_at IS NULL).
// Used by the Athena admin UI.
listLockedAccounts(): Promise<LockedAccount[]>

// Manually unlock an account by setting unlocked_at on the active lockout row.
// Returns true if an active lockout was found and unlocked.
// Returns false for all not-found cases (no distinction between "no lockout" and
// "wrong identifier" -- prevents enumeration attacks).
// Appends an audit log entry on success.
unlockAccount(identifier: string, adminIdentityId: string): Promise<boolean>

// Append a row to the security audit log table.
// Metadata keys are validated against an allowlist; values are truncated to 500 chars.
appendAuditLog(event: AuditLogEvent): Promise<void>

// Read brute-force configuration from the settings table.
// Results are cached for 60 seconds.
getBruteForceConfig(): Promise<BruteForceConfig>
```

### Type Definitions

```typescript
interface BruteForceConfig {
  /** Number of failed attempts before triggering a lockout. Default: 5. */
  maxAttempts: number;
  /** Sliding window in seconds for counting attempts. Default: 600 (10 min). */
  windowSeconds: number;
  /** Lockout duration in seconds. Minimum enforced: 60. Default: 900 (15 min). */
  lockoutDurationSeconds: number;
}

interface LockoutState {
  locked: boolean;
  /** When the lockout expires. Undefined if not locked. */
  lockedUntil?: Date;
}

interface LockedAccount {
  id: number;
  identifier: string;
  identity_id: string | null;
  locked_at: Date | null;
  locked_until: Date | null;
  lock_reason: string | null;
  /** Attempt count at the time the lockout was triggered. */
  auto_threshold_at: number | null;
  trigger_ip: string | null;
}

interface LoginAttempt {
  id: number;
  identifier: string;
  ip_address: string | null;
  attempt_time: Date;
}

interface AuditLogEvent {
  event_type: string;
  identifier?: string;
  identity_id?: string;
  admin_identity_id?: string;
  /**
   * Keys are validated against AUDIT_METADATA_ALLOWLIST before insert.
   * Allowed keys: 'ip', 'reason', 'locked_until', 'lock_reason'.
   * Any other key is silently dropped. Values truncated to 500 chars.
   */
  metadata?: Record<string, string>;
}
```

### Configuration Keys

All thresholds are stored in the SDK settings table under the `security.brute_force.*` namespace. Changes take effect within the 60-second settings cache TTL — no service restart required.

| Key | Type | Default | Min | Max | Notes |
|-----|------|---------|-----|-----|-------|
| `security.brute_force.max_attempts` | integer | `5` | `1` | — | Failed attempts before lockout fires. See off-by-one warning below. |
| `security.brute_force.window_seconds` | integer | `600` | `1` | — | Sliding window duration in seconds (10 min default). |
| `security.brute_force.lockout_duration_seconds` | integer | `900` | `60` | — | How long the lockout lasts. Values below 60 are rejected and default (900) is used. |

**Off-by-one at low thresholds**: The append-then-count pattern in `recordFailedAttempt` is subject to a race condition when concurrent login requests are processed simultaneously. At `max_attempts < 3`, two concurrent failed attempts can both count before the lockout row is committed, allowing one extra attempt through. Do not set `max_attempts` below `3` in production.

**Minimum lockout duration enforcement**: `lockout_duration_seconds` values below 60 are rejected by `getBruteForceConfig()`. The default (900) is used instead, and a warning is logged:

```
[security][brute_force] lockout_duration_seconds value <N> is below minimum 60. Using default: 900
```

### Database Tables

The module creates three tables in the `olympus` database. Table names are derived from the `SETTINGS_TABLE` environment variable:

| `SETTINGS_TABLE` | Login attempts table | Lockouts table | Audit log table |
|------------------|---------------------|----------------|-----------------|
| `ciam_settings` | `ciam_login_attempts` | `ciam_lockouts` | `ciam_security_audit_log` |
| `iam_settings` | `iam_login_attempts` | `iam_lockouts` | `iam_security_audit_log` |

All tables are created automatically via `CREATE TABLE IF NOT EXISTS` on first SDK use. No manual migration step is required.

**`ciam_login_attempts`** — append-only, one row per failed attempt:

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGSERIAL PRIMARY KEY | |
| `identifier` | TEXT NOT NULL | Lowercased email or username |
| `ip_address` | INET | Client IP, nullable |
| `attempt_time` | TIMESTAMPTZ NOT NULL DEFAULT NOW() | Used for sliding window query |

Indexes: `(identifier, attempt_time DESC)` for the sliding window count query; `(attempt_time)` for TTL cleanup.

Rows are deleted on successful login (`clearAttempts`) and cleaned up probabilistically (5% chance per `recordFailedAttempt` call) for records older than `2 x window_seconds`. This cleanup is mandatory, not optional — it bounds the table size on the login hot path.

**`ciam_lockouts`** — one row per lockout, never deleted on unlock (audit history):

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGSERIAL PRIMARY KEY | |
| `identifier` | TEXT NOT NULL | Lowercased — the stable lookup key for all operations |
| `identity_id` | TEXT | Kratos UUID; nullable if Kratos was unavailable at lockout time |
| `locked_at` | TIMESTAMPTZ DEFAULT NOW() | When the lockout was created |
| `locked_until` | TIMESTAMPTZ | When the lockout expires |
| `unlocked_at` | TIMESTAMPTZ | Set on manual unlock; NULL means still locked |
| `unlock_reason` | TEXT | Set to `admin_manual` on unlock |
| `unlocked_by_admin_id` | TEXT | Kratos UUID of the admin who unlocked |
| `lock_reason` | TEXT DEFAULT 'brute_force' | How the lockout was triggered |
| `auto_threshold_at` | SMALLINT | Attempt count at lockout time |
| `trigger_ip` | INET | IP address that triggered the lockout |

Index: `(identifier, locked_until DESC)` for the active lockout lookup.

`identifier` is the stable key for all lockout operations. `identity_id` is nullable — accounts locked during a Kratos outage have `identity_id = NULL` and are fully supported. All SDK functions operate on `identifier`, not `identity_id`.

**`ciam_security_audit_log`** — append-only audit log:

| Column | Type | Notes |
|--------|------|-------|
| `id` | BIGSERIAL PRIMARY KEY | |
| `event_type` | TEXT NOT NULL | e.g., `lockout_created`, `account_unlocked` |
| `identifier` | TEXT | Normalized identifier; nullable |
| `identity_id` | TEXT | Kratos UUID of the subject; nullable |
| `admin_identity_id` | TEXT | Kratos UUID of the acting admin; nullable for system events |
| `metadata` | JSONB | Allowed keys only: `ip`, `reason`, `locked_until`, `lock_reason` |
| `created_at` | TIMESTAMPTZ DEFAULT NOW() | |

Index: `(identifier, created_at DESC)` for per-identifier audit history queries.

---

## Examples

### Hera: Wiring the lockout check into the login flow

```typescript
import {
  checkLockout,
  recordFailedAttempt,
  clearAttempts,
} from "@olympusoss/sdk";

export async function loginAction(
  identifier: string,
  password: string,
  clientIp: string | null
) {
  const normalizedIdentifier = identifier.toLowerCase().trim();

  // Step 1: Check lockout before contacting Kratos.
  const lockoutState = await checkLockout(normalizedIdentifier);
  if (lockoutState.locked) {
    const lockedUntil = lockoutState.lockedUntil;
    const remainingMs = lockedUntil ? lockedUntil.getTime() - Date.now() : 0;
    const minutes = Math.max(1, Math.ceil(remainingMs / 60_000));
    return {
      error: "account_locked",
      message: `Account temporarily locked. Try again in ${minutes} minute${minutes !== 1 ? "s" : ""}.`,
    };
  }

  // Step 2: Forward credentials to Kratos.
  const kratosResult = await submitLoginToKratos(normalizedIdentifier, password);

  if (kratosResult.success) {
    // Step 3a: Clear attempt counter on success (fire-and-forget).
    // Do not await -- a cleanup failure must not block a successful login redirect.
    clearAttempts(normalizedIdentifier).catch(() => {});
    return { success: true, sessionToken: kratosResult.sessionToken };
  }

  // Step 3b: Record the failed attempt.
  // recordFailedAttempt handles lockout creation internally when the threshold is reached.
  // clientIp should come from the X-Real-IP header set by the Caddy reverse proxy --
  // not from X-Forwarded-For, which clients can spoof.
  const { shouldLockout } = await recordFailedAttempt(normalizedIdentifier, clientIp);

  if (shouldLockout) {
    // The account is now locked. The lockout row and audit log entry were written
    // inside recordFailedAttempt. Return the same generic message -- do not reveal
    // that a lockout was just triggered.
  }

  // Never reveal whether the failure is a wrong password or a lockout threshold.
  return { error: "invalid_credentials", message: "Invalid email or password." };
}
```

### Athena: Listing locked accounts and performing an admin unlock

```typescript
import { listLockedAccounts, unlockAccount } from "@olympusoss/sdk";

// GET /api/security/locked-accounts
export async function getLockedAccounts() {
  return listLockedAccounts();
}

// POST /api/security/locked-accounts/:identifier/unlock
// :identifier is the URL-encoded email or username (e.g., user%40example.com).
export async function adminUnlockAccount(
  rawIdentifier: string,
  adminIdentityId: string
) {
  // URL-decode before normalizing. The identifier in the path is URL-encoded
  // because email addresses contain '@' which must be encoded in URL path segments.
  const normalizedIdentifier = decodeURIComponent(rawIdentifier).toLowerCase().trim();

  const unlocked = await unlockAccount(normalizedIdentifier, adminIdentityId);

  if (!unlocked) {
    // Return 404 for all not-found cases. Do not distinguish between
    // "account not locked" and "identifier does not exist" -- prevents enumeration.
    return { status: 404, body: { error: "not_found" } };
  }

  return { status: 200, body: { message: "Account unlocked successfully." } };
}
```

---

## Edge Cases

### Database unavailable during `checkLockout`

If the database is unavailable, `checkLockout` logs at ERROR level with the structured tag `[security][brute_force][fail_open]` and returns `{ locked: false }`. The login proceeds. A database outage is already a P0 incident; blocking all logins on top of it compounds the impact.

The identifier is logged as a SHA-256 hash (first 16 hex characters), not plaintext, to prevent email addresses from appearing in logs.

Wire a monitoring alert on the `[security][brute_force][fail_open]` log tag. Any DB outage that affects lockout checks will produce this tag and must not be silently ignored.

### Database unavailable during `recordFailedAttempt`

If the database is unavailable, `recordFailedAttempt` logs at ERROR level with the same `[security][brute_force][fail_open]` tag and returns `{ shouldLockout: false, attemptCount: 0 }`. The failed attempt is not recorded and no lockout is created. The login flow surfaces the generic invalid credentials message to the user as normal.

### Unlock on an account with `identity_id = NULL`

Accounts locked during a Kratos outage may have `identity_id = NULL` in the lockouts table. `unlockAccount` uses `identifier` as its lookup key and fully supports these accounts. No special handling is required by callers.

### `unlockAccount` called on a non-locked account

`unlockAccount` returns `false` when no active lockout exists for the identifier. It does not throw. Callers should return 404 in this case. Admin dashboards should treat this as a no-op (the account may have had its lockout expire naturally between when the admin loaded the list and when they clicked Unlock).

### Identifier normalization

All SDK functions normalize `identifier` to lowercase and trim whitespace before any database operation. `User@Example.COM` and `user@example.com` resolve to the same lockout record. Callers must not pre-normalize differently (e.g., stripping the domain) — normalize only with `.toLowerCase().trim()` and pass the result directly to the SDK.

---

## Security Considerations

- The lockout check fires before Kratos credential validation. This prevents timing-based enumeration — a locked account and a valid account with a wrong password both receive a response without contacting Kratos in the locked case.
- The lockout message does not reveal the number of remaining attempts or whether a lockout was just triggered. Use the generic form: "Account temporarily locked. Try again in N minutes." Do not expose attempt counts.
- Client IP must be sourced from the `X-Real-IP` header set by the Caddy reverse proxy, not from `X-Forwarded-For`, which clients can spoof. Hera engineers must read from the correct header.
- Audit log `metadata` keys are constrained to an allowlist: `ip`, `reason`, `locked_until`, `lock_reason`. Any other key passed to `appendAuditLog` is silently dropped. Values are truncated to 500 characters. This prevents log injection via user-controlled email addresses.
- `unlockAccount` returns `false` for all not-found cases. It does not distinguish between "no lockout exists" and "identifier has no account." The Athena unlock endpoint must translate `false` to a 404 response — not reveal which case applied.
- GDPR Article 17 (right to erasure): when a CIAM identity is deleted, the associated `ciam_login_attempts` and `ciam_lockouts` rows must also be deleted. This gap is tracked in platform#56 and is not yet implemented in the current release.
