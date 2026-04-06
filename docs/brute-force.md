# Brute Force Protection Module

## Overview

The brute force protection module in `@olympusoss/sdk` provides per-account login attempt tracking, lockout management, and security audit logging. It stores state in the `olympus` PostgreSQL database (same database as SDK settings) and is domain-scoped by the `SETTINGS_TABLE` environment variable.

Hera and Athena consume this module to implement the two-layer rate limiting described in the [platform rate limiting guide](../../platform/docs/rate-limiting.md).

## How It Works

```
User submits login
     │
     ▼
Hera loginAction: normalize identifier to lowercase
     │
     ▼
SDK checkLockout(identifier)
     ├── LOCKED → return lockout response (do not contact Kratos)
     └── NOT LOCKED → continue
          │
          ▼
     Kratos: submit credentials
          ├── SUCCESS → SDK clearAttempts(identifier) [fire-and-forget] → redirect
          └── FAILURE → SDK recordFailedAttempt(identifier, ip)
                             │
                             └── count >= max_attempts → SDK createLockout(...)
                                                                + appendAuditLog(...)
                                   Return generic "Invalid email or password."
```

The lockout check runs before Kratos credential submission. This prevents timing-based username enumeration and avoids unnecessary load on Kratos during brute-force attacks.

## API / Technical Details

### Function Signatures

```typescript
// Check whether an account is currently locked out
checkLockout(identifier: string): Promise<LockoutState>

// Record a failed login attempt for an identifier
recordFailedAttempt(identifier: string, ip: string | null): Promise<void>

// Clear all failed attempt records for an identifier (call on successful login)
clearAttempts(identifier: string): Promise<void>

// Create a lockout record for an identifier (called internally by Hera after threshold is reached)
createLockout(
  identifier: string,
  ip: string | null,
  failedAttempts: number,
  lockedUntilSeconds: number
): Promise<void>

// List all active lockout records (used by Athena admin panel)
listLockedAccounts(options?: { limit?: number; offset?: number }): Promise<LockedAccount[]>

// Unlock an account and record the action in the audit log
unlockAccount(identifier: string, adminIdentityId: string): Promise<UnlockResult>

// Append a security audit log entry
appendAuditLog(entry: AuditLogEntry): Promise<void>

// Get the current brute force configuration from the settings table
getBruteForceConfig(): Promise<BruteForceConfig>
```

### Return Types

```typescript
interface LockoutState {
  locked: boolean
  lockedUntil?: Date         // When the lockout expires (undefined if not locked)
  remainingSeconds?: number  // Seconds until expiry, computed server-side (undefined if not locked)
}

interface LockedAccount {
  identifier: string
  identityId: string | null
  lockedUntil: Date
  lockReason: "auto_threshold" | "admin_manual"
  triggerIp: string | null
  failedAttempts: number
  createdAt: Date
  unlocked_at: Date | null
}

interface UnlockResult {
  success: true
  alreadyUnlocked: boolean  // true if the account was not locked when unlock was called
}

interface AuditLogEntry {
  action: string                // e.g., "account_unlocked", "lockout_created"
  actorIdentityId?: string      // Admin who performed the action (null for system actions)
  targetIdentifier: string      // Email or username
  targetIdentityId?: string     // Kratos UUID (null if unavailable at lockout time)
  metadata?: Record<string, string>  // Constrained to allowed keys; values truncated to 500 chars
}

interface BruteForceConfig {
  maxAttempts: number               // Default: 5
  windowSeconds: number             // Default: 600
  lockoutDurationSeconds: number    // Default: 900
  failOpen: boolean                 // Default: true
}
```

### Configuration Keys

All thresholds are stored in the SDK settings table under the `security.brute_force.*` namespace. Changes take effect within the 60-second settings cache TTL — no service restart required.

| Key | Type | Default | Min | Max | Notes |
|-----|------|---------|-----|-----|-------|
| `security.brute_force.max_attempts` | integer | `5` | `1` | `100` | Failed attempts before lockout fires |
| `security.brute_force.window_seconds` | integer | `600` | `60` | `86400` | Sliding window duration (10 min default) |
| `security.brute_force.lockout_duration_seconds` | integer | `900` | `60` | `86400` | How long the lockout lasts (15 min default) |
| `security.brute_force.fail_open` | boolean | `true` | — | — | Behavior when database is unavailable |

**Off-by-one at low thresholds**: At `max_attempts=1` or `max_attempts=2`, concurrent login requests processed simultaneously can allow one extra attempt before the lockout record is committed. This is a known V1 behavior of the append-then-count pattern. Avoid setting `max_attempts` below `3` in production — the Caddy per-IP layer provides additional protection at low counts.

**Minimum lockout duration enforcement**: `lockout_duration_seconds` values below 60 are rejected by `getBruteForceConfig()` with a WARN log entry, and the default value (900) is used instead. A 0-second lockout would silently disable brute force protection — this enforcement prevents misconfiguration:

```
[WARN] security.brute_force.lockout_duration_seconds value (0) is below minimum (60). Using default 900s.
```

### Database Tables

The module creates three tables in the `olympus` database. Table names are derived from the `SETTINGS_TABLE` environment variable — `ciam_settings` produces `ciam_login_attempts`, `ciam_lockouts`, and `ciam_security_audit`.

**`ciam_login_attempts`** — append-only, one row per failed attempt:

| Column | Type | Notes |
|--------|------|-------|
| `id` | SERIAL PK | |
| `identifier` | TEXT NOT NULL | Lowercased email or username |
| `attempt_time` | TIMESTAMPTZ NOT NULL | Used for sliding window query |
| `ip_address` | TEXT NULL | Client IP for admin visibility |
| `identity_id` | TEXT NULL | Kratos UUID, if known at attempt time |

Index: `(identifier, attempt_time DESC)` for the sliding window count query.

Rows are deleted on successful login (`clearAttempts`) and cleaned up probabilistically (5% chance per `recordFailedAttempt` call) for records older than `2 × window_seconds`.

**`ciam_lockouts`** — one row per lockout, never deleted (audit history):

| Column | Type | Notes |
|--------|------|-------|
| `id` | SERIAL PK | |
| `identifier` | TEXT UNIQUE NOT NULL | Lowercased — the stable lookup key |
| `identity_id` | TEXT NULL | Kratos UUID; nullable if Kratos was unavailable at lockout time |
| `locked_until` | TIMESTAMPTZ NOT NULL | Lockout expiry |
| `lock_reason` | TEXT NOT NULL | `auto_threshold` or `admin_manual` |
| `trigger_ip` | TEXT NULL | IP that triggered lockout |
| `failed_attempts` | INTEGER NOT NULL | Snapshot of count at lockout time |
| `created_at` | TIMESTAMPTZ NOT NULL | |
| `unlocked_at` | TIMESTAMPTZ NULL | Set on manual unlock; NULL = still locked |
| `unlocked_by` | TEXT NULL | Admin identity ID who unlocked |

`identifier` is the stable key for all lockout operations. `identity_id` is nullable — accounts locked during a Kratos outage (when Kratos UUID lookup fails) have `identity_id = NULL` and are fully supported. All SDK functions operate on `identifier`, not `identity_id`.

**`ciam_security_audit`** — append-only audit log:

| Column | Type | Notes |
|--------|------|-------|
| `id` | SERIAL PK | |
| `action` | TEXT NOT NULL | `account_unlocked`, `lockout_created` |
| `actor_identity_id` | TEXT NULL | Admin who acted; NULL for system-generated entries |
| `target_identifier` | TEXT NOT NULL | Normalized identifier |
| `target_identity_id` | TEXT NULL | Kratos UUID |
| `metadata` | JSONB NULL | Allowed keys: `ip`, `reason`, `locked_until`, `lock_reason`; values truncated at 500 chars |
| `created_at` | TIMESTAMPTZ NOT NULL | |

---

## Examples

### Hera: Wiring lockout check into the login flow

```typescript
import {
  checkLockout,
  recordFailedAttempt,
  clearAttempts,
  createLockout,
  appendAuditLog,
  getBruteForceConfig,
} from "@olympusoss/sdk";

export async function loginAction(identifier: string, password: string, clientIp: string) {
  const normalizedIdentifier = identifier.toLowerCase().trim();

  // Step 1: Check lockout before contacting Kratos
  const lockoutState = await checkLockout(normalizedIdentifier);
  if (lockoutState.locked) {
    const minutes = Math.ceil((lockoutState.remainingSeconds ?? 900) / 60);
    return {
      error: "account_locked",
      message: `Account temporarily locked. Try again in ${minutes} minute${minutes !== 1 ? "s" : ""}.`,
      retry_after: lockoutState.remainingSeconds,
    };
  }

  // Step 2: Forward credentials to Kratos
  const kratosResult = await submitLoginToKratos(normalizedIdentifier, password);

  if (kratosResult.success) {
    // Step 3a: Clear attempt counter on success (fire-and-forget)
    clearAttempts(normalizedIdentifier).catch(() => {
      // Non-critical — do not block the login redirect
    });
    return { success: true, sessionToken: kratosResult.sessionToken };
  }

  // Step 3b: Record failed attempt
  await recordFailedAttempt(normalizedIdentifier, clientIp);

  // Step 4: Check if threshold is now reached
  const config = await getBruteForceConfig();
  const recentCount = await countRecentAttempts(normalizedIdentifier, config.windowSeconds);

  if (recentCount >= config.maxAttempts) {
    await createLockout(normalizedIdentifier, clientIp, recentCount, config.lockoutDurationSeconds);
    await appendAuditLog({
      action: "lockout_created",
      targetIdentifier: normalizedIdentifier,
      metadata: {
        reason: "auto_threshold",
        ip: clientIp ?? "unknown",
      },
    });
  }

  // Never reveal whether it is a wrong password or an account lock
  return { error: "invalid_credentials", message: "Invalid email or password." };
}
```

### Athena: Listing and unlocking locked accounts

```typescript
import { listLockedAccounts, unlockAccount } from "@olympusoss/sdk";

// GET /api/security/locked-accounts
export async function getLockedAccounts(limit = 50, offset = 0) {
  return listLockedAccounts({ limit, offset });
}

// POST /api/security/locked-accounts/:identifier/unlock
export async function adminUnlockAccount(identifier: string, adminIdentityId: string) {
  const normalizedIdentifier = decodeURIComponent(identifier).toLowerCase().trim();
  const result = await unlockAccount(normalizedIdentifier, adminIdentityId);

  if (result.alreadyUnlocked) {
    return { message: "Account was not locked." };
  }

  return { message: "Account unlocked successfully." };
}
```

Note: `identifier` in the URL path is the URL-encoded email or username (e.g., `user%40example.com`). Decode before passing to `unlockAccount`. The `unlockAccount` function is idempotent — calling it on a non-locked identifier returns `{ success: true, alreadyUnlocked: true }` rather than throwing.

---

## Edge Cases

### Database unavailable during `checkLockout`

If the database is unavailable when `checkLockout` is called, the SDK logs the failure and returns `{ locked: false }` — the login proceeds (fail-open). A database outage is already a P0 incident; blocking all logins on top of it compounds the impact.

The log entry uses a structured tag for monitoring alert wiring:

```
[ERROR][security][brute_force][fail_open] Database unavailable — lockout check bypassed for identifier: <sha256-hash>. Login proceeding.
```

The identifier is logged as a SHA-256 hash, not plaintext, to prevent email addresses from appearing in logs. Use the same hash to correlate log entries with database records when investigating.

**Alert configuration**: Wire a monitoring alert on `[security][brute_force][fail_open]` log lines. Any DB outage will produce this tag — it should not be silently ignored. The monitoring alert ownership is tracked in platform#57.

### Database unavailable during `recordFailedAttempt`

If the database is unavailable when `recordFailedAttempt` is called, the SDK logs the failure at ERROR level with the same `[security][brute_force][fail_open]` tag. The failed attempt is not recorded. The login flow does not surface an error to the user (a correct password still succeeds; a wrong password still returns the generic invalid credentials message).

### Unlock on an account with `identity_id = NULL`

Accounts locked during a Kratos outage may have `identity_id = NULL` in the `ciam_lockouts` table. The `unlockAccount` function uses `identifier` (not `identity_id`) as its lookup key and fully supports these accounts. No special handling is required by callers.

### `unlockAccount` called on a non-locked account

`unlockAccount` is idempotent. Calling it when no active lockout exists returns `{ success: true, alreadyUnlocked: true }`. It does not throw or return an error. This is intentional — admin unlock operations in dashboards should never fail due to race conditions between the admin viewing a stale list and the lockout expiring naturally.

### Identifier normalization mismatches

All SDK functions normalize `identifier` to lowercase and trim whitespace before any database operation. Callers must pass the same normalized value consistently. `user@example.com` and `User@EXAMPLE.COM` are treated as the same identifier. A mismatch at the call site (e.g., Hera passes lowercased, Athena passes mixed-case) will cause lookup failures — normalize before calling.

---

## Security Considerations

- The lockout check fires before Kratos credential validation. This prevents timing-based enumeration (a locked account and a valid account with wrong password produce responses in the same time range, because neither contacts Kratos for the locked case).
- The lockout message does not reveal the number of remaining attempts or whether the account exists. Use the generic message "Account temporarily locked. Try again in N minutes." — do not expose attempt counts.
- Client IP is sourced from `X-Real-IP` (set by the Caddy reverse proxy) — not from `X-Forwarded-For`, which clients can spoof. Hera engineers must read from the correct header. See the architecture brief for the trusted header chain.
- Audit log `metadata` keys are constrained to an allowlist (`ip`, `reason`, `locked_until`, `lock_reason`). Values are truncated to 500 characters. This prevents log injection via user-controlled email addresses.
- The `unlockAccount` function returns 404 for all not-found cases — it does not distinguish between "no lockout exists" and "identifier has no account." This prevents enumeration of valid identifiers via the admin unlock API.
- GDPR Article 17 (right to erasure): when a CIAM identity is deleted, the associated `ciam_login_attempts` and `ciam_lockouts` rows must be deleted as well. This is tracked in platform#56 and is not yet implemented in the current release.
