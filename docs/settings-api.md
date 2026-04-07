# Settings API

## Overview

The `@olympusoss/sdk` settings API provides persistent, admin-editable key-value configuration stored in the `olympus` PostgreSQL database. Settings support optional AES-256-GCM encryption for sensitive values and are cached in-process to minimize database queries.

## How It Works

Settings are stored in the `ciam_settings` or `iam_settings` table (determined by the `SETTINGS_TABLE` environment variable). The SDK exposes four operations: get, set, delete, and list. A TTL-based in-memory cache reduces round-trips to the database.

### getSetting() — Single Key Fetch

`getSetting(key)` issues a single-row `SELECT` against the settings table and returns the full `Setting` object or `null` if the key does not exist. The result is cached in-process.

```
SELECT key, value, encrypted, category, updated_at FROM <table> WHERE key = $1
```

The cache stores `Setting | null` per key. On a cache hit, no database query is issued.

### getSettingOrDefault() — String Value with Fallback

`getSettingOrDefault(key, fallback)` calls `getSetting(key)` internally and returns the `.value` field as a plain string, or `fallback` if the key does not exist. Its return type is `Promise<string>` — it never returns a `Setting` object.

This is the function used by the majority of callers in Athena and Hera. Its string return type is preserved across SDK versions.

### listSettings() — Full Table Scan

`listSettings()` returns all settings as `Setting[]`. This is appropriate for admin panel listing and is NOT used for individual key lookups.

## API / Technical Details

### Setting Interface

```typescript
interface Setting {
  key: string
  value: string
  encrypted: boolean
  category: string | null
  updated_at: Date
}
```

### Functions

| Function | Signature | Returns | DB Query |
|----------|-----------|---------|----------|
| `getSetting` | `(key: string) => Promise<Setting \| null>` | Full Setting object or null | Single-row SELECT |
| `getSettingOrDefault` | `(key: string, fallback: string) => Promise<string>` | `.value` string or fallback | Single-row SELECT (via getSetting) |
| `getSecretSetting` | `(key: string) => Promise<string \| null>` | Decrypted value or null | Single-row SELECT + AES-256-GCM decrypt |
| `setSetting` | `(key: string, value: string, opts?) => Promise<void>` | void | INSERT or UPDATE |
| `batchSetSettings` | `(entries: BatchSettingEntry[], table: string) => Promise<void>` | void | Transaction: N upserts |
| `deleteSetting` | `(key: string) => Promise<void>` | void | DELETE |
| `listSettings` | `() => Promise<Setting[]>` | All settings | Full table SELECT |

### BatchSettingEntry Interface

```typescript
interface BatchSettingEntry {
  key: string
  value: string
  encrypted?: boolean   // default: false
  category?: string     // default: "general"
}
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | Connection string for the `olympus` PostgreSQL database |
| `SETTINGS_TABLE` | Yes | Table name: `ciam_settings` or `iam_settings` |
| `ENCRYPTION_KEY` | Yes | AES-256-GCM key (32-byte hex) for encrypting secret values |

### Cache Behavior

- Cache is in-process only — not shared between containers
- Cache stores `Setting | null` per key (full object, not just value string)
- Default TTL: 60 seconds
- Only `getSetting()` reads and writes the cache
- `getSettingOrDefault()` calls `getSetting()` and extracts `.value` — it never accesses the cache directly
- `listSettings()` does not use the cache — it always reads from the database

## Examples

### Reading a single setting

```typescript
import { getSetting } from "@olympusoss/sdk";

const setting = await getSetting("captcha.enabled");
if (setting === null) {
  // Key does not exist
}
// setting.key === "captcha.enabled"
// setting.value === "true"
// setting.encrypted === false
// setting.category === "captcha"
// setting.updated_at instanceof Date
```

### Reading with a string fallback (most common pattern)

```typescript
import { getSettingOrDefault } from "@olympusoss/sdk";

// Returns a string — never a Setting object
const enabled = await getSettingOrDefault("captcha.enabled", "false");
const siteKey = await getSettingOrDefault("captcha.site_key", process.env.CAPTCHA_SITE_KEY || "");
```

### Vault fallback pattern — SDK value takes priority over env var

```typescript
import { getSettingOrDefault } from "@olympusoss/sdk";

const clientId = await getSettingOrDefault(
  "oauth.client_id",
  process.env.OAUTH_CLIENT_ID || ""
);
```

### Writing a setting

```typescript
import { setSetting } from "@olympusoss/sdk";

await setSetting("captcha.enabled", "true", { category: "captcha" });
await setSetting("smtp.password", "secret", { encrypted: true, category: "email" });
```

### Writing multiple settings atomically

Use `batchSetSettings()` when multiple keys must succeed or fail together. All entries are written inside a single Postgres transaction — either all commit or none commit.

```typescript
import { batchSetSettings } from "@olympusoss/sdk";

await batchSetSettings(
  [
    { key: "mfa.required",           value: "true",    category: "mfa" },
    { key: "mfa.grace_period_days",  value: "7",       category: "mfa" },
    { key: "mfa.methods.totp",       value: "true",    category: "mfa" },
    { key: "mfa.methods.webauthn",   value: "false",   category: "mfa" },
  ],
  process.env.SETTINGS_TABLE!
);
```

This is the canonical pattern used by athena#48 (MFA Policy Settings Panel). See [batchSetSettings()](#batchsetsettings--atomic-multi-key-write) for full details.

### Reading an encrypted setting (decrypted)

```typescript
import { getSecretSetting } from "@olympusoss/sdk";

const smtpPassword = await getSecretSetting("smtp.password");
// Returns decrypted plaintext or null if key not found
```

## batchSetSettings() — Atomic Multi-Key Write

### Overview

`batchSetSettings(entries, table)` writes multiple settings inside a single Postgres transaction. Either all entries commit or none do. Use this whenever two or more settings are interdependent and a partial write would leave the system in an inconsistent state.

The canonical consumer is athena#48 (MFA Policy Settings Panel), where keys like `mfa.required` and `mfa.methods.totp` must always be consistent — enabling MFA with no methods configured would lock out unenrolled users.

### Function Signature

```typescript
batchSetSettings(
  entries: BatchSettingEntry[],
  table: string
): Promise<void>
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `entries` | `BatchSettingEntry[]` | Array of settings to write. Empty array is a no-op. |
| `table` | `string` | Settings table name: `ciam_settings` or `iam_settings`. Must match `^[a-z_]+$` — pass `process.env.SETTINGS_TABLE`. |

### How It Works

1. If `entries` is empty, the function returns immediately with no database interaction.
2. The `table` parameter is validated against `^[a-z_]+$`. An invalid name throws before any database call.
3. For each entry with `encrypted: true`, the value is encrypted with AES-256-GCM via `crypto.ts encrypt()` before the upsert.
4. All upserts run sequentially inside a single `sql.begin()` transaction. If any upsert throws, the entire transaction rolls back and no rows are committed.
5. After a successful commit, cache entries for all written keys are invalidated.

### Transaction Behavior

The transaction uses READ COMMITTED isolation (Postgres default). Concurrent calls to `batchSetSettings()` targeting overlapping keys will interleave at the row level — `ON CONFLICT DO UPDATE` serializes individual row writes, but there is no cross-call ordering guarantee across concurrent transactions. If two admin sessions save overlapping keys simultaneously, the committed state may contain keys from both sessions. For the MFA policy use case, this window is narrow and acceptable. Callers requiring strict last-write-wins ordering across concurrent batch operations must coordinate at the application layer (e.g., a serialized queue or distributed lock).

### Cache Behavior

Cache entries for all written keys are invalidated only after a successful commit. On transaction rollback, the cache is not modified — stale cache is only cleared when the underlying data is confirmed committed to Postgres.

Other SDK consumers in separate processes share no in-memory cache, so they may serve stale values for up to the TTL window (default 60s) after a successful commit. Security-sensitive settings (e.g., `mfa.required` set to `false`) may continue to be read as their prior value for up to 60s in other processes. Design callers of security-critical settings with this window in mind.

### Usage — MFA Policy (Canonical Pattern)

```typescript
import { batchSetSettings } from "@olympusoss/sdk";

// Canonical MFA policy keys — used by athena#48
await batchSetSettings(
  [
    { key: "mfa.required",          value: "true",  category: "mfa" },
    { key: "mfa.grace_period_days", value: "7",     category: "mfa" },
    { key: "mfa.methods.totp",      value: "true",  category: "mfa" },
    { key: "mfa.methods.webauthn",  value: "false", category: "mfa" },
  ],
  process.env.SETTINGS_TABLE!
);
```

### Usage — Mixed Encrypted and Plain Entries

```typescript
import { batchSetSettings } from "@olympusoss/sdk";

await batchSetSettings(
  [
    { key: "smtp.host",     value: "mail.example.com",    category: "email" },
    { key: "smtp.port",     value: "587",                  category: "email" },
    { key: "smtp.password", value: "secret",               category: "email", encrypted: true },
  ],
  process.env.SETTINGS_TABLE!
);
```

Each entry carries its own `encrypted` flag. A batch can contain a mix of plaintext and encrypted entries.

### Error Handling

```
Error: batchSetSettings failed — transaction rolled back: <postgres error>
```

On any failure, the function throws with a descriptive message identifying the function, the consequence (rolled back), and the upstream error. No partial write is possible — if this error is thrown, zero rows were committed.

```
Error: Invalid table name: <table>
```

Thrown synchronously before any database interaction if the `table` parameter does not match `^[a-z_]+$`.

### When to Use batchSetSettings() vs setSetting()

| Scenario | Use |
|----------|-----|
| Single key update | `setSetting()` |
| Multiple independent keys | Multiple `setSetting()` calls (simpler) |
| Multiple interdependent keys that must be consistent | `batchSetSettings()` |
| MFA policy (4 keys must match at all times) | `batchSetSettings()` |
| Any write where partial failure is unacceptable | `batchSetSettings()` |

### Known Limitations

- **Empty-value encryption bypass**: Entries with `encrypted: true` and `value: ""` store an empty string without performing encryption. `crypto.ts encrypt()` returns `""` for empty input. Always ensure encrypted entries have non-empty values before calling `batchSetSettings()`.
- **No upper bound on batch size**: No maximum is enforced at the SDK layer. For the current use case (MFA policy: 4 keys), this is not a concern. If any call site can produce batches exceeding 20 entries, add an upper bound guard at the call site.
- **Sequential upserts**: Entries are written sequentially inside the transaction, not as a bulk UNNEST. This is appropriate for small batches (under 50 keys). For large batches, a UNNEST-based approach would be more efficient.

## Edge Cases

### Key not found

`getSetting()` returns `null`. `getSettingOrDefault()` returns the fallback string. Neither throws.

### Encrypted value without decrypt

When `getSetting()` is called for an encrypted key, `setting.value` contains the ciphertext and `setting.encrypted` is `true`. Use `getSecretSetting()` to receive the decrypted plaintext.

### Cache miss returning null

`null` is cached per key. A second call for a non-existent key returns `null` from cache without a database query. Cache invalidation occurs at TTL expiry.

### Concurrent getSetting() calls before cache is populated

Two simultaneous cache misses both query the database. Both return the same `Setting`. The second cache write is idempotent — no data corruption.

### getSettingOrDefault() callers after getSetting() return type change

`getSettingOrDefault()` always returns `Promise<string>`. Callers that use `getSettingOrDefault()` are unaffected by any changes to the underlying `getSetting()` return shape, because `getSettingOrDefault()` unwraps `.value` internally before returning.

## Security Considerations

- Encrypted values (where `encrypted: true`) are stored as AES-256-GCM ciphertext in the database. The `ENCRYPTION_KEY` environment variable must be set and must not be committed to source control.
- `getSetting()` does NOT decrypt encrypted values. Use `getSecretSetting()` when the decrypted value is needed.
- The `encrypted` boolean field in the `Setting` object tells consumers whether the stored value is ciphertext. API consumers must check this field before interpreting the value.
- `listSettings()` returns all rows including encrypted values as ciphertext — the API layer in Athena masks these before returning them to the client.
- The in-process cache stores the full `Setting` object including the ciphertext value for encrypted keys. This is acceptable because the cache is in-process memory — it is not serialized, persisted, or shared across containers.
- The `SettingsCache` class is not exported from `sdk/src/index.ts`. External code cannot access the cache directly.

### batchSetSettings() Security Notes

- The `table` parameter is validated with `^[a-z_]+$` before any SQL is constructed. Always pass `process.env.SETTINGS_TABLE` — do not construct table names dynamically from user input.
- Encryption is applied per-entry via AES-256-GCM using `crypto.ts`. Encryption errors inside the transaction cause a full rollback — no partial write is possible.
- The encryption key never appears in error messages. Errors from `batchSetSettings()` only surface the postgres.js message string.
- Entries with `encrypted: true` and an empty `value` (`""`) store an empty plaintext string — `encrypt()` returns `""` for empty input without performing encryption. Validate that all encrypted entries have non-empty values before calling this function.
- After commit, other SDK consumer processes (separate containers) may serve stale values for up to 60s (default TTL). For security-critical settings like `mfa.required`, design the calling flow to tolerate this staleness window.

### What NOT to do

- Do not call `listSettings()` when you only need a single key. Use `getSetting()` instead — it issues one SQL query instead of a full table scan.
- Do not log `Setting` objects that may contain sensitive values. Masked listing is the responsibility of the API layer.
- Do not use `getSetting()` as a substitute for `getSecretSetting()` when you need the decrypted plaintext of an encrypted key.
- Do not pass dynamically constructed table names to `batchSetSettings()`. Always use `process.env.SETTINGS_TABLE`.
- Do not call `batchSetSettings()` with `encrypted: true` entries that have empty string values — the value will be stored as plaintext empty string, not as encrypted ciphertext.
