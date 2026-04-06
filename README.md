# @olympusoss/sdk

Shared settings, encryption, and database client for the Olympus platform. Consumed by Athena, Hera, and Site containers.

## Overview

The SDK provides persistent, admin-editable key-value configuration stored in the `olympus` PostgreSQL database. It handles:

- **Settings CRUD** — get, set, batch-set, delete, and list settings per domain (CIAM / IAM)
- **AES-256-GCM encryption** — transparent encrypt/decrypt for sensitive values (API keys, secrets)
- **In-memory TTL cache** — reduces database round-trips; 60s default TTL per key
- **Brute-force protection** — login attempt tracking, lockout management, audit logging (see [`docs/brute-force.md`](./docs/brute-force.md))
- **Session location tracking** — stores login locations per session for security displays

## Package Structure

```
sdk/src/
├── index.ts          # Barrel export — all public API
├── settings.ts       # Settings CRUD: get/set/batchSet/delete/list
├── crypto.ts         # AES-256-GCM encrypt/decrypt
├── cache.ts          # In-memory TTL cache (SettingsCache)
├── db.ts             # postgres.js connection pool, auto-migration, table helpers
├── locations.ts      # Session location tracking
└── brute-force.ts    # Login attempt tracking, lockout, audit log
```

## Environment Variables

Every container that imports `@olympusoss/sdk` must set:

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | Connection string for the `olympus` PostgreSQL database |
| `SETTINGS_TABLE` | Yes | Table name: `ciam_settings` (CIAM domain) or `iam_settings` (IAM domain) |
| `ENCRYPTION_KEY` | Yes | AES-256-GCM key material (minimum 32 bytes) for encrypting secret values |

### Generating ENCRYPTION_KEY

Generate a cryptographically random key for production deployments:

```bash
openssl rand -base64 32
```

This produces 256 bits of random key material encoded as base64 (44 characters, 32+ bytes when decoded). Store the output as `ENCRYPTION_KEY`.

**Critical security rules:**
- Never reuse a key from dev seed files, example configs, or repository history in production. Any key committed to source control — including `dev-encryption-key-minimum-32-chars!!` — is a known-bad value and will be rejected by the SDK startup validation in production (`NODE_ENV=production`).
- Never commit the production `ENCRYPTION_KEY` to source control.
- Rotate the key by running the migration script before redeploying with a new key.

### Startup Entropy Validation

The SDK validates `ENCRYPTION_KEY` at import time (via the barrel `index.ts`):

1. **Presence check** (all environments): key must be set.
2. **Byte-length check** (all environments): raw key must be at least 32 bytes.
3. **Blocklist check** (production only, `NODE_ENV=production`): key must not match a known dev/example default.

If any check fails, the SDK throws immediately and the application does not start. The error message names the specific check that failed.

**Known limitation**: the startup validation cannot detect a 32-byte key with zero randomness entropy (e.g., 32 identical characters) unless it is on the blocklist. This is an accepted limitation — the mitigation is using `openssl rand -base64 32` to generate keys.

**Scope limitation**: the entropy check fires only when the SDK is imported via the barrel (`index.ts`). A consumer that imports `sdk/src/crypto.ts` directly — bypassing the barrel — does not get the entropy check. All current Olympus consumers (Athena, Hera, Site) import via the barrel. Future consumers importing crypto utilities directly must implement their own validation or use the barrel.

### Blocklist Maintenance

The canonical blocklist of known-bad dev keys lives in `sdk/src/blocklist.ts`. When a new key is committed to any Olympus repo seed, example, or config file, it must be added to `blocklist.ts` in the same PR or a linked follow-on issue. Enforcement is by code review convention.

## Setup

SDK is mounted into dev containers via Podman volume at startup:

```yaml
volumes:
  - ../../sdk:/sdk
command: ["sh", "-c", "cd /sdk && bun install; ln -s /sdk node_modules/@olympusoss/sdk && bun run dev"]
```

Production containers pull the published `@olympusoss/sdk` package from GitHub Packages.

Tables are created automatically on first SDK use (`CREATE TABLE IF NOT EXISTS`) — no manual migration step required.

## Settings API

See [`docs/settings-api.md`](./docs/settings-api.md) for the full reference. Quick summary:

### Reading Settings

```typescript
import { getSetting, getSettingOrDefault, getSecretSetting } from "@olympusoss/sdk";

// Returns Setting | null (full object including metadata)
const setting = await getSetting("captcha.enabled");

// Returns string — most common pattern for simple feature flags
const enabled = await getSettingOrDefault("captcha.enabled", "false");

// Returns decrypted plaintext for encrypted secrets
const apiKey = await getSecretSetting("recaptcha.secret_key");
```

### Writing a Single Setting

```typescript
import { setSetting } from "@olympusoss/sdk";

await setSetting("captcha.enabled", "true", { category: "captcha" });
await setSetting("smtp.password", "s3cr3t", { encrypted: true, category: "email" });
```

### Writing Multiple Settings Atomically

Use `batchSetSettings()` when multiple keys must commit together or not at all. A failed write rolls back all entries — no partial state is possible.

```typescript
import { batchSetSettings } from "@olympusoss/sdk";

// MFA policy — all 4 keys must be consistent
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

See [batchSetSettings() documentation](./docs/settings-api.md#batchsetsettings--atomic-multi-key-write) for transaction semantics, cache behavior, error handling, and known limitations.

### Vault Fallback Pattern

SDK value takes priority; env var serves as the fallback for zero-downtime migration:

```typescript
import { getSettingOrDefault } from "@olympusoss/sdk";

const clientId = await getSettingOrDefault(
  "oauth.client_id",
  process.env.OAUTH_CLIENT_ID || ""
);
```

## Encryption

`encrypt(value)` and `decrypt(ciphertext)` use AES-256-GCM with HKDF-SHA-256 key derivation.

```typescript
import { encrypt, decrypt } from "@olympusoss/sdk";

const ciphertext = encrypt("secret-value");
const plaintext  = decrypt(ciphertext);
```

**Key derivation**: The AES-256 key is derived from `ENCRYPTION_KEY` using HKDF-SHA-256 with:
- IKM: raw bytes of `ENCRYPTION_KEY`
- Salt: absent (zero-length) — correct when IKM is uniformly random (`openssl rand -base64 32`)
- Info: `'olympus-settings-aes-256-gcm'` — domain separation, distinct from any other key derived from the same IKM
- Length: 32 bytes

**Ciphertext versioning**: New encryptions produce `v2:`-prefixed ciphertext (`v2:iv:authTag:data`). Legacy ciphertext (no prefix) from SDK < 1.0.41 is still decryptable — the runtime `decrypt()` detects the format and uses the appropriate key derivation path automatically.

**Key separation**: `ENCRYPTION_KEY` is used exclusively for AES-256-GCM encryption of settings values. HMAC signing of Athena admin session cookies uses a separate `SESSION_SIGNING_KEY` environment variable (see athena#99). These two operations must never share a key.

**Important**: `encrypt("")` returns `""` without performing encryption. Never pass empty strings as encrypted values — validate at the call site.

See [`docs/encryption.md`](./docs/encryption.md) for: cryptographic design details, ciphertext versioning table (`v2:` prefix), startup validation NODE_ENV behavior, blocklist maintenance, and the full migration runbook with pre-migration checklist.

### Upgrading from SDK < 1.0.41 (SHA-256 key derivation)

If you have existing encrypted settings in the `olympus` database, run the migration script before upgrading the SDK in production containers:

```bash
DATABASE_URL=... ENCRYPTION_KEY=... bun run src/migrate-encryption-key.ts
```

The migration script re-encrypts all encrypted rows using the new HKDF-derived key. It is idempotent — rows already carrying the `v2:` prefix are skipped. See `src/migrate-encryption-key.ts` for full details.

## Cache

Settings are cached in-process with a 60s default TTL. The cache is per-process — separate containers do not share it. After a write (`setSetting`, `batchSetSettings`), the relevant cache entries are invalidated immediately for the current process. Other containers may serve stale values for up to 60s.

For security-sensitive settings (e.g., `mfa.required`, `captcha.enabled`), design callers to tolerate this staleness window.

## Database

The SDK connects to the `olympus` PostgreSQL database — a separate database from the four Ory databases (`ciam_kratos`, `ciam_hydra`, `iam_kratos`, `iam_hydra`).

Tables created by the SDK:

| Table | Domain | Purpose |
|-------|--------|---------|
| `ciam_settings` | CIAM | Admin-editable settings for the CIAM domain |
| `iam_settings` | IAM | Admin-editable settings for the IAM domain |
| `ciam_login_attempts` | CIAM | Login attempt records for brute-force protection |
| `iam_login_attempts` | IAM | Login attempt records for brute-force protection |
| `ciam_lockouts` | CIAM | Active lockout records |
| `iam_lockouts` | IAM | Active lockout records |
| `ciam_security_audit` | CIAM | Security audit log entries |
| `iam_security_audit` | IAM | Security audit log entries |

All tables use `CREATE TABLE IF NOT EXISTS` — safe to call on every startup.

## Versioning

All Olympus repos follow unified versioning. Use `octl bump` to bump versions — never edit `package.json` version fields manually. See the workspace `CLAUDE.md` for the full versioning flow.

## Tests

```bash
bun test
```

Tests are colocated with source files (`*.test.ts`). All tests mock the database, crypto, and cache modules.

To run only the analytics instrumentation tests:

```bash
bun test sdk/src/analytics.test.ts
```

This suite uses `Bun.spawnSync` subprocess isolation and must be run from the SDK project root. It covers the `emitAnalyticsEvent()` try/catch safety guarantee and the `sdk.startup.succeeded` event schema. See [`docs/encryption.md`](./docs/encryption.md#testing-the-analytics-events) for details.
