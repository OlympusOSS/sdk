# SDK Encryption — Internals and Operations

**Ticket**: sdk#5
**Last updated**: 2026-04-08

## Upgrading to SDK >= 1.0.41

If you are upgrading from SDK < 1.0.41, complete these steps in order:

1. **Generate a production-grade key** (if not already done):
   ```bash
   openssl rand -base64 32
   ```
   Ensure `ENCRYPTION_KEY` is at least 32 bytes. Store it in your GitHub Secret, not in source control.

2. **Add `validateOnStartup()` to your service entry point**:
   ```typescript
   import { validateOnStartup } from "@olympusoss/sdk";
   validateOnStartup(); // synchronous — throws on failure
   ```
   In Next.js apps (Athena, Hera), this goes in `src/instrumentation.ts` under a `NEXT_RUNTIME === 'nodejs'` guard.

3. **Run the migration script** (if you have existing encrypted settings):
   ```bash
   DATABASE_URL=postgres://... ENCRYPTION_KEY=<key> bun run src/migrate-encryption-key.ts
   ```
   Skip this step if your database has no encrypted rows (fresh install). See [Migration Runbook](#migration-runbook-sdk--1041-upgrade) for details.

4. **Co-deploy with athena#99** (if applicable): Set `SESSION_SIGNING_KEY` in all Athena containers. `ENCRYPTION_KEY` and `SESSION_SIGNING_KEY` must be different values.

## Overview

The SDK encrypts sensitive settings values (API keys, secrets, credentials) using AES-256-GCM with HKDF-SHA-256 key derivation. This document covers the cryptographic design, ciphertext versioning, startup validation behavior, and the migration procedure for upgrading from the legacy SHA-256-derived key.

## How It Works

### Key Derivation

The AES-256 encryption key is derived from `ENCRYPTION_KEY` using HKDF-SHA-256:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Algorithm | HKDF-SHA-256 | Key stretching with domain separation |
| IKM | Raw bytes of `ENCRYPTION_KEY` | Input key material |
| Salt | Absent (zero-length) | Correct when IKM is uniformly random — HKDF with random IKM and no salt is cryptographically sound |
| Info | `'olympus-settings-aes-256-gcm'` | Domain separation — ensures this derived key is distinct from any other key derived from the same IKM |
| Output length | 32 bytes | AES-256 key size |

**Why not bare SHA-256?** SHA-256 provides no key stretching. A low-entropy `ENCRYPTION_KEY` maps directly to a predictable AES key, making offline dictionary attacks against leaked ciphertext computationally trivial. HKDF applies proper key derivation so the derived AES key has full 256-bit strength regardless of the input key's character distribution.

**Why absent salt?** When the IKM is uniformly random (produced by `openssl rand -base64 32`), an absent salt is the correct choice. A fixed constant string as salt adds no security and misleadingly implies false entropy. The HKDF spec allows absent salt for uniformly-random IKM.

### Encryption

Each encrypt operation:
1. Generates a fresh 12-byte random IV
2. Encrypts with AES-256-GCM (authentication tag included)
3. Prepends the `v2:` version prefix
4. Returns: `v2:<ivBase64>:<authTagBase64>:<ciphertextBase64>`

### Key Separation

`ENCRYPTION_KEY` is used **exclusively** for AES-256-GCM encryption of settings values. HMAC signing of Athena admin session cookies uses a separate `SESSION_SIGNING_KEY` environment variable (tracked in athena#99). These two operations must never share a key.

| Operation | Key Variable | Location |
|-----------|-------------|----------|
| AES-256-GCM settings encryption | `ENCRYPTION_KEY` | SDK (`crypto.ts`) |
| HMAC-SHA-256 session cookie signing | `SESSION_SIGNING_KEY` | Athena (`src/lib/session.ts`) |

## Ciphertext Versioning

The SDK uses a version prefix on all stored ciphertext to enable zero-downtime migration between key derivation schemes.

| Prefix | Key Derivation | Status | Notes |
|--------|---------------|--------|-------|
| None (no prefix) | Bare SHA-256 | Legacy — SDK < 1.0.41 | Must be migrated; the SDK does not decrypt these values without migration |
| `v2:` | HKDF-SHA-256 | Current | All new encryptions use this prefix |

**If you see `v2:` values in the database**: this is correct. All encrypted settings rows produced by SDK >= 1.0.41 carry the `v2:` prefix.

**If you see rows without a prefix**: these are legacy ciphertext produced by SDK < 1.0.41. They must be migrated before upgrading the SDK. See the migration runbook below.

Future format changes will increment the prefix (`v3:`, etc.). The SDK reads the prefix to select the correct decryption path automatically.

## Startup Validation

The SDK validates `ENCRYPTION_KEY` at import time via the barrel (`index.ts`). Validation runs before any settings are read or written.

### Validation Checks

Two checks run in sequence:

1. **Presence check** (all environments): `ENCRYPTION_KEY` must be set
2. **Byte-length check** (all environments): the raw key must be at least 32 bytes
3. **Blocklist check** (production only — `NODE_ENV=production`): the key must not match any entry in the known-bad-keys list

If any check fails, the SDK throws immediately with a message naming the specific check:

```
EncryptionKeyError: ENCRYPTION_KEY failed byte-length check: expected >= 32 bytes, got 16
EncryptionKeyError: ENCRYPTION_KEY is a known development placeholder and cannot be used in production
```

### NODE_ENV Behavior

| Environment | Presence check | Byte-length check | Blocklist check |
|-------------|---------------|------------------|-----------------|
| Development (`NODE_ENV != production`) | Runs | Runs | **Skipped** |
| Production (`NODE_ENV=production`) | Runs | Runs | Runs |

In development, only byte-length validation runs. This means a weak dev key (e.g., 32 `a` characters) passes in dev but would pass in production too unless it is on the blocklist. Always test with a production-equivalent key before deployment.

### Known Limitation

The startup validation cannot detect a 32-byte key with zero randomness entropy (e.g., 32 identical characters) unless it is on the blocklist. This is an accepted limitation — the mitigation is using `openssl rand -base64 32` to generate keys. Do not rely on the startup validation as a substitute for proper key generation.

### Blocklist Maintenance

The canonical list of known-bad dev keys lives in `sdk/src/blocklist.ts`. When a new key is committed to any Olympus repo seed, example, or config file, it must be added to `blocklist.ts` in the same PR or a linked follow-on issue. This is enforced by code review convention.

### Validation Scope Limitation

The entropy check fires only when the SDK is imported via the barrel (`index.ts`). A consumer that imports `sdk/src/crypto.ts` directly bypasses the check. All current Olympus consumers (Athena, Hera, Site) import via the barrel. Future consumers importing crypto utilities directly must implement their own validation or import via the barrel.

## Startup Validation — `validateOnStartup()`

Call `validateOnStartup()` at the entry point of every service that imports `@olympusoss/sdk`. It runs all three validation checks (presence, byte-length, blocklist) and throws immediately with a descriptive error if any check fails. The service does not start with a misconfigured key.

```typescript
import { validateOnStartup } from "@olympusoss/sdk";

// In your service entry (e.g., server.ts, app.ts) — before any other SDK calls:
validateOnStartup();
```

`validateOnStartup()` is synchronous. It returns `void` and throws on failure. No `await` needed.

### Error shapes

Every validation error follows the `{ code, message, suggestion }` format. The `suggestion` field contains the exact command to fix the problem — no documentation lookup required.

| Code | Cause | Suggestion |
|------|-------|-----------|
| `ENCRYPTION_KEY_ABSENT` | `ENCRYPTION_KEY` env var is not set | `Generate a key: openssl rand -base64 32` |
| `ENCRYPTION_KEY_WEAK` | Key is shorter than 32 bytes | `Generate a key: openssl rand -base64 32` |
| `ENCRYPTION_KEY_BLOCKLISTED` | Key matches a known development placeholder | `Generate a unique key: openssl rand -base64 32` |

Example thrown error:

```
EncryptionKeyError: ENCRYPTION_KEY is not set.
  code: ENCRYPTION_KEY_ABSENT
  suggestion: Generate a key: openssl rand -base64 32 (Unix) or node -e "require('crypto').randomBytes(32).toString('base64')" (Windows)
```

The SDK throws on any validation failure. The service must not catch and suppress this error — allow it to propagate and crash the startup process.

## Generating a Key

**Unix / macOS / Linux:**

```bash
openssl rand -base64 32
```

**Windows (PowerShell):**

```powershell
node -e "require('crypto').randomBytes(32).toString('base64')"
```

Both commands produce 256 bits of cryptographically random key material encoded as base64 (44 characters, 32 bytes when decoded).

**Shell quoting**: base64 output may contain `+`, `/`, and `=` characters. Always quote the value when setting it as an environment variable to prevent shell interpolation:

```bash
export ENCRYPTION_KEY="GK7s39Oa7613mZvjSvUZuBdZvo3wfTOig2ms/KRLtcg="
```

Without quotes, a `+` or `/` in the key value will be interpreted by the shell and produce a different value than intended.

**Critical rules:**
- Never reuse a key from dev seed files, example configs, or repository history in production
- Never commit the production `ENCRYPTION_KEY` to source control
- Store the output directly in the GitHub Secret (`ENCRYPTION_KEY`) for production, or in `platform/dev/.env` for local development
- The key must be set in every container that imports `@olympusoss/sdk`

## Migration Runbook (SDK < 1.0.41 Upgrade)

### When This Applies

This migration is required if any of the following are true:
- You are upgrading from SDK < 1.0.41 to SDK >= 1.0.41
- The `ciam_settings` or `iam_settings` tables contain rows where `encrypted = true` and the `value` column does NOT start with `v2:`

If your database has no encrypted settings rows (fresh install, or no encrypted values ever stored), migration is not required.

### Before You Start

1. **Back up the database**:
   ```bash
   pg_dump -h localhost -p 5432 -U postgres olympus > olympus_backup_$(date +%Y%m%d_%H%M%S).sql
   ```

2. **Verify encrypted rows exist** (determines whether migration is necessary):
   ```sql
   SELECT COUNT(*) FROM ciam_settings WHERE encrypted = true AND value NOT LIKE 'v2:%';
   SELECT COUNT(*) FROM iam_settings WHERE encrypted = true AND value NOT LIKE 'v2:%';
   ```
   If both counts are 0, skip the migration.

3. **Plan a maintenance window** or run during a zero-traffic period. The migration is fast (typically seconds for a small settings table), but encrypted values are briefly unreadable mid-migration if the SDK is updated before migration completes.

### Running the Migration

```bash
DATABASE_URL=postgres://postgres@localhost:5432/olympus \
ENCRYPTION_KEY=<your-production-key> \
bun run src/migrate-encryption-key.ts
```

The script:
1. Reads all rows from `ciam_settings` and `iam_settings` where `encrypted = true`
2. Decrypts each value using the legacy SHA-256-derived key
3. Re-encrypts each value using the new HKDF-derived key
4. Writes the updated `v2:`-prefixed ciphertext back to the database

### Verifying Migration Success

After the script completes, confirm all encrypted rows carry the `v2:` prefix:

```sql
SELECT COUNT(*) FROM ciam_settings WHERE encrypted = true AND value NOT LIKE 'v2:%';
SELECT COUNT(*) FROM iam_settings WHERE encrypted = true AND value NOT LIKE 'v2:%';
```

Both counts must be 0. If any rows remain without a `v2:` prefix, re-run the migration script (it is idempotent — rows already at `v2:` are skipped automatically).

### Idempotency

The migration script is safe to re-run. Rows already carrying the `v2:` prefix are skipped. You can run it multiple times without duplicating or corrupting data.

### Deployment Sequence (sdk#5 + athena#99 atomic delivery)

sdk#5 and athena#99 (`SESSION_SIGNING_KEY` in Athena `session.ts`) must deploy in the same release. The correct sequence is:

1. Run the migration script against the production database (before deploying new containers)
2. Deploy SDK changes (HKDF key derivation, startup validation)
3. Deploy Athena changes (new `SESSION_SIGNING_KEY` env var)
4. Confirm both `ENCRYPTION_KEY` and `SESSION_SIGNING_KEY` are set in all container environments

**Transition window**: Between steps 2 and 3, Athena still derives its HMAC session signing key from `ENCRYPTION_KEY`. This is not a regression — it is the same as the pre-deployment state. The transition window is the deployment gap (minutes in a standard pipeline run).

**Rollback**: If either deployment fails, existing sessions (signed with `ENCRYPTION_KEY`-derived HMAC) remain valid under rollback. The migration script is the only irreversible step — if it has run, ciphertext is re-encrypted with the HKDF-derived key. Rolling back the SDK code would leave the database with `v2:`-prefixed ciphertext that the legacy code cannot decrypt. The safest rollback path is to restore from the backup taken in step 1.

## API / Technical Details

### `encrypt(value: string): string`

Returns AES-256-GCM ciphertext with `v2:` prefix. Returns `""` for empty input without encrypting.

```typescript
import { encrypt } from "@olympusoss/sdk";

const ciphertext = encrypt("my-api-key");
// Returns: "v2:abc...base64..."
```

**Important**: `encrypt("")` returns `""`. Never store an empty string as an encrypted value — validate at the call site before encrypting.

### `decrypt(ciphertext: string): string`

Decrypts a `v2:`-prefixed ciphertext. Returns `""` for empty input.

```typescript
import { decrypt } from "@olympusoss/sdk";

const plaintext = decrypt("v2:abc...base64...");
```

If the ciphertext format is unrecognized (no recognized version prefix), `decrypt()` returns the value as-is — plaintext passthrough for backward compatibility with unencrypted values stored before encryption was introduced. It does not throw.

Throws if:
- Authentication tag verification fails (ciphertext was tampered)
- The key was rotated without running the migration script (mismatch between stored ciphertext and current key)

### `isEncryptedFormat(value: string): boolean`

Returns `true` if the value is in a recognized encrypted format (`v2:` prefix or legacy three-part colon format). Use this to distinguish encrypted values from plaintext values stored before encryption was introduced.

```typescript
import { isEncryptedFormat } from "@olympusoss/sdk";

isEncryptedFormat("v2:abc:def:ghi"); // true
isEncryptedFormat("plaintext-value"); // false
```

Do not re-implement format detection in calling code — use this function.

## Analytics Events

The SDK emits structured analytics events to `process.stdout` on every startup. These events are ingested by the platform log aggregation pipeline and are available for Loki LogQL queries and Athena dashboards.

### Delivery Mechanism

All events are emitted as a single JSON line to `process.stdout`:

```
{"type":"analytics","event":"sdk.startup.succeeded","env":"production","key_length_bytes":44,"timestamp":"2026-04-06T00:00:00.000Z"}
```

The `type: "analytics"` discriminator aligns with the platform-wide convention (Hera uses the same field and stream for its analytics events). The delivery path uses `process.stdout.write` directly — it has zero dependency on SDK initialization completing, so events fire even when startup fails and throws.

Emission errors are swallowed — analytics failure cannot crash the startup path. The function is internal to the SDK startup path and is not part of the public API.

### Event Schema

| Event | `type` | Properties | Stream | When |
|-------|--------|------------|--------|------|
| `sdk.startup.succeeded` | `analytics` | `env`, `key_length_bytes`, `timestamp` | stdout | All validation checks pass |
| `sdk.startup.failed` | `analytics` | `env`, `tier` (1/2/3), `reason` (`key_missing` / `key_too_short` / `key_blocklisted`), `timestamp` | stdout | Any validation failure |
| `platform.key.weak` | `analytics` | `env`, `tier` (3), `timestamp` | stdout | Blocklisted key in production only — emitted alongside `sdk.startup.failed` tier 3 |

### Startup Validation Funnel

```
Tier 1: ENCRYPTION_KEY present?   FAIL → sdk.startup.failed { tier: 1, reason: "key_missing" }  → throw
Tier 2: Key >= 32 bytes?           FAIL → sdk.startup.failed { tier: 2, reason: "key_too_short" } → throw
Tier 3: Not in blocklist? (prod)   FAIL → sdk.startup.failed { tier: 3, reason: "key_blocklisted" }
                                        + platform.key.weak  { tier: 3 }                          → throw
PASS  → sdk.startup.succeeded { env, key_length_bytes }
```

`platform.key.weak` is exclusive to Tier 3. Tier 1 and Tier 2 failures emit only `sdk.startup.failed`.

### Event Properties

| Property | Type | Present on | Description |
|----------|------|------------|-------------|
| `type` | string | All events | Always `"analytics"` — discriminator for log pipeline filtering |
| `event` | string | All events | Event name (e.g., `sdk.startup.succeeded`) |
| `env` | string | All events | Value of `process.env.NODE_ENV` at startup; `"unknown"` if unset |
| `key_length_bytes` | number | `sdk.startup.succeeded` | Byte length of the raw `ENCRYPTION_KEY` string — not binary decoded length, not key content |
| `tier` | number | `sdk.startup.failed`, `platform.key.weak` | Tier that failed: 1 (missing), 2 (short), 3 (blocklisted) |
| `reason` | string | `sdk.startup.failed` | Machine-readable rejection reason: `key_missing`, `key_too_short`, or `key_blocklisted` |
| `timestamp` | string | All events | ISO 8601 timestamp of emission |

No key material appears in any event payload or error messages. `key_length_bytes` is a byte count. `reason` is a string constant. Error messages never include key substrings or any key material.

### Loki LogQL Filtering

Filter SDK startup analytics events:

```logql
{job="sdk"} | json | type="analytics" | event="sdk.startup.succeeded"
```

Alert on production blocklist hit:

```logql
{job="sdk"} | json | type="analytics" | event="platform.key.weak" | env="production"
```

The `env` field is set at emit time from `process.env.NODE_ENV` — apply `NODE_ENV` filtering at the log aggregation layer to separate production signals from development noise.

### Future-State Events

The following events are defined in the analytics plan but are not yet emitted. They require additional infrastructure before they can be instrumented:

| Event | Blocked on |
|-------|-----------|
| `sdk.key.rotated` | Persistent key fingerprint storage (`sdk_key_metadata` table, tracked as [AN-7]) |
| `sdk.crypto.migrated` | Migration script instrumentation ([AN-2]) |
| `sdk.decrypt.failed` | Runtime decryption failure tracking in `crypto.ts` ([AN-3]) |

### Testing the Analytics Events

The analytics instrumentation is covered by `sdk/src/analytics.test.ts`. Tests use `Bun.spawnSync` subprocess isolation — each test spawns a fresh Bun process with controlled environment variables to avoid module cache collisions with the IIFE in `index.ts`.

Run the analytics test suite from the SDK project root:

```bash
bun test src/analytics.test.ts
```

The test file must be run from the SDK project root because the inline subprocess scripts import from `./src/index.ts` using a relative path.

Two test suites:

- **Suite 1 — try/catch safety**: verifies that `process.stdout.write` failures are swallowed and do not crash startup; confirms validation throws still fire correctly even when the analytics path fails internally
- **Suite 2 — `sdk.startup.succeeded` event schema**: verifies all required properties are present (`type`, `event`, `env`, `key_length_bytes`, `timestamp`), that `key_length_bytes` is a number and not key content, that no key material appears in the payload, and that `env` reflects `NODE_ENV`

## Security Considerations

- **Key rotation requires migration**: changing `ENCRYPTION_KEY` in production without running the migration script will cause decryption failures for all encrypted settings. Plan key rotation with the migration step.
- **The `v2:` prefix is not secret**: it indicates key derivation method, not the key value itself. Do not treat it as sensitive.
- **AES-GCM authentication**: the authentication tag in each ciphertext detects tampering. A modified ciphertext causes `decrypt()` to throw — it does not silently return corrupted plaintext.
- **Session and settings keys must differ**: using the same key for both AES encryption (SDK) and HMAC session signing (Athena) means a leak of either affects both. The separation into `ENCRYPTION_KEY` and `SESSION_SIGNING_KEY` is a hard requirement, not a suggestion.

## References

- `sdk/src/crypto.ts` — HKDF key derivation and AES-256-GCM implementation
- `sdk/src/index.ts` — startup validation IIFE and `emitAnalyticsEvent()` helper
- `sdk/src/blocklist.ts` — canonical list of known-bad dev keys
- `sdk/src/migrate-encryption-key.ts` — one-time migration script
- `sdk/src/analytics.test.ts` — Bun test suite for startup analytics events
- `docs/state/analytics-sdk5.md` — full analytics plan (event schema, dashboards, instrumentation stories)
- sdk#5 — Origin ticket
- athena#99 — Linked cross-repo ticket (`SESSION_SIGNING_KEY` in Athena)
