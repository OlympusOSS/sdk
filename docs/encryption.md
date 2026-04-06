# SDK Encryption — Internals and Operations

**Ticket**: sdk#5
**Last updated**: 2026-04-06

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
4. Returns: `v2:<base64(IV + ciphertext + authTag)>`

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

## Generating a Key

Always use the following command to generate `ENCRYPTION_KEY`:

```bash
openssl rand -base64 32
```

This produces 256 bits of cryptographically random key material encoded as base64 (44 characters, 32 bytes when decoded).

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

Throws if:
- The ciphertext format is unrecognized
- Authentication tag verification fails (ciphertext was tampered)
- The key was rotated without running the migration script (mismatch between stored ciphertext and current key)

## Security Considerations

- **Key rotation requires migration**: changing `ENCRYPTION_KEY` in production without running the migration script will cause decryption failures for all encrypted settings. Plan key rotation with the migration step.
- **The `v2:` prefix is not secret**: it indicates key derivation method, not the key value itself. Do not treat it as sensitive.
- **AES-GCM authentication**: the authentication tag in each ciphertext detects tampering. A modified ciphertext causes `decrypt()` to throw — it does not silently return corrupted plaintext.
- **Session and settings keys must differ**: using the same key for both AES encryption (SDK) and HMAC session signing (Athena) means a leak of either affects both. The separation into `ENCRYPTION_KEY` and `SESSION_SIGNING_KEY` is a hard requirement, not a suggestion.

## References

- `sdk/src/crypto.ts` — HKDF key derivation and AES-256-GCM implementation
- `sdk/src/blocklist.ts` — canonical list of known-bad dev keys
- `sdk/src/migrate-encryption-key.ts` — one-time migration script
- sdk#5 — Origin ticket
- athena#99 — Linked cross-repo ticket (`SESSION_SIGNING_KEY` in Athena)
