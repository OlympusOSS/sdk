/**
 * Canonical blocklist of known-bad ENCRYPTION_KEY values.
 *
 * This file is the single source of truth for known dev/example/seed keys that
 * must never be used in production. When a new key is committed to any seed,
 * example, or config file in any Olympus repo, it must be added here in the same
 * PR or a linked follow-on issue.
 *
 * Maintenance process: code review enforced. Any PR adding a key to a seed or
 * example file must include a corresponding update here or link a follow-on issue.
 *
 * Limitation: this list cannot enumerate unknown weak keys. A key not on this list
 * but with zero randomness entropy (e.g., 32 identical characters) will not be
 * rejected by this check. The blocklist is a defence-in-depth layer — the primary
 * mitigation is using openssl rand -base64 32 to generate keys (see README).
 */
export const ENCRYPTION_KEY_BLOCKLIST: readonly string[] = [
	// platform/dev/compose.dev.yml — used in all dev containers
	"dev-encryption-key-minimum-32-chars!!",
];
