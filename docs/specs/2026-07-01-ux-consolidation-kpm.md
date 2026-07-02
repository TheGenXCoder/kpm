# UX Consolidation — KPM Work Items

**Date:** 2026-07-01
**Owner:** Bert Smith
**Status:** Implemented (2026-07-01)
**Canonical record:** [agentkms/docs/design/2026-07-01-ux-consolidation.md](https://github.com/TheGenXCoder/agentkms/blob/main/docs/design/2026-07-01-ux-consolidation.md) — read that first; this doc scopes only the kpm side.

## Why (one paragraph)

Enrollment and remote selection have too many overlapping entry points (4 ways to pick a server, 4 ways to enroll, cert paths in user-visible config, multi-config-file sprawl). The features are fine; the UX fails the adoption test. This spec collapses the kpm side to: `kpm login <invitecode>` once per machine, one config file, `--dev` as the only escape hatch, local-first reads.

## Dependency

**Blocked on agentkms D1:** the new invite-code format (`kpmi1_` prefix, payload carrying `server_url`, `ca_fingerprint`, one-time `token`, `expires_at`) is minted server-side by `agentkms init --prod` / `agentkms invite <user>`. The local-first cache work (D5) is **not** blocked and can proceed in parallel.

## Work items

### K1 — `kpm login <invitecode>` (design record D3)

One command replaces enroll + init + hand-edited config:

1. Decode invite code → server URL, CA fingerprint, bootstrap token.
2. Fetch server CA over TLS; verify SHA-256 against the pinned fingerprint; reject on mismatch.
3. Generate ECDSA keypair locally; CSR with SPIFFE identity (existing `kpm enroll` flow — reuse it).
4. Receive device cert; store all cert material under `~/.kpm/identity/<server>/` (kpm-managed, never user-edited).
5. Write `~/.kpm/config.yaml` with this server as default remote — **no `cert:`/`key:`/`ca:` keys in the file**.

Invariant unchanged: private keys never leave the machine.

### K2 — Single config file (design record D4)

- `~/.kpm/config.yaml` is the only config, written by `login` (or `quickstart` for dev).
- `--dev` / `KPM_DEV=1` stays as "local store only, never touch hosted".
- Deprecate with warnings: `KPM_CONFIG=`, `config-<name>.yaml` selection, legacy `kpm enroll <url> --invite <token>`. Remove one release later.
- Multi-remote (`kpm remote add/use`) is deferred; the identity dir is already keyed by server so nothing precludes it.

### K3 — Local-first reads (design record D5)

Formalize `fallback:` + `mirror_to_fallback:` into first-class cache semantics:

- `kpm get`: local encrypted store first → pull + cache on miss or TTL expiry (default TTL 15 min, tunable).
- `kpm sync`: force full re-sync.
- `kpm add`: write to remote, mirror locally (current behavior kept).
- Cache encrypted at rest (key via OS keychain/keyring; Windows custody — DPAPI vs Credential Manager — is an open question).
- **`--strict` bypasses the cache entirely.** Strict mode's contract is "no key material on the client".

### Rejected: NRT push subscription (design record D6)

No server-push value updates. TTL + `kpm sync` covers rotation; `--strict` covers instant revocation. Revisit only on a concrete staleness incident.

## Migration

Open question in the canonical record: one-shot `kpm migrate` collapsing existing multi-config setups into the new layout, vs documented manual steps. Decide during K2.
