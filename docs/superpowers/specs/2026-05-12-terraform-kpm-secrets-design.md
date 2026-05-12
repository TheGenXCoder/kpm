# Terraform Provider for KPM — Design Spec

**Date:** 2026-05-12
**Status:** Approved for implementation
**Author:** Bert Smith (TheGenXCoder)

---

## Summary

Build a standalone Terraform provider (`terraform-provider-kpm`) that lets HCL code manage KPM secrets and GitHub App registrations as first-class Terraform resources. The provider speaks directly to the AgentKMS REST API over mTLS, reusing `pkg/tlsutil` from the KPM repo as a Go module dependency.

---

## Approach

**Approach A — Direct API client (import KPM packages as a Go module)**

The provider imports `github.com/TheGenXCoder/kpm/pkg/tlsutil` and calls the AgentKMS REST API directly over mTLS. No dependency on the `kpm` binary at runtime. This is how production-grade Terraform providers (Vault, Consul, etc.) are built. The KPM repo's existing `pkg/tlsutil` becomes a shared library consumed by both the CLI and the provider.

Alternatives considered and rejected:
- **Subprocess the `kpm` CLI** — brittle, requires binary on PATH, anti-pattern for production providers.
- **Extract a dedicated `kpmclient` library first** — correct long-term direction but premature for v1; can migrate later if the client interface stabilises.

---

## Repository

New standalone repo: `github.com/TheGenXCoder/terraform-provider-kpm`

Matches Terraform registry conventions. Published to the public registry as `registry.terraform.io/providers/catalyst9/kpm`. Versioned independently from the KPM CLI.

---

## Repository Structure

```
terraform-provider-kpm/
├── internal/
│   ├── provider/
│   │   └── provider.go          # provider block, Configure(), mTLS client init
│   ├── resources/
│   │   ├── secret.go            # kpm_secret resource (CRUD)
│   │   └── github_app.go        # kpm_github_app resource (CRUD)
│   └── datasources/
│       ├── secret.go            # kpm_secret data source (read)
│       └── credential.go        # kpm_credential data source (read)
├── internal/client/
│   └── agentkms.go              # thin HTTP client wrapping AgentKMS REST API
├── main.go                      # plugin entry point
└── go.mod                       # imports github.com/TheGenXCoder/kpm for pkg/tlsutil
```

The `internal/client` layer is the only place that touches the AgentKMS API. All resources and data sources call it exclusively — keeps provider logic decoupled from HTTP details and easy to test with a mock client.

---

## Provider Configuration

```hcl
provider "kpm" {
  server  = "https://agentkms.local:8443"
  cert    = "/path/to/client.crt"
  key     = "/path/to/client.key"
  ca_cert = "/path/to/ca.crt"
}
```

All four fields also accept environment variables — `KPM_SERVER`, `KPM_CERT`, `KPM_KEY`, `KPM_CA_CERT` — consistent with how the CLI reads them, so CI pipelines don't need provider blocks with hardcoded paths. Auth failures surface during provider `Configure()` before any resource operations are attempted.

Built with **Terraform Plugin Framework v2** (not the legacy SDKv2).

---

## Resources

### `kpm_secret` resource

Full lifecycle management of a KPM secret.

```hcl
resource "kpm_secret" "db_password" {
  path        = "kv/db/prod"
  key         = "password"
  value       = var.db_password   # sensitive
  type        = "generic"
  tags        = ["prod", "db"]
  description = "Production DB password"
}
```

The `type` field determines which AgentKMS endpoint family is used:

| type | CRUD endpoints |
|------|----------------|
| `generic` (default) | `POST/GET/DELETE /credentials/generic/{path}` |
| `llm` | `POST/GET/DELETE /credentials/llm/{provider}` |

`value` is `Sensitive: true` in the schema — redacted from plan output and state display. The raw value is stored in Terraform state (encrypted at rest by the state backend — S3+KMS, Terraform Cloud, etc. — same model as `aws_secretsmanager_secret_version`).

On Read (drift detection), the provider fetches the current value and compares against state. Out-of-band changes are detected and surfaced as a planned update.

---

### `kpm_github_app` resource

Manages a GitHub App installation registered in AgentKMS. Maps to the existing `client.RegisterGithubApp`, `client.GetGithubApp`, `client.ListGithubApps`, and `client.RemoveGithubApp` methods — confirmed server-side via AgentKMS mTLS client.

```hcl
resource "kpm_github_app" "ci" {
  app_id          = "12345"
  installation_id = "67890"
  private_key     = var.gh_app_private_key   # sensitive, write-only
  name            = "ci-bot"
}
```

**Write-only private key:** AgentKMS never returns the private key on any read endpoint ("stored encrypted, not retrievable"). `private_key` is marked `Sensitive: true` and `WriteOnly: true` (Plugin Framework v2 native). Terraform stores a SHA-256 fingerprint of the key in state for change detection — a key replacement in HCL triggers a fingerprint mismatch → destroy + create.

---

## Data Sources

### `kpm_secret` data source

Read-only. Pulls an existing secret into Terraform config without managing its lifecycle.

```hcl
data "kpm_secret" "db_host" {
  path = "kv/db/prod"
  key  = "host"
}

resource "aws_db_instance" "main" {
  address = data.kpm_secret.db_host.value
}
```

`value` is `Sensitive: true` and `Computed: true`.

### `kpm_credential` data source

Fetches a dynamic or short-lived credential minted by AgentKMS.

```hcl
data "kpm_credential" "openai" {
  type = "llm"
  path = "openai"
}
```

Returns `value` (sensitive, computed) and `expires_at` (RFC3339 string). No state written — fetched fresh on every `terraform apply` / `terraform plan`. Because `expires_at` changes on every fetch it does not drive spurious diffs.

---

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| AgentKMS unreachable | Terraform diagnostic error with mTLS/HTTP error message. No silent fallback. |
| Secret not found on Read | Provider signals "resource no longer exists" — Terraform removes from state, recreates on next apply. |
| Auth failure (bad cert/key/CA) | Surfaced in `Configure()` before any resource operations. |
| Partial apply failure | Each resource is independent; standard Terraform behaviour, no cross-resource rollback. |

---

## Testing

Three layers:

1. **Unit tests** — mock the `internal/client` interface; test schema validation, state logic, and SHA-256 fingerprint behaviour for `kpm_github_app`.
2. **Acceptance tests** (`TF_ACC=1`) — spin up a local AgentKMS dev instance (same pattern as `kpm quickstart`), run real `terraform apply` / `terraform destroy` cycles against all four resources/data sources.
3. **Provider framework validation** — `resource.UnitTest` from the Plugin Framework testing helpers catches schema mismatches and missing required attributes without a live server.

CI runs unit tests and framework validation on every PR. Acceptance tests run on tag push or manual trigger (require a live AgentKMS instance).

---

## Future Work (Out of Scope for v1)

- **Option 4 integration** — use KPM to supply secrets to Terraform runs so `TF_VAR_*` and `.tfvars` never contain plaintext. Separate spec.
- **Infrastructure module** — HCL module to provision AgentKMS server infrastructure.
- **Secret seeding module** — HCL module to bootstrap initial secrets during environment provisioning.
- **`kpmclient` Go library** — formal extraction of a versioned client library once the API surface stabilises.
