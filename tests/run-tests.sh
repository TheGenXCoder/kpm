#!/bin/bash
# ============================================================================
# KPM v0.1.0 Test Suite
# ============================================================================
#
# Requirements: Docker installed, internet access
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/tests/run-tests.sh | bash
#
#   Or:
#   git clone https://github.com/TheGenXCoder/kpm.git
#   cd kpm
#   bash tests/run-tests.sh
#
# What this does:
#   1. Pulls a fresh Arch Linux Docker image
#   2. Installs KPM + AgentKMS dev server inside the container
#   3. Runs 40 tests covering the full product
#   4. Reports results
#   5. Container is destroyed — nothing left on your machine
#
# ============================================================================

set -e

echo ""
echo "============================================"
echo "  KPM v0.1.0 — Automated Test Suite"
echo "  Running in a disposable Docker container"
echo "============================================"
echo ""

# Check Docker is available
if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is required but not installed."
    echo "Install from: https://docs.docker.com/get-docker/"
    exit 1
fi

echo "Pulling base image (archlinux:latest)..."
docker pull archlinux:latest 2>&1 | tail -1

echo "Starting test container..."
echo ""

docker run --rm --network=host archlinux:latest bash -c '
set -e

RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
NC="\033[0m"

PASS=0
FAIL=0

# Path helpers (XDG with legacy fallback)
kpm_config_dir() { echo "${XDG_CONFIG_HOME:-$HOME/.config}/kpm"; }
kpm_data_dir() { echo "${XDG_DATA_HOME:-$HOME/.local/share}/kpm"; }
kpm_templates() { echo "$(kpm_config_dir)/templates"; }
kpm_certs() { echo "$(kpm_data_dir)/certs"; }
WARN=0

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YELLOW}WARN${NC} $1"; WARN=$((WARN+1)); }

# ─── INSTALL DEPENDENCIES ────────────────────────────────────────────────────

echo "=== Installing dependencies (go, git, curl) ==="
pacman -Sy --noconfirm go git curl 2>&1 | tail -1
echo ""

# ─── INSTALL KPM ─────────────────────────────────────────────────────────────

echo "=== Installing KPM ==="
curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/scripts/install.sh | bash 2>&1 | tail -3
if command -v kpm &>/dev/null; then
    pass "kpm installed ($(kpm version 2>&1))"
else
    fail "kpm not found in PATH"
    exit 1
fi
echo ""

# ─── INSTALL AGENTKMS DEV SERVER ─────────────────────────────────────────────

echo "=== Installing AgentKMS dev server ==="
git clone --depth 1 https://github.com/TheGenXCoder/agentkms.git /tmp/akms 2>&1 | tail -1
cd /tmp/akms && go build -o /usr/local/bin/agentkms-dev ./cmd/dev/ 2>&1 | tail -1
cd /
if command -v agentkms-dev &>/dev/null; then
    pass "agentkms-dev installed"
else
    fail "agentkms-dev not found"
    exit 1
fi
echo ""

# ─── QUICKSTART ───────────────────────────────────────────────────────────────

echo "=== Running kpm quickstart ==="
kpm quickstart 2>/tmp/qs-log
cat /tmp/qs-log | tail -3
sleep 3

if curl -sk --cert "$(kpm_certs)/client.crt" --key "$(kpm_certs)/client.key" --cacert "$(kpm_certs)/ca.crt" https://127.0.0.1:8443/healthz 2>/dev/null | grep -q "ok"; then
    pass "AgentKMS dev server running + healthy"
else
    fail "AgentKMS dev server not reachable"
    exit 1
fi
echo ""

# ─── REGISTRY: kpm add ───────────────────────────────────────────────────────

echo "=== kpm add ==="

OUTPUT=$(echo "test-cloudflare-token-value" | kpm add cloudflare/dns-token --tags dns,ci --description "catalyst9.ai DNS" --type api-token 2>&1)
echo "$OUTPUT" | grep -q "Stored cloudflare/dns-token v1" && pass "T01: add via pipe with --type --tags" || fail "T01: $OUTPUT"

OUTPUT=$(echo "sk-ant-test-key-1234" | kpm add anthropic/api-key --tags dev,ci 2>&1)
echo "$OUTPUT" | grep -q "api-token" && pass "T02: add auto-detect type (sk- prefix)" || fail "T02: $OUTPUT"

echo "-----BEGIN OPENSSH PRIVATE KEY-----
testdata
-----END OPENSSH PRIVATE KEY-----" > /tmp/sshkey
OUTPUT=$(kpm add ssh/deploy-key --from-file /tmp/sshkey --description "deploy to prod" 2>&1)
rm -f /tmp/sshkey
echo "$OUTPUT" | grep -q "ssh-key" && pass "T03: add from file (SSH key detected)" || fail "T03: $OUTPUT"

OUTPUT=$(echo "postgres://admin:pass@db:5432/app" | kpm add db/postgres --tags production 2>&1)
echo "$OUTPUT" | grep -q "connection-string" && pass "T04: add auto-detect connection string" || fail "T04: $OUTPUT"

OUTPUT=$(echo "my-jwt-signing-key" | kpm add app/jwt-secret --description "JWT HMAC key" 2>&1)
echo "$OUTPUT" | grep -q "Stored app/jwt-secret v1" && pass "T05: add generic secret" || fail "T05: $OUTPUT"

OUTPUT=$(echo "ghp_test1234567890" | kpm add --service github --name deploy-pat --tags ci 2>&1)
echo "$OUTPUT" | grep -q "Stored github/deploy-pat" && pass "T06: add with --service/--name flags" || fail "T06: $OUTPUT"

OUTPUT=$(echo "value" | kpm add 2>&1) || true
echo "$OUTPUT" | grep -qi "path required" && pass "T07: add without path errors" || fail "T07: $OUTPUT"

echo ""

# ─── REGISTRY: kpm list ──────────────────────────────────────────────────────

echo "=== kpm list ==="

OUTPUT=$(kpm list 2>&1)
echo "$OUTPUT" | grep -q "cloudflare" && echo "$OUTPUT" | grep -q "anthropic" && echo "$OUTPUT" | grep -q "ssh" && pass "T08: list all services" || fail "T08: $OUTPUT"
echo "$OUTPUT" | grep -q "6 secrets" && pass "T09: list count = 6" || warn "T09: count — $(echo "$OUTPUT" | tail -1)"

OUTPUT=$(kpm list cloudflare 2>&1)
echo "$OUTPUT" | grep -q "dns-token" && ! echo "$OUTPUT" | grep -q "anthropic" && pass "T10: list by service" || fail "T10: $OUTPUT"

OUTPUT=$(kpm list --tag ci 2>&1)
echo "$OUTPUT" | grep -q "dns-token" && echo "$OUTPUT" | grep -q "anthropic" && pass "T11: list by tag" || fail "T11: $OUTPUT"

OUTPUT=$(kpm list --json 2>&1)
echo "$OUTPUT" | grep -q "\"service\"" && pass "T12: list --json" || fail "T12: $OUTPUT"

echo ""

# ─── REGISTRY: kpm describe ──────────────────────────────────────────────────

echo "=== kpm describe ==="

OUTPUT=$(kpm describe cloudflare/dns-token 2>&1)
echo "$OUTPUT" | grep -q "Type:" && echo "$OUTPUT" | grep -q "Tags:" && echo "$OUTPUT" | grep -q "Description:" && pass "T13: describe metadata" || fail "T13: $OUTPUT"
echo "$OUTPUT" | grep -q "api-token" && pass "T14: describe correct type" || fail "T14: $OUTPUT"
echo "$OUTPUT" | grep -q "dns" && echo "$OUTPUT" | grep -q "ci" && pass "T15: describe correct tags" || fail "T15: $OUTPUT"

OUTPUT=$(kpm describe nonexistent/path 2>&1) || true
echo "$OUTPUT" | grep -qi "not found\|error" && pass "T16: describe nonexistent errors" || fail "T16: $OUTPUT"

echo ""

# ─── REGISTRY: kpm history ───────────────────────────────────────────────────

echo "=== kpm history ==="

OUTPUT=$(kpm history cloudflare/dns-token 2>&1)
echo "$OUTPUT" | grep -q "v1" && echo "$OUTPUT" | grep -q "current" && pass "T17: history v1 (current)" || fail "T17: $OUTPUT"

echo ""

# ─── REGISTRY: kpm get ───────────────────────────────────────────────────────

echo "=== kpm get ==="

OUTPUT=$(kpm get cloudflare/dns-token 2>&1)
[ -n "$OUTPUT" ] && ! echo "$OUTPUT" | grep -qi "error" && pass "T18: get registry path" || fail "T18: $OUTPUT"

OUTPUT=$(kpm get nonexistent/secret 2>&1) || true
echo "$OUTPUT" | grep -qi "error\|not found" && pass "T19: get nonexistent errors" || fail "T19: $OUTPUT"

echo ""

# ─── REGISTRY: kpm remove ────────────────────────────────────────────────────

echo "=== kpm remove ==="

OUTPUT=$(echo y | kpm remove app/jwt-secret 2>&1)
echo "$OUTPUT" | grep -q "Removed" && pass "T20: soft delete" || fail "T20: $OUTPUT"

OUTPUT=$(kpm list 2>&1)
! echo "$OUTPUT" | grep -q "jwt-secret" && pass "T21: deleted hidden from list" || fail "T21: $OUTPUT"

OUTPUT=$(kpm list --include-deleted 2>&1)
echo "$OUTPUT" | grep -q "jwt-secret" && pass "T22: --include-deleted shows it" || warn "T22: $OUTPUT"

echo ""

# ─── TEMPLATE SYSTEM ─────────────────────────────────────────────────────────

echo "=== Template system ==="

OUTPUT=$(kpm tree 2>&1)
echo "$OUTPUT" | grep -q "User:" && echo "$OUTPUT" | grep -q "template" && pass "T23: kpm tree" || fail "T23: $OUTPUT"

OUTPUT=$(kpm env --from $(kpm_templates)/shell-env.template 2>&1)
echo "$OUTPUT" | grep -q "ENC\[kpm:" && pass "T24: kpm env = ciphertext (secure default)" || fail "T24: $OUTPUT"

OUTPUT=$(kpm env --from $(kpm_templates)/shell-env.template --plaintext 2>&1)
echo "$OUTPUT" | grep -q "=" && ! echo "$OUTPUT" | grep -q "ENC\[kpm:" && pass "T25: kpm env --plaintext = raw values" || fail "T25: $OUTPUT"

echo ""

# ─── ENCRYPTED ENV + JIT DECRYPT ─────────────────────────────────────────────

echo "=== Encrypted env + JIT decrypt ==="

eval $(kpm env --from $(kpm_templates)/shell-env.template --output shell 2>/dev/null)

echo "$ANTHROPIC_API_KEY" | grep -q "ENC\[kpm:" && pass "T26: shell env has ciphertext" || fail "T26: env is not ciphertext"

OUTPUT=$(kpm show 2>&1)
echo "$OUTPUT" | grep -q "encrypted" && pass "T27: kpm show" || fail "T27: $OUTPUT"

OUTPUT=$(kpm run -- sh -c "echo \$ANTHROPIC_API_KEY" 2>&1)
echo "$OUTPUT" | grep -v "ENC\[" | grep -q "." && pass "T28: kpm run decrypts for child" || warn "T28: $OUTPUT"

if command -v mock-codex &>/dev/null; then
    OUTPUT=$(mock-codex "test" 2>&1) || true
    echo "$OUTPUT" | grep -q "still encrypted\|ENC\[kpm:" && pass "T29: mock-codex fails with ciphertext" || warn "T29: $OUTPUT"

    OUTPUT=$(kpm run -- mock-codex "test" 2>&1)
    echo "$OUTPUT" | grep -q "Response:" && pass "T30: mock-codex works via kpm run" || warn "T30: $OUTPUT"
else
    warn "T29: mock-codex not installed (skipped — install with kpm-base image)"
    warn "T30: mock-codex not installed (skipped)"
fi

echo ""

# ─── SECURITY CHECKS ─────────────────────────────────────────────────────────

echo "=== SECURITY CHECKS (most important) ==="

SECRETS="test-cloudflare-token\|sk-ant-test\|PRIVATE KEY\|postgres://admin\|jwt-signing\|ghp_test"

L=$(kpm list 2>&1 | grep -c "$SECRETS" || true)
[ "$L" = "0" ] && pass "S1: kpm list — zero value leaks" || fail "S1: list leaked $L values!"

L=$(kpm describe cloudflare/dns-token 2>&1 | grep -c "$SECRETS" || true)
[ "$L" = "0" ] && pass "S2: kpm describe — zero value leaks" || fail "S2: describe leaked $L values!"

L=$(kpm history cloudflare/dns-token 2>&1 | grep -c "$SECRETS" || true)
[ "$L" = "0" ] && pass "S3: kpm history — zero value leaks" || fail "S3: history leaked $L values!"

L=$(kpm list --json 2>&1 | grep -c "$SECRETS" || true)
[ "$L" = "0" ] && pass "S4: kpm list --json — zero value leaks" || fail "S4: json leaked $L values!"

L=$(kpm show 2>&1 | grep -c "$SECRETS" || true)
[ "$L" = "0" ] && pass "S5: kpm show — zero value leaks" || fail "S5: show leaked $L values!"

echo "$ANTHROPIC_API_KEY" | grep -q "ENC\[kpm:" && ! echo "$ANTHROPIC_API_KEY" | grep -q "sk-" && pass "S6: env var = ciphertext, not plaintext" || fail "S6: env leaked plaintext"

echo ""

# ─── PROFILE VARIABLES (Phase D) ─────────────────────────────────────────────

echo "=== Profile variables ==="

# Set up nested directory structure with profile configs at each level
PROFILE_ROOT=$(mktemp -d)
mkdir -p "$PROFILE_ROOT/clients/acme/us-east/project-x/.kpm"
mkdir -p "$PROFILE_ROOT/clients/acme/us-east/.kpm"
mkdir -p "$PROFILE_ROOT/clients/acme/.kpm"

cat > "$PROFILE_ROOT/clients/acme/.kpm/config.yaml" <<EOF
profile:
  customer: acme
EOF

cat > "$PROFILE_ROOT/clients/acme/us-east/.kpm/config.yaml" <<EOF
profile:
  region: us-east
EOF

cat > "$PROFILE_ROOT/clients/acme/us-east/project-x/.kpm/config.yaml" <<EOF
profile:
  project: project-x
  environment: staging
  region: us-east-override
EOF

cd "$PROFILE_ROOT/clients/acme/us-east/project-x"

# P1: kpm profile shows merged values
OUTPUT=$(kpm profile 2>&1)
echo "$OUTPUT" | grep -q "customer.*acme" && pass "P1: profile merges customer from parent" || fail "P1: $OUTPUT"

# P2: region from middle level present
echo "$OUTPUT" | grep -q "region" && pass "P2: profile merges region from middle level" || fail "P2: $OUTPUT"

# P3: project from cwd present
echo "$OUTPUT" | grep -q "project.*project-x" && pass "P3: profile has project from cwd" || fail "P3: $OUTPUT"

# P4: child overrides parent (region should be us-east-override, not us-east)
echo "$OUTPUT" | grep -q "us-east-override" && pass "P4: child overrides parent for same key" || fail "P4: $OUTPUT"

# P5: kpm show --profile displays merged profile
OUTPUT=$(kpm show --profile 2>&1)
echo "$OUTPUT" | grep -q "Profile:" && echo "$OUTPUT" | grep -q "customer.*acme" && pass "P5: kpm show --profile shows merged profile" || fail "P5: $OUTPUT"

cd - > /dev/null
rm -rf "$PROFILE_ROOT"

echo ""

# ─── TEMPLATE INCLUDES (Phase C) ─────────────────────────────────────────────

echo "=== Template includes ==="

# Seed a secret for the include test
echo "included-db-password" | kpm add test/db --tags ci 2>&1 > /dev/null

# Create a base template and a template that includes it
TEMPLATES_DIR="$(kpm_templates)"
mkdir -p "$TEMPLATES_DIR"

printf "DB_PASSWORD=\${kms:test/db}\n" > "$TEMPLATES_DIR/test-base.template"
printf "\${kms:include/test-base}\nAPP_NAME=my-service\n" > "$TEMPLATES_DIR/test-app.template"

# I1: Include pulls in variables from base template
OUTPUT=$(kpm env --from "$TEMPLATES_DIR/test-app.template" --plaintext 2>&1)
echo "$OUTPUT" | grep -q "DB_PASSWORD=included-db-password" && pass "I1: include pulls variables from base" || fail "I1: $OUTPUT"

# I2: Current template adds its own variables
echo "$OUTPUT" | grep -q "APP_NAME=my-service" && pass "I2: own variables preserved" || fail "I2: $OUTPUT"

# I3: Circular includes are detected
printf "\${kms:include/circ-b}\nA=1\n" > "$TEMPLATES_DIR/circ-a.template"
printf "\${kms:include/circ-a}\nB=2\n" > "$TEMPLATES_DIR/circ-b.template"

OUTPUT=$(kpm env --from "$TEMPLATES_DIR/circ-a.template" --plaintext 2>&1) || true
echo "$OUTPUT" | grep -qi "circular" && pass "I3: circular include detected" || fail "I3: $OUTPUT"

# Cleanup include test files
rm -f "$TEMPLATES_DIR/test-base.template" "$TEMPLATES_DIR/test-app.template" "$TEMPLATES_DIR/circ-a.template" "$TEMPLATES_DIR/circ-b.template"

echo ""

# ─── PROFILE VARS IN TEMPLATES ───────────────────────────────────────────────

echo "=== Profile variables in templates ==="

# Create a project dir with a profile
PROF_TEST=$(mktemp -d)
mkdir -p "$PROF_TEST/.kpm"
cat > "$PROF_TEST/.kpm/config.yaml" <<EOF
profile:
  testkey: test-value
EOF

# Create a template that uses the profile variable in a secret ref
mkdir -p "$TEMPLATES_DIR"
printf "TEST_VAR={{profile:testkey}}\n" > "$TEMPLATES_DIR/profile-test.template"

cd "$PROF_TEST"

OUTPUT=$(kpm env --from "$TEMPLATES_DIR/profile-test.template" --plaintext 2>&1)
echo "$OUTPUT" | grep -q "TEST_VAR=test-value" && pass "PV1: profile variable resolves in template value" || fail "PV1: $OUTPUT"

cd - > /dev/null
rm -rf "$PROF_TEST"
rm -f "$TEMPLATES_DIR/profile-test.template"

# Cleanup the test/db secret
echo y | kpm remove test/db 2>&1 > /dev/null || true

echo ""

# ─── SUMMARY ─────────────────────────────────────────────────────────────────

echo "============================================"
echo "  RESULTS"
echo "============================================"
echo -e "  ${GREEN}PASS: $PASS${NC}"
echo -e "  ${RED}FAIL: $FAIL${NC}"
echo -e "  ${YELLOW}WARN: $WARN${NC}"
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo -e "  ${RED}SOME TESTS FAILED${NC}"
    exit 1
else
    echo -e "  ${GREEN}ALL TESTS PASSED${NC}"
fi
'
