#!/bin/bash
# KPM v0.1.0 Manual Test Script
# Run in a fresh Docker container: docker run -it --rm --network=host kpm-base
# Expected: all tests PASS, zero value leaks in security checks
#
# Prerequisites: kpm-base Docker image built on the test machine
# Usage: bash /myfiles/manual-test.sh
#        or copy/paste sections one at a time

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

pass() { echo -e "  ${GREEN}PASS${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}FAIL${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YELLOW}WARN${NC} $1"; WARN=$((WARN+1)); }

echo "============================================"
echo "  KPM v0.1.0 — Manual Test Suite"
echo "============================================"
echo ""

# ─── SETUP ────────────────────────────────────────────────────────────────────

echo "=== SETUP ==="

echo "Installing KPM..."
curl -sL https://raw.githubusercontent.com/TheGenXCoder/kpm/main/scripts/install.sh | bash 2>&1 | tail -2
if command -v kpm &>/dev/null; then
    pass "kpm installed"
else
    fail "kpm not found in PATH"
    exit 1
fi

echo "Installing agentkms-dev..."
git clone --depth 1 https://github.com/TheGenXCoder/agentkms.git /tmp/akms 2>&1 | tail -1
cd /tmp/akms && go build -o /usr/local/bin/agentkms-dev ./cmd/dev/ 2>&1
if command -v agentkms-dev &>/dev/null; then
    pass "agentkms-dev installed"
else
    fail "agentkms-dev not found"
    exit 1
fi

echo "Running quickstart..."
kpm quickstart 2>&1 | tail -2
sleep 2

# Verify server is running
if curl -sk --cert ~/.kpm/certs/client.crt --key ~/.kpm/certs/client.key --cacert ~/.kpm/certs/ca.crt https://127.0.0.1:8443/healthz 2>/dev/null | grep -q "ok"; then
    pass "AgentKMS dev server running"
else
    fail "AgentKMS dev server not reachable"
    exit 1
fi

echo ""

# ─── REGISTRY: kpm add ───────────────────────────────────────────────────────

echo "=== REGISTRY: kpm add ==="

# T1: Interactive-style add via pipe
OUTPUT=$(echo "test-cloudflare-token-value" | kpm add cloudflare/dns-token --tags dns,ci --description "catalyst9.ai DNS" --type api-token 2>&1)
if echo "$OUTPUT" | grep -q "Stored cloudflare/dns-token v1"; then
    pass "T1: add via pipe"
else
    fail "T1: add via pipe — got: $OUTPUT"
fi

# T2: Add with auto-detect (sk- prefix → api-token)
OUTPUT=$(echo "sk-ant-test-key-1234" | kpm add anthropic/api-key --tags dev,ci 2>&1)
if echo "$OUTPUT" | grep -q "api-token"; then
    pass "T2: add auto-detect type from sk- prefix"
else
    fail "T2: auto-detect — got: $OUTPUT"
fi

# T3: Add from file (SSH key → ssh-key type)
echo "-----BEGIN OPENSSH PRIVATE KEY-----
test-deploy-key-data-here
-----END OPENSSH PRIVATE KEY-----" > /tmp/test-ssh-key
OUTPUT=$(kpm add ssh/deploy-key --from-file /tmp/test-ssh-key --description "deploy to prod" 2>&1)
rm -f /tmp/test-ssh-key
if echo "$OUTPUT" | grep -q "ssh-key"; then
    pass "T3: add from file (SSH key detected)"
else
    fail "T3: add from file — got: $OUTPUT"
fi

# T4: Add connection string (auto-detect)
OUTPUT=$(echo "postgres://admin:s3cret@db.prod:5432/myapp" | kpm add db/postgres-prod --tags production 2>&1)
if echo "$OUTPUT" | grep -q "connection-string"; then
    pass "T4: add auto-detect connection string"
else
    fail "T4: connection string — got: $OUTPUT"
fi

# T5: Add generic secret (no pattern match)
OUTPUT=$(echo "my-jwt-signing-secret-2026" | kpm add app/jwt-secret --description "JWT HMAC key" 2>&1)
if echo "$OUTPUT" | grep -q "Stored app/jwt-secret v1"; then
    pass "T5: add generic secret"
else
    fail "T5: generic secret — got: $OUTPUT"
fi

# T6: Add with --service/--name flags
OUTPUT=$(echo "ghp_test1234567890" | kpm add --service github --name deploy-pat --tags ci 2>&1)
if echo "$OUTPUT" | grep -q "Stored github/deploy-pat"; then
    pass "T6: add with --service/--name flags"
else
    fail "T6: --service/--name — got: $OUTPUT"
fi

# T7: Add without path (should error)
OUTPUT=$(echo "value" | kpm add 2>&1) || true
if echo "$OUTPUT" | grep -qi "path required"; then
    pass "T7: add without path errors correctly"
else
    fail "T7: missing path error — got: $OUTPUT"
fi

echo ""

# ─── REGISTRY: kpm list ──────────────────────────────────────────────────────

echo "=== REGISTRY: kpm list ==="

# T8: List all secrets
OUTPUT=$(kpm list 2>&1)
if echo "$OUTPUT" | grep -q "cloudflare" && echo "$OUTPUT" | grep -q "anthropic" && echo "$OUTPUT" | grep -q "ssh"; then
    pass "T8: list shows all services"
else
    fail "T8: list — got: $OUTPUT"
fi

# T9: List shows correct count
if echo "$OUTPUT" | grep -q "6 secrets"; then
    pass "T9: list shows correct count (6)"
else
    warn "T9: count mismatch — got: $(echo "$OUTPUT" | tail -1)"
fi

# T10: List filter by service
OUTPUT=$(kpm list cloudflare 2>&1)
if echo "$OUTPUT" | grep -q "dns-token" && ! echo "$OUTPUT" | grep -q "anthropic"; then
    pass "T10: list filtered by service"
else
    fail "T10: service filter — got: $OUTPUT"
fi

# T11: List filter by tag
OUTPUT=$(kpm list --tag ci 2>&1)
if echo "$OUTPUT" | grep -q "dns-token" && echo "$OUTPUT" | grep -q "anthropic"; then
    pass "T11: list filtered by tag"
else
    fail "T11: tag filter — got: $OUTPUT"
fi

# T12: List filter by type
OUTPUT=$(kpm list --type-filter ssh-key 2>&1)
if echo "$OUTPUT" | grep -q "deploy-key" && ! echo "$OUTPUT" | grep -q "cloudflare"; then
    pass "T12: list filtered by type"
else
    warn "T12: type filter — got: $OUTPUT"
fi

# T13: List JSON output
OUTPUT=$(kpm list --json 2>&1)
if echo "$OUTPUT" | grep -q '"service"' && echo "$OUTPUT" | grep -q '"type"'; then
    pass "T13: list --json output"
else
    fail "T13: JSON output — got: $OUTPUT"
fi

echo ""

# ─── REGISTRY: kpm describe ──────────────────────────────────────────────────

echo "=== REGISTRY: kpm describe ==="

# T14: Describe shows metadata
OUTPUT=$(kpm describe cloudflare/dns-token 2>&1)
if echo "$OUTPUT" | grep -q "Type:" && echo "$OUTPUT" | grep -q "Tags:" && echo "$OUTPUT" | grep -q "Description:"; then
    pass "T14: describe shows metadata"
else
    fail "T14: describe — got: $OUTPUT"
fi

# T15: Describe shows correct type
if echo "$OUTPUT" | grep -q "api-token"; then
    pass "T15: describe correct type"
else
    fail "T15: type in describe — got: $OUTPUT"
fi

# T16: Describe shows correct tags
if echo "$OUTPUT" | grep -q "dns" && echo "$OUTPUT" | grep -q "ci"; then
    pass "T16: describe correct tags"
else
    fail "T16: tags in describe — got: $OUTPUT"
fi

# T17: Describe nonexistent secret
OUTPUT=$(kpm describe nonexistent/path 2>&1) || true
if echo "$OUTPUT" | grep -qi "not found\|error\|404"; then
    pass "T17: describe nonexistent errors"
else
    fail "T17: nonexistent describe — got: $OUTPUT"
fi

echo ""

# ─── REGISTRY: kpm history ───────────────────────────────────────────────────

echo "=== REGISTRY: kpm history ==="

# T18: History shows version
OUTPUT=$(kpm history cloudflare/dns-token 2>&1)
if echo "$OUTPUT" | grep -q "v1" && echo "$OUTPUT" | grep -q "current"; then
    pass "T18: history shows v1 (current)"
else
    fail "T18: history — got: $OUTPUT"
fi

# T19: Add update and verify v2
echo "updated-token-value" | kpm add cloudflare/dns-token 2>&1 | grep -q "v2" || true
OUTPUT=$(kpm history cloudflare/dns-token 2>&1)
if echo "$OUTPUT" | grep -q "v2" && echo "$OUTPUT" | grep -q "v1"; then
    pass "T19: history shows v1 and v2 after update"
else
    warn "T19: version history — got: $OUTPUT"
fi

echo ""

# ─── REGISTRY: kpm get ───────────────────────────────────────────────────────

echo "=== REGISTRY: kpm get ==="

# T20: Get registry secret by service/name
OUTPUT=$(kpm get cloudflare/dns-token 2>&1)
if [ -n "$OUTPUT" ] && ! echo "$OUTPUT" | grep -qi "error\|not found"; then
    pass "T20: get registry path returns value"
else
    fail "T20: get registry path — got: $OUTPUT"
fi

# T21: Get nonexistent secret
OUTPUT=$(kpm get nonexistent/secret 2>&1) || true
if echo "$OUTPUT" | grep -qi "error\|not found"; then
    pass "T21: get nonexistent errors"
else
    fail "T21: nonexistent get — got: $OUTPUT"
fi

echo ""

# ─── REGISTRY: kpm remove ────────────────────────────────────────────────────

echo "=== REGISTRY: kpm remove ==="

# T22: Soft delete
OUTPUT=$(echo y | kpm remove app/jwt-secret 2>&1)
if echo "$OUTPUT" | grep -q "Removed"; then
    pass "T22: soft delete"
else
    fail "T22: remove — got: $OUTPUT"
fi

# T23: Deleted secret hidden from list
OUTPUT=$(kpm list 2>&1)
if ! echo "$OUTPUT" | grep -q "jwt-secret"; then
    pass "T23: deleted secret hidden from list"
else
    fail "T23: deleted still visible — got: $OUTPUT"
fi

# T24: Deleted visible with --include-deleted
OUTPUT=$(kpm list --include-deleted 2>&1)
if echo "$OUTPUT" | grep -q "jwt-secret" && echo "$OUTPUT" | grep -q "DELETED"; then
    pass "T24: --include-deleted shows deleted secret"
else
    warn "T24: include-deleted — got: $OUTPUT"
fi

echo ""

# ─── TEMPLATE SYSTEM ─────────────────────────────────────────────────────────

echo "=== TEMPLATE SYSTEM ==="

# T25: kpm tree
OUTPUT=$(kpm tree 2>&1)
if echo "$OUTPUT" | grep -q "User:" && echo "$OUTPUT" | grep -q "template"; then
    pass "T25: kpm tree shows hierarchy"
else
    fail "T25: tree — got: $OUTPUT"
fi

# T26: kpm env (secure default — ciphertext)
OUTPUT=$(kpm env --from ~/.kpm/templates/shell-env.template 2>&1)
if echo "$OUTPUT" | grep -q "ENC\[kpm:"; then
    pass "T26: kpm env outputs ciphertext by default"
else
    fail "T26: env secure default — got: $OUTPUT"
fi

# T27: kpm env --plaintext
OUTPUT=$(kpm env --from ~/.kpm/templates/shell-env.template --plaintext 2>&1)
if echo "$OUTPUT" | grep -q "=" && ! echo "$OUTPUT" | grep -q "ENC\[kpm:"; then
    pass "T27: kpm env --plaintext outputs raw values"
else
    fail "T27: env plaintext — got: $OUTPUT"
fi

echo ""

# ─── ENCRYPTED ENV + JIT DECRYPT ─────────────────────────────────────────────

echo "=== ENCRYPTED ENV ==="

# T28: Load ciphertext into shell
eval $(kpm env --from ~/.kpm/templates/shell-env.template --output shell 2>/dev/null)
if echo "$ANTHROPIC_API_KEY" | grep -q "ENC\[kpm:"; then
    pass "T28: shell env has ciphertext"
else
    fail "T28: env should be ciphertext — got: $(echo $ANTHROPIC_API_KEY | head -c 30)"
fi

# T29: kpm show
OUTPUT=$(kpm show 2>&1)
if echo "$OUTPUT" | grep -q "encrypted" && echo "$OUTPUT" | grep -q "secrets managed"; then
    pass "T29: kpm show displays managed secrets"
else
    fail "T29: show — got: $OUTPUT"
fi

# T30: kpm run decrypts for child process
OUTPUT=$(kpm run -- sh -c 'echo $ANTHROPIC_API_KEY' 2>&1)
if echo "$OUTPUT" | grep -v "ENC\[" | grep -q "sk-\|test\|demo"; then
    pass "T30: kpm run decrypts for child"
else
    warn "T30: kpm run decrypt — got: $OUTPUT"
fi

# T31: mock-codex with ciphertext fails
OUTPUT=$(mock-codex "test" 2>&1) || true
if echo "$OUTPUT" | grep -q "still encrypted\|ENC\[kpm:"; then
    pass "T31: mock-codex fails with ciphertext"
else
    warn "T31: mock-codex with ciphertext — got: $OUTPUT"
fi

# T32: mock-codex through kpm run works
OUTPUT=$(kpm run -- mock-codex "test" 2>&1)
if echo "$OUTPUT" | grep -q "Response:"; then
    pass "T32: mock-codex works through kpm run"
else
    warn "T32: mock-codex via kpm run — got: $OUTPUT"
fi

echo ""

# ─── SECURITY CHECKS ─────────────────────────────────────────────────────────

echo "=== SECURITY CHECKS ==="

# S1: kpm list never shows values
LEAKS=$(kpm list 2>&1 | grep -c "test-cloudflare-token\|sk-ant-test\|PRIVATE KEY\|postgres://\|jwt-signing" || true)
if [ "$LEAKS" = "0" ]; then
    pass "S1: kpm list — zero value leaks"
else
    fail "S1: kpm list leaked $LEAKS values!"
fi

# S2: kpm describe never shows values
LEAKS=$(kpm describe cloudflare/dns-token 2>&1 | grep -c "test-cloudflare-token\|updated-token" || true)
if [ "$LEAKS" = "0" ]; then
    pass "S2: kpm describe — zero value leaks"
else
    fail "S2: kpm describe leaked $LEAKS values!"
fi

# S3: kpm history never shows values
LEAKS=$(kpm history cloudflare/dns-token 2>&1 | grep -c "test-cloudflare-token\|updated-token" || true)
if [ "$LEAKS" = "0" ]; then
    pass "S3: kpm history — zero value leaks"
else
    fail "S3: kpm history leaked $LEAKS values!"
fi

# S4: kpm list --json never shows values
LEAKS=$(kpm list --json 2>&1 | grep -c "test-cloudflare-token\|sk-ant-test\|PRIVATE KEY" || true)
if [ "$LEAKS" = "0" ]; then
    pass "S4: kpm list --json — zero value leaks"
else
    fail "S4: kpm list --json leaked $LEAKS values!"
fi

# S5: kpm show never shows values
LEAKS=$(kpm show 2>&1 | grep -c "test-cloudflare-token\|sk-ant-test\|demo" || true)
if [ "$LEAKS" = "0" ]; then
    pass "S5: kpm show — zero value leaks"
else
    fail "S5: kpm show leaked $LEAKS values!"
fi

# S6: echo $VAR shows ciphertext not plaintext
if echo "$ANTHROPIC_API_KEY" | grep -q "ENC\[kpm:" && ! echo "$ANTHROPIC_API_KEY" | grep -q "sk-"; then
    pass "S6: env var contains ciphertext, not plaintext"
else
    fail "S6: env var should be ciphertext"
fi

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
