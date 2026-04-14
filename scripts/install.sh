#!/bin/bash
# KPM Quick Install
# curl -sL https://raw.githubusercontent.com/TheGenXCoder/agentkms/main/scripts/install.sh | bash
#
# Installs kpm (key-pair-manager) — the secure secrets CLI backed by AgentKMS.
# Requires: git, go (1.21+)
# Release binaries coming soon — this build-from-source step will be optional.
#
# kpm has ONE dependency (yaml.v3). No supply chain bloat.
# The dev server (agentkms-dev) is built separately by `kpm quickstart` only if needed.

set -e

REPO="https://github.com/TheGenXCoder/kpm.git"
BRANCH="main"
INSTALL_DIR="${KPM_INSTALL_DIR:-/usr/local/bin}"
BUILD_DIR="$(mktemp -d)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

# ── Check dependencies ────────────────────────────────────────────────────────

command -v git >/dev/null 2>&1 || fail "git is required. Install it first."
command -v go  >/dev/null 2>&1 || fail "go is required (1.21+). Install from https://go.dev/dl/
    Release binaries coming soon — this requirement will be optional."

GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' || echo "0.0")
info "Found go $GO_VERSION"

# ── Build ─────────────────────────────────────────────────────────────────────

info "Cloning kpm..."
git clone --depth 1 --branch "$BRANCH" "$REPO" "$BUILD_DIR/kpm" 2>&1 | tail -1

info "Building kpm (1 dependency: yaml.v3)..."
cd "$BUILD_DIR/kpm"
go build -o "$BUILD_DIR/kpm" ./cmd/kpm/ 2>&1

# ── Install ───────────────────────────────────────────────────────────────────

if [ -w "$INSTALL_DIR" ]; then
    mv "$BUILD_DIR/kpm" "$INSTALL_DIR/kpm"
else
    info "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mv "$BUILD_DIR/kpm" "$INSTALL_DIR/kpm"
fi

chmod +x "$INSTALL_DIR/kpm"

# ── Cleanup ───────────────────────────────────────────────────────────────────

rm -rf "$BUILD_DIR"

# ── Verify ────────────────────────────────────────────────────────────────────

VERSION=$("$INSTALL_DIR/kpm" version 2>&1)
info "Installed: $VERSION"
echo ""

# ── Next steps ────────────────────────────────────────────────────────────────

if [ ! -f ~/.kpm/config.yaml ]; then
    echo "Next steps:"
    echo ""
    echo "  kpm quickstart    # Set up a local dev environment in seconds"
    echo ""
    echo "  Or, to connect to an existing AgentKMS server:"
    echo "    1. Get your certs from your team lead (ca.crt, client.crt, client.key)"
    echo "       Place them in ~/.kpm/certs/"
    echo "    2. kpm init"
    echo "    3. kpm tree"
    echo ""
else
    echo "Config found at ~/.kpm/config.yaml"
    echo "Run: kpm tree"
fi
