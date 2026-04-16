#!/bin/bash
# KPM Quick Install
# curl -sL https://kpm.catalyst9.ai/install | bash
#
# Installs kpm (key-pair-manager) — the secure secrets CLI backed by AgentKMS.
# Prefers prebuilt release binaries (no Go required). Falls back to
# building from source if the binary is unavailable or curl fails.
#
# kpm has ONE dependency (yaml.v3). No supply chain bloat.
# The dev server (agentkms-dev) is built separately by `kpm quickstart` only if needed.

set -e

REPO="https://github.com/TheGenXCoder/kpm.git"
BRANCH="main"
RELEASE_TAG="${KPM_RELEASE_TAG:-v0.1.0}"
INSTALL_DIR="${KPM_INSTALL_DIR:-/usr/local/bin}"
BUILD_DIR="$(mktemp -d)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

# ── Detect OS + arch ─────────────────────────────────────────────────────────

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    linux|darwin) ;;
    *) fail "Unsupported OS: $OS (supported: linux, darwin)" ;;
esac

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) fail "Unsupported arch: $ARCH (supported: amd64, arm64)" ;;
esac

BINARY_URL="https://github.com/TheGenXCoder/kpm/releases/download/${RELEASE_TAG}/kpm-${OS}-${ARCH}"

# ── Try prebuilt binary first ─────────────────────────────────────────────────

info "Detected platform: ${OS}/${ARCH}"
info "Attempting to download prebuilt binary (${RELEASE_TAG})..."

if command -v curl >/dev/null 2>&1 && curl -fsSL -o "$BUILD_DIR/kpm-bin" "$BINARY_URL" 2>/dev/null; then
    info "Prebuilt binary downloaded"
    chmod +x "$BUILD_DIR/kpm-bin"
    INSTALL_METHOD="prebuilt"
else
    warn "Prebuilt binary unavailable — falling back to source build"

    command -v git >/dev/null 2>&1 || fail "git is required for source build. Install it first."
    command -v go  >/dev/null 2>&1 || fail "go is required (1.21+) for source build. Install from https://go.dev/dl/"

    GO_VERSION=$(go version 2>/dev/null | sed -n 's/.*go\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    info "Found go ${GO_VERSION:-unknown}"

    info "Cloning kpm..."
    git clone --depth 1 --branch "$BRANCH" "$REPO" "$BUILD_DIR/src" 2>&1 | tail -1

    info "Building kpm (1 dependency: yaml.v3)..."
    cd "$BUILD_DIR/src"
    go build -o "$BUILD_DIR/kpm-bin" ./cmd/kpm/ 2>&1
    INSTALL_METHOD="source"
fi

# ── Install ───────────────────────────────────────────────────────────────────

if [ -w "$INSTALL_DIR" ]; then
    mv "$BUILD_DIR/kpm-bin" "$INSTALL_DIR/kpm"
else
    info "Installing to $INSTALL_DIR (requires sudo)..."
    sudo mv "$BUILD_DIR/kpm-bin" "$INSTALL_DIR/kpm"
fi

chmod +x "$INSTALL_DIR/kpm"

# ── Verify ────────────────────────────────────────────────────────────────────

VERSION=$("$INSTALL_DIR/kpm" version 2>&1)
info "Installed via ${INSTALL_METHOD}: $VERSION"
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
