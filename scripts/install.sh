#!/bin/bash
# KPM Quick Install
# curl -sL https://kpm.catalyst9.ai/install | bash
#
# Installs kpm (key-pair-manager) — the secure secrets CLI backed by AgentKMS.
# Prefers prebuilt release binaries (no Go required). Falls back to
# building from source if the binary is unavailable or curl fails.
#
# Flags (pass via "bash -s -- --flag" when piping from curl):
#   --source-only   Skip the prebuilt binary; always build from source.
#                   Useful in CI, for power users, or to install from main.
#
# Environment variables:
#   KPM_INSTALL_DIR  Where to install (default: /usr/local/bin)
#   KPM_RELEASE_TAG  Which release to pull (default: v0.2.1)
#
# kpm has ONE dependency (yaml.v3). No supply chain bloat.
# The dev server (agentkms-dev) is built separately by `kpm quickstart` only if needed.

set -e

REPO="https://github.com/TheGenXCoder/kpm.git"
BRANCH="main"
RELEASE_TAG="${KPM_RELEASE_TAG:-v0.2.1}"
INSTALL_DIR="${KPM_INSTALL_DIR:-/usr/local/bin}"
BUILD_DIR="$(mktemp -d)"
SOURCE_ONLY=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
fail()  { echo -e "${RED}ERROR:${NC} $*" >&2; exit 1; }

cleanup() { rm -rf "$BUILD_DIR"; }
trap cleanup EXIT

# ── Parse flags ──────────────────────────────────────────────────────────────

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source-only)
            SOURCE_ONLY=1
            shift
            ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            fail "Unknown flag: $1 (try --help)"
            ;;
    esac
done

# ── Source-build helper ──────────────────────────────────────────────────────

build_from_source() {
    command -v git >/dev/null 2>&1 || fail "git is required for source build. Install it first."
    command -v go  >/dev/null 2>&1 || fail "go is required (1.21+) for source build. Install from https://go.dev/dl/"

    GO_VERSION=$(go version 2>/dev/null | sed -n 's/.*go\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
    info "Found go ${GO_VERSION:-unknown}"

    info "Building kpm from source (typically 30-60s on a modern machine)..."
    info "Cloning kpm..."
    git clone --depth 1 --branch "$BRANCH" "$REPO" "$BUILD_DIR/src" 2>&1 | tail -1

    info "Compiling (1 dependency: yaml.v3)..."
    cd "$BUILD_DIR/src"
    go build -o "$BUILD_DIR/kpm-bin" ./cmd/kpm/ 2>&1
}

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

info "Detected platform: ${OS}/${ARCH}"

# ── Install path ─────────────────────────────────────────────────────────────

if [ "$SOURCE_ONLY" -eq 1 ]; then
    info "--source-only specified — skipping prebuilt binary download"
    build_from_source
    INSTALL_METHOD="source (forced)"
else
    info "Attempting to download prebuilt binary (${RELEASE_TAG})..."
    if command -v curl >/dev/null 2>&1 && curl -fsSL -o "$BUILD_DIR/kpm-bin" "$BINARY_URL" 2>/dev/null; then
        info "Prebuilt binary downloaded (~10MB)"
        chmod +x "$BUILD_DIR/kpm-bin"
        INSTALL_METHOD="prebuilt"
    else
        warn "Prebuilt binary unavailable for ${OS}/${ARCH} at ${RELEASE_TAG}"
        warn "Falling back to source build (no kpm on PATH yet — this is fine)"
        build_from_source
        INSTALL_METHOD="source"
    fi
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
