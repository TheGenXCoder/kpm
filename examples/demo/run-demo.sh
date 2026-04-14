#!/bin/bash
# KPM Demo — Fresh Arch Container → Resolved Secrets
# Run this on tp-dev (or any machine on the 10.2.10.0/24 network)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== Building demo container ==="
docker build -t kpm-demo "$SCRIPT_DIR"

echo ""
echo "=== Preparing config ==="
# Ensure certs exist
if [ ! -f ~/.kpm/certs/client.crt ]; then
    echo "ERROR: ~/.kpm/certs/ not found. Run cert enrollment first."
    exit 1
fi

# Copy config alongside certs
cp "$SCRIPT_DIR/kpm-config.yaml" ~/.kpm/config.yaml

echo ""
echo "=== Starting interactive demo container ==="
echo ""
echo "Try these commands inside the container:"
echo ""
echo "  # See the template hierarchy"
echo "  kpm tree"
echo ""
echo "  # Show the project template (safe to commit — no secrets)"
echo "  cat .kpm/templates/.env.template"
echo ""
echo "  # Resolve secrets from AgentKMS (secure by default — ciphertext output)"
echo "  kpm env --from .kpm/templates/.env.template"
echo ""
echo "  # Plaintext output — explicit opt-in"
echo "  kpm env --from .kpm/templates/.env.template --plaintext"
echo ""
echo "  # Load shell env from user template (like .zshrc would)"
echo "  eval \$(kpm env --from ~/.kpm/templates/shell-env.template --plaintext --output shell)"
echo "  echo \$ANTHROPIC_API_KEY"
echo ""

docker run -it --rm \
    --network=host \
    -v "$HOME/.kpm/certs:/root/.kpm/certs:ro" \
    -v "$SCRIPT_DIR/kpm-config.yaml:/root/.kpm/config.yaml:ro" \
    -v "$SCRIPT_DIR/templates/enterprise/vpn-config.template:/etc/catalyst9/.kpm/templates/vpn-config.template:ro" \
    -v "$SCRIPT_DIR/templates/user/shell-env.template:/root/.kpm/templates/shell-env.template:ro" \
    -v "$SCRIPT_DIR/templates/user/ssh-keys.template:/root/.kpm/templates/ssh-keys.template:ro" \
    -v "$SCRIPT_DIR/templates/project/.env.template:/app/.kpm/templates/.env.template:ro" \
    kpm-demo
