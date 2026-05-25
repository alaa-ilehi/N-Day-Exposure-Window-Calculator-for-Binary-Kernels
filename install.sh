#!/usr/bin/env bash
# Builds the Docker image and installs a global 'patch-shadow' wrapper.
# Run from the project root: ./install.sh

set -euo pipefail

IMAGE="patch-shadow"
WRAPPER="/usr/local/bin/patch-shadow"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Patch Shadow installer ==="

if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker not found." >&2; exit 1
fi
if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon not running." >&2; exit 1
fi

echo "[1/3] Building Docker image '$IMAGE'..."
docker build -t "$IMAGE" "$SCRIPT_DIR"

echo "[2/3] Installing wrapper to $WRAPPER..."
cat > /tmp/patch-shadow-wrapper <<'EOF'
#!/usr/bin/env bash
exec docker run --rm -i -v "$(pwd):/data" -w /data patch-shadow "$@"
EOF

if [[ "$EUID" -eq 0 ]]; then
    install -m 755 /tmp/patch-shadow-wrapper "$WRAPPER"
else
    sudo install -m 755 /tmp/patch-shadow-wrapper "$WRAPPER"
fi

echo ""
echo "Done. Usage from any directory:"
echo "  patch-shadow --help"
echo "  patch-shadow scan kernel.elf"
echo "  patch-shadow list-cves"
