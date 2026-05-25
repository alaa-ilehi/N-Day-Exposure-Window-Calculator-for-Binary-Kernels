#!/usr/bin/env bash
# install.sh — installs patch-shadow globally on Linux / macOS
#
# Usage:
#   chmod +x install.sh
#   ./install.sh
#
# After install, from any directory:
#   patch-shadow --help
#   patch-shadow scan kernel.elf

set -euo pipefail

IMAGE="patch-shadow"
WRAPPER="/usr/local/bin/patch-shadow"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "=== Patch Shadow installer ==="
echo ""

# ── 1. Check Docker ────────────────────────────────────────────────────────
echo "[1/3] Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "ERROR: Docker is not installed. Install Docker and retry." >&2
    exit 1
fi
if ! docker info &>/dev/null; then
    echo "ERROR: Docker daemon is not running. Start it and retry." >&2
    exit 1
fi
echo "      Docker OK"

# ── 2. Build image ──────────────────────────────────────────────────────────
echo "[2/3] Building Docker image '$IMAGE' (first run may take a minute)..."
docker build -t "$IMAGE" "$SCRIPT_DIR"
echo "      Image built OK"

# ── 3. Install wrapper ──────────────────────────────────────────────────────
echo "[3/3] Installing wrapper to $WRAPPER..."

cat > /tmp/patch-shadow-wrapper <<'EOF'
#!/usr/bin/env bash
# patch-shadow wrapper — mounts CWD as /data inside the container
exec docker run --rm -i \
    -v "$(pwd):/data" \
    -w /data \
    patch-shadow "$@"
EOF

if [[ "$EUID" -eq 0 ]]; then
    install -m 755 /tmp/patch-shadow-wrapper "$WRAPPER"
else
    sudo install -m 755 /tmp/patch-shadow-wrapper "$WRAPPER"
fi

echo ""
echo "Installation complete!"
echo ""
echo "Usage (from any directory):"
echo "  patch-shadow --help"
echo "  patch-shadow list-cves"
echo "  patch-shadow scan kernel.elf"
echo "  patch-shadow scan kernel.elf --output json"
echo ""
