#!/usr/bin/env bash
set -e

IMAGE_NAME="angb-analyzer"
BIN_NAME="angb"
INSTALL_DIR="/usr/local/bin"

echo "[+] Verifying dependencies..."

command -v docker >/dev/null || {
  echo "Docker not found"
  exit 1
}

echo "[+] Building docker image..."
docker build -t "$IMAGE_NAME" .

echo "[+] Installing command $BIN_NAME..."

sudo install -m 755 bin/angb "$INSTALL_DIR/$BIN_NAME"

echo
echo "[✓] Instalation finished csucessfully!"
echo "Now you can use:"
echo
echo "  angb <arquivo>"
