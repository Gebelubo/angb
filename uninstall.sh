#!/usr/bin/env bash
set -e

IMAGE_NAME="angb-analyzer"
BIN_NAME="angb"
INSTALL_DIR="/usr/local/bin"

echo "[+] Starting uninstalling of angb..."

if [ -f "$INSTALL_DIR/$BIN_NAME" ]; then
  echo "[+] Removing command $BIN_NAME..."
  sudo rm -f "$INSTALL_DIR/$BIN_NAME"
else
  echo "[i] Command $BIN_NAME not found (ok)"
fi

# Remove a imagem Docker
if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
  echo "[+] Removing docker image $IMAGE_NAME..."
  docker rmi "$IMAGE_NAME"
else
  echo "[i] Docker image $IMAGE_NAME not found (ok)"
fi

echo
echo "[✓] Uninstalling concluded."
echo "No user file was changed."
