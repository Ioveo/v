#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Ioveo/v.git}"
TARGET_DIR="${TARGET_DIR:-$HOME/saia-safe}"

echo "[INFO] target: $TARGET_DIR"

if [[ -d "$TARGET_DIR/.git" ]]; then
  echo "[INFO] existing git repo found, updating..."
  git -C "$TARGET_DIR" pull --ff-only
else
  if [[ -e "$TARGET_DIR" ]]; then
    echo "[ERROR] target exists but is not a git repo: $TARGET_DIR"
    echo "        move/remove it or set TARGET_DIR to another path"
    exit 1
  fi
  echo "[INFO] cloning $REPO_URL"
  git clone "$REPO_URL" "$TARGET_DIR"
fi

PROJECT_DIR="$TARGET_DIR/serv00-safe/project"
if [[ ! -d "$PROJECT_DIR" ]]; then
  echo "[ERROR] project folder not found: $PROJECT_DIR"
  exit 1
fi

cd "$PROJECT_DIR"
chmod +x "./saia-safe.sh"

if ! command -v cc >/dev/null 2>&1; then
  echo "[ERROR] 'cc' compiler not found in PATH"
  exit 1
fi

echo "[INFO] building binary..."
cc *.c -o saia -lpthread -lm -std=c11

echo "[OK] install complete"
echo ""
echo "Next commands:"
echo "  cd $PROJECT_DIR"
echo "  ./saia-safe.sh menu"
echo "  ./saia-safe.sh start --run-audit 3 1 1000 30"
