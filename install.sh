#!/usr/bin/env sh
set -e

REPO="casoon/nosecrets"
BIN="nosecrets"
INSTALL_DIR="${NOSECRETS_INSTALL_DIR:-/usr/local/bin}"

# Detect OS
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64)  TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *)      echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    EXT="tar.gz"
    ;;
  Linux)
    case "$ARCH" in
      aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
      x86_64)  TARGET="x86_64-unknown-linux-gnu" ;;
      *)       echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    EXT="tar.gz"
    ;;
  *)
    echo "Unsupported OS: $OS" >&2
    echo "On Windows, use: npm install -g @casoon/nosecrets"
    exit 1
    ;;
esac

# Resolve version
if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')"
fi

if [ -z "$VERSION" ]; then
  echo "Could not determine latest version" >&2
  exit 1
fi

ASSET="${BIN}-${TARGET}.${EXT}"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ASSET}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Installing nosecrets v${VERSION} (${TARGET})..."
curl -fsSL "$URL" -o "${TMP}/${ASSET}"
tar -xzf "${TMP}/${ASSET}" -C "$TMP"

if [ ! -w "$INSTALL_DIR" ]; then
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo install -m 755 "${TMP}/${BIN}" "${INSTALL_DIR}/${BIN}"
else
  install -m 755 "${TMP}/${BIN}" "${INSTALL_DIR}/${BIN}"
fi

echo "Installed: $(${INSTALL_DIR}/${BIN} --version)"
