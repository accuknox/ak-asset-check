#!/usr/bin/env sh
set -e

REPO="accuknox/ak-asset-check"
BINARY="ak-asset-check"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# ── Detect OS ─────────────────────────────────────────────────────────────────
case "$(uname -s)" in
  Linux)  OS="linux"  ;;
  Darwin) OS="darwin" ;;
  *)
    echo "Unsupported OS: $(uname -s)" >&2
    echo "For Windows, download the .zip from https://github.com/${REPO}/releases/latest" >&2
    exit 1
    ;;
esac

# ── Detect architecture ───────────────────────────────────────────────────────
case "$(uname -m)" in
  x86_64|amd64)          ARCH="amd64" ;;
  aarch64|arm64|armv8*)  ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

# ── Resolve latest version ────────────────────────────────────────────────────
if command -v curl >/dev/null 2>&1; then
  FETCH="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  FETCH="wget -qO-"
else
  echo "curl or wget is required" >&2
  exit 1
fi

VERSION="${VERSION:-$($FETCH "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')}"

if [ -z "$VERSION" ]; then
  echo "Could not determine latest version. Set VERSION env var to override." >&2
  exit 1
fi

ARCHIVE="${BINARY}-${OS}-${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"

# ── Download & install ────────────────────────────────────────────────────────
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading ${BINARY} ${VERSION} (${OS}/${ARCH})…"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" | tar -xz -C "$TMP"
else
  wget -qO- "$URL" | tar -xz -C "$TMP"
fi

if [ ! -f "$TMP/$BINARY" ]; then
  echo "Binary not found in archive. Contents:" >&2
  ls "$TMP" >&2
  exit 1
fi

chmod +x "$TMP/$BINARY"

# Install — try without sudo first, fall back to sudo
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
else
  echo "Installing to $INSTALL_DIR (requires sudo)…"
  sudo mv "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo "Installed: $INSTALL_DIR/$BINARY"
"$INSTALL_DIR/$BINARY" --version 2>/dev/null || true
