#!/bin/sh
# install.sh — one-line installer for shuang (Linux/macOS).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/rasuvaeff/shuang/master/scripts/install.sh | sh
#
# Override the install location with INSTALL_DIR=/your/path:
#   curl -fsSL ... | INSTALL_DIR=$HOME/bin sh
#
# To pin both this script and its release asset, fetch this file from a release tag:
#   VERSION=v0.2.0
#   curl -fsSL "https://raw.githubusercontent.com/rasuvaeff/shuang/${VERSION}/scripts/install.sh" | VERSION="$VERSION" sh
set -eu

OWNER="rasuvaeff"
REPO="shuang"
# An explicitly requested directory is honored or the install fails — only the
# default may silently fall back to ~/.local/bin.
explicit_install_dir="${INSTALL_DIR+yes}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${VERSION:-}"

err() {
    printf 'shuang install: %s\n' "$*" >&2
    exit 1
}

# --- detect platform -----------------------------------------------------------
os=$(uname -s)
case "$os" in
    Linux*)  target_os=unknown-linux-gnu ;;
    Darwin*) target_os=apple-darwin ;;
    *) err "unsupported OS: $os (only Linux and macOS are supported by this script)" ;;
esac

arch=$(uname -m)
case "$arch" in
    x86_64|amd64)   target_arch=x86_64 ;;
    arm64|aarch64)  target_arch=aarch64 ;;
    *) err "unsupported arch: $arch (only x86_64 and aarch64/arm64 are published)" ;;
esac

target="${target_arch}-${target_os}"

# Published targets (see .github/workflows/release.yml). Linux is x86_64-only for now.
case "$target" in
    x86_64-unknown-linux-gnu|x86_64-apple-darwin|aarch64-apple-darwin) ;;
    *)
        err "no prebuilt binary is published for ${target}; build from source instead:
    cargo install --git https://github.com/${OWNER}/${REPO}"
        ;;
esac

asset="shuang-${target}.tar.gz"
if [ -n "$VERSION" ]; then
    base_url="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}"
else
    base_url="https://github.com/${OWNER}/${REPO}/releases/latest/download"
fi

printf '==> Detecting platform... %s\n' "$target"
printf '==> Downloading %s (%s)...\n' "$asset" "${VERSION:-latest}"

tmpdir=$(mktemp -d) || err "could not create temp dir"
trap 'rm -rf "$tmpdir"' EXIT INT TERM

# $1 = remote file name, $2 = destination path
download() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "${base_url}/$1" -o "$2" || err "download failed: ${base_url}/$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "${base_url}/$1" || err "download failed: ${base_url}/$1"
    else
        err "neither curl nor wget is installed"
    fi
}

download "$asset" "${tmpdir}/${asset}"

# --- verify checksum ------------------------------------------------------------
# The release publishes <asset>.sha256 next to every archive. Verification is
# mandatory: this script is meant to be piped into a shell, so an altered or
# truncated download must fail closed rather than be executed.
printf '==> Verifying checksum...\n'
download "${asset}.sha256" "${tmpdir}/${asset}.sha256"

if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${tmpdir}/${asset}" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${tmpdir}/${asset}" | cut -d' ' -f1)
else
    err "neither sha256sum nor shasum is available to verify the download"
fi
expected=$(cut -d' ' -f1 <"${tmpdir}/${asset}.sha256")
[ -n "$expected" ] || err "published checksum for ${asset} is empty"
if [ "$actual" != "$expected" ]; then
    err "checksum mismatch for ${asset}
    expected: ${expected}
    actual:   ${actual}"
fi

printf '==> Extracting...\n'
tar -xzf "${tmpdir}/${asset}" -C "$tmpdir" || err "extraction failed"
[ -f "${tmpdir}/shuang" ] || err "archive did not contain a 'shuang' binary"

# --- choose destination --------------------------------------------------------
if [ -n "$explicit_install_dir" ] && [ ! -d "$INSTALL_DIR" ]; then
    mkdir -p "$INSTALL_DIR" 2>/dev/null || true
fi
if [ -w "$INSTALL_DIR" ]; then
    dest="$INSTALL_DIR"
    SUDO=""
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    # Only passwordless sudo: `curl … | sh` has no TTY to type a password into.
    dest="$INSTALL_DIR"
    SUDO="sudo"
elif [ -n "$explicit_install_dir" ]; then
    # The user asked for this exact directory — failing beats installing elsewhere.
    err "INSTALL_DIR=${INSTALL_DIR} is not writable and passwordless sudo is unavailable"
else
    dest="${HOME}/.local/bin"
    SUDO=""
    mkdir -p "$dest"
fi

printf '==> Installing to %s/shuang...\n' "$dest"
$SUDO mkdir -p "$dest"
$SUDO mv -f "${tmpdir}/shuang" "${dest}/shuang"
$SUDO chmod +x "${dest}/shuang"

# --- PATH hint -----------------------------------------------------------------
case ":$PATH:" in
    *":${dest}:"*) ;;
    *)
        printf '==> NOTE: %s is not on your PATH.\n' "$dest"
        printf '    Add it to your shell profile, e.g.:\n'
        printf '    export PATH="%s:$PATH"\n' "$dest"
        ;;
esac

printf '==> Installed: '
"${dest}/shuang" --version
printf '\nRun "shuang --help" (or "shuang -h") to get started.\n'
