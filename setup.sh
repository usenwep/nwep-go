#!/bin/bash
set -euo pipefail

VERSION="0.1.0"

# Detect OS
case "$(uname -s)" in
    Linux*)  OS="linux";;
    Darwin*) OS="darwin";;
    MINGW*|MSYS*|CYGWIN*) OS="windows";;
    *) OS="$(uname -s | tr '[:upper:]' '[:lower:]')";;
esac

# Detect architecture
case "$(uname -m)" in
    x86_64|amd64)  ARCH="x86_64";;
    aarch64|arm64) ARCH="aarch64";;
    armv7*)        ARCH="armv7";;
    *) ARCH="$(uname -m)";;
esac

PLATFORM="${OS}-${ARCH}"
DIR="nwep-${VERSION}-${PLATFORM}"
TARBALL="${DIR}.tar.gz"
URL="https://github.com/niceweb/nwep/releases/download/v${VERSION}/${TARBALL}"

mkdir -p third_party/nwep
cd third_party/nwep

# Download if not already present
if [ ! -d "${DIR}" ]; then
    echo "Downloading nwep ${VERSION} for ${PLATFORM}..."
    curl -fsSL -o "${TARBALL}" "${URL}"
    tar xzf "${TARBALL}"
    rm "${TARBALL}"
fi

# Create/update the 'current' symlink
# If the detected platform dir exists, use it; otherwise pick the first available
if [ -d "${DIR}" ]; then
    TARGET="${DIR}"
else
    TARGET="$(ls -d nwep-${VERSION}-* 2>/dev/null | head -1 || true)"
    if [ -z "${TARGET}" ]; then
        echo "Error: no nwep build found in third_party/nwep/" >&2
        exit 1
    fi
    echo "Warning: ${DIR} not found, using ${TARGET}"
fi

rm -f current
ln -s "${TARGET}" current
echo "nwep ${VERSION} ready (${TARGET})"
