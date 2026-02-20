#!/bin/bash
set -euo pipefail

REPO="usenwep/nwep"

# Detect OS — respect GOOS when cross-compiling (e.g. GOOS=android).
# Fall back to uname for native builds.
if [ -n "${GOOS:-}" ]; then
    case "${GOOS}" in
        android) OS="android";;
        linux)   OS="linux";;
        darwin)  OS="darwin";;
        windows) OS="windows";;
        *)       OS="${GOOS}";;
    esac
else
    case "$(uname -s)" in
        Linux*)              OS="linux";;
        Darwin*)             OS="darwin";;
        MINGW*|MSYS*|CYGWIN*) OS="windows";;
        *) OS="$(uname -s | tr '[:upper:]' '[:lower:]')";;
    esac
fi

# Detect architecture — respect GOARCH when cross-compiling.
# Map Go arch names to the artifact naming convention.
if [ -n "${GOARCH:-}" ]; then
    case "${GOARCH}" in
        arm64) ARCH="aarch64";;
        arm)   ARCH="arm";;
        amd64) ARCH="x86_64";;
        386)   ARCH="x86";;
        *)     ARCH="${GOARCH}";;
    esac
else
    case "$(uname -m)" in
        x86_64|amd64)  ARCH="x86_64";;
        aarch64|arm64) ARCH="aarch64";;
        armv7*)        ARCH="arm";;
        i686|i386)     ARCH="x86";;
        *) ARCH="$(uname -m)";;
    esac
fi

# Fetch the latest release and find a matching asset
echo "Fetching latest release from ${REPO}..."
RELEASE_JSON="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")"
TAG="$(echo "${RELEASE_JSON}" | grep -m1 '"tag_name"' | sed 's/.*: *"\(.*\)".*/\1/')"

# Build a pattern to match: must contain our OS and ARCH
# For linux x86_64, prefer gcc variant; for linux aarch64, prefer gcc over cross
ASSET_URL=""
ASSET_NAME=""

# Get all asset download URLs and names
ASSETS="$(echo "${RELEASE_JSON}" | grep -E '"browser_download_url"' | sed 's/.*: *"\(.*\)".*/\1/')"

for url in ${ASSETS}; do
    name="$(basename "${url}")"
    # Must match OS and ARCH
    if echo "${name}" | grep -qi "${OS}" && echo "${name}" | grep -qi "${ARCH}"; then
        # Prefer gcc variant on linux if available, otherwise take first match
        if [ -z "${ASSET_URL}" ]; then
            ASSET_URL="${url}"
            ASSET_NAME="${name}"
        fi
        if echo "${name}" | grep -qi "gcc"; then
            ASSET_URL="${url}"
            ASSET_NAME="${name}"
            break
        fi
    fi
done

if [ -z "${ASSET_URL}" ]; then
    echo "Error: no matching asset found for ${OS}-${ARCH} in release ${TAG}" >&2
    echo "Available assets:" >&2
    for url in ${ASSETS}; do echo "  $(basename "${url}")" >&2; done
    exit 1
fi

mkdir -p third_party/nwep
cd third_party/nwep

# Record existing directories before extraction
BEFORE="$(ls -d nwep-* 2>/dev/null || true)"

echo "Downloading ${ASSET_NAME} (${TAG})..."
curl -fsSL -o "${ASSET_NAME}" "${ASSET_URL}"
if echo "${ASSET_NAME}" | grep -q '\.zip$'; then
    unzip -oq "${ASSET_NAME}"
else
    tar xzf "${ASSET_NAME}"
fi
rm "${ASSET_NAME}"

# Find the newly extracted directory
AFTER="$(ls -d nwep-* 2>/dev/null || true)"
TARGET=""
for d in ${AFTER}; do
    if ! echo "${BEFORE}" | grep -qx "${d}"; then
        TARGET="${d}"
        break
    fi
done

# Fallback: if no new directory appeared (already existed), pick by name
if [ -z "${TARGET}" ]; then
    TARGET="$(ls -d nwep-*"${OS}"*"${ARCH}"* 2>/dev/null | head -1 || true)"
fi
if [ -z "${TARGET}" ]; then
    TARGET="$(ls -d nwep-* 2>/dev/null | head -1 || true)"
fi
if [ -z "${TARGET}" ]; then
    echo "Error: no nwep build found in third_party/nwep/" >&2
    exit 1
fi

rm -f current
ln -s "${TARGET}" current
echo "nwep ready (${TARGET})"
