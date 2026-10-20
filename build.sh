#!/bin/bash
#
# Build Meridian binaries for every supported platform into dist/.
#
# Usage:
#   ./build.sh              # version defaults to the current git tag
#   ./build.sh v1.6.0       # explicit version
#
set -e

VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null || echo dev)}"
BUILD_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OUTPUT_DIR="dist"
LDFLAGS="-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}"

mkdir -p "$OUTPUT_DIR"

PLATFORMS=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64" "windows/arm64")

echo "Building Meridian ${VERSION} (${BUILD_TIME})"

for platform in "${PLATFORMS[@]}"
do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}

    CLIENT_OUT="meridian-client-${GOOS}-${GOARCH}"
    SERVER_OUT="meridian-server-${GOOS}-${GOARCH}"

    if [ "$GOOS" = "windows" ]; then
        CLIENT_OUT+=".exe"
        SERVER_OUT+=".exe"
    fi

    echo "Building for $GOOS/$GOARCH..."
    env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
        go build -ldflags "$LDFLAGS" -o "$OUTPUT_DIR/$CLIENT_OUT" ./cmd/meridian-client
    env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 \
        go build -ldflags "$LDFLAGS" -o "$OUTPUT_DIR/$SERVER_OUT" ./cmd/meridian-server
done

# Regenerate checksums for everything we just built. SHA256SUMS must be
# excluded: listing it would hash the previous (or empty) file and make the
# checksum file fail its own verification.
(
    cd "$OUTPUT_DIR"
    # Build an explicit file list first: macOS find has no -printf, and globbing
    # would pick up a stale SHA256SUMS from the previous run.
    files=$(for f in *; do [ "$f" = "SHA256SUMS" ] || [ ! -f "$f" ] || echo "$f"; done | sort)
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum $files > SHA256SUMS
    else
        shasum -a 256 $files > SHA256SUMS
    fi
)

echo "Build complete. Files are in $OUTPUT_DIR/"
