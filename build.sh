#!/bin/bash
set -e
VERSION="v1.3.0"
OUTPUT_DIR="dist"
mkdir -p $OUTPUT_DIR

PLATFORMS=("linux/amd64" "linux/arm64" "darwin/amd64" "darwin/arm64" "windows/amd64" "windows/arm64")

for platform in "${PLATFORMS[@]}"
do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    
    CLIENT_OUT="meridian-client-${GOOS}-${GOARCH}"
    SERVER_OUT="meridian-server-${GOOS}-${GOARCH}"
    
    if [ $GOOS = "windows" ]; then
        CLIENT_OUT+=".exe"
        SERVER_OUT+=".exe"
    fi
    
    echo "Building for $GOOS/$GOARCH..."
    env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-s -w" -o $OUTPUT_DIR/$CLIENT_OUT ./cmd/meridian-client
    env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-s -w" -o $OUTPUT_DIR/$SERVER_OUT ./cmd/meridian-server
done

echo "Build complete. Files are in $OUTPUT_DIR/"
