#!/bin/sh
# Cross compile a release binary for every published target into /out.
#
# Runs inside the golang builder stage, once, on the build host's arch. The
# server is CGO-free, so CGO_ENABLED=0 lets one builder emit every GOOS/GOARCH
# below.
#
# These binaries are the server only: they still need a Ghidra install on the
# machine that runs them, pointed at by GHIDRAREST_GHIDRA_HOME. The container
# image is the batteries-included option.
#
# Naming is ghidrarest-<os>-<arch>[.exe]. The workflow repackages these into
# archives whose single member is a plain `ghidrarest`, so an extract drops the
# binary on PATH, not a long triple-suffixed name.
set -eu

VERSION="${VERSION:-dev}"
OUT=/out
mkdir -p "$OUT"

targets="linux/amd64 linux/arm64 linux/386 darwin/amd64 darwin/arm64 windows/amd64"

for t in $targets; do
	os="${t%/*}"
	arch="${t#*/}"
	name="ghidrarest-${os}-${arch}"
	ext=""
	if [ "$os" = "windows" ]; then
		ext=".exe"
	fi
	echo "building ${name}${ext} (version ${VERSION})"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "${OUT}/${name}${ext}" ./src
done

echo "built:"
ls -l "$OUT"
