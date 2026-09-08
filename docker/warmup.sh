#!/bin/sh
# Build time smoke test: import one small, always present binary and run the
# export task over it.
#
# Two reasons this runs in the image build rather than in CI only:
#   1. Ghidra compiles everything under -scriptPath as one bundle at first use,
#      against whatever API this Ghidra release ships. A compile error here
#      fails the build instead of failing the first user's job. That covers
#      every task and every shared helper at once -- `selftest` reaches its
#      println only if the whole bundle compiled and every task in
#      RestRegistry constructed.
#   2. The compiled bundle is cached under $HOME, which is baked into the
#      image (not the /data volume), so it survives into every container.
#
# Adding a task needs no change here: selftest walks the registry.
set -eu

GHIDRA_HOME="${GHIDRAREST_GHIDRA_HOME:-/opt/ghidra}"
SCRIPT_DIR="${GHIDRAREST_SCRIPT_DIR:-/opt/ghidra-rest/scripts}"
WORK="$(mktemp -d)"
TARGET="${1:-/bin/date}"

mkdir -p "${WORK}/proj" "${WORK}/out"

echo "warmup: importing ${TARGET} with $(basename "${GHIDRA_HOME}")"

MAXMEM="${GHIDRAREST_JAVA_MAX_MEM:-2G}" \
	"${GHIDRA_HOME}/support/analyzeHeadless" \
	"${WORK}/proj" warmup \
	-import "${TARGET}" \
	-scriptPath "${SCRIPT_DIR}" \
	-postScript RestScript.java export "${WORK}/out" \
	-postScript RestScript.java selftest \
	-analysisTimeoutPerFile 600 \
	-deleteProject \
	| tee "${WORK}/headless.log"

if [ ! -s "${WORK}/out/summary.json" ]; then
	echo "warmup: analyzeHeadless produced no summary.json" >&2
	exit 1
fi

# The registry loaded and every task constructed. Without this a task could be
# broken in a way only its own first invocation would reveal.
if ! grep -q "RestScript: selftest ok" "${WORK}/headless.log"; then
	echo "warmup: selftest did not report; the script bundle did not load" >&2
	exit 1
fi

# Prove the artifacts are the shape the server expects, not just non-empty.
for f in summary.json functions.json strings.json symbols.json imports.json \
	exports.json xrefs.json types.json memory/index.json; do
	if [ ! -s "${WORK}/out/${f}" ]; then
		echo "warmup: missing artifact ${f}" >&2
		exit 1
	fi
done

echo "warmup: ok"
head -c 400 "${WORK}/out/summary.json"
echo

rm -rf "${WORK}"
