#!/bin/sh
# Build time smoke test: import one small, always present binary and run the
# export script over it.
#
# Two reasons this runs in the image build rather than in CI only:
#   1. The scripts are compiled by Ghidra at first use, against whatever API
#      this Ghidra release ships. A compile error here fails the build instead
#      of failing the first user's job. ApplySignature.java is run too, with an
#      empty ops file: no op is applied, but the class is compiled and cached,
#      and a signature apply is not the place to discover it does not build.
#   2. The compiled script is cached under $HOME, which is baked into the
#      image (not the /data volume), so it survives into every container.
set -eu

GHIDRA_HOME="${GHIDRAREST_GHIDRA_HOME:-/opt/ghidra}"
SCRIPT_DIR="${GHIDRAREST_SCRIPT_DIR:-/opt/ghidra-rest/scripts}"
WORK="$(mktemp -d)"
TARGET="${1:-/bin/date}"

mkdir -p "${WORK}/proj" "${WORK}/out"

# Empty on purpose: ApplySignature applies nothing and rewrites functions.json.
: > "${WORK}/ops.tsv"
: > "${WORK}/result.tsv"

echo "warmup: importing ${TARGET} with $(basename "${GHIDRA_HOME}")"

MAXMEM="${GHIDRAREST_JAVA_MAX_MEM:-2G}" \
	"${GHIDRA_HOME}/support/analyzeHeadless" \
	"${WORK}/proj" warmup \
	-import "${TARGET}" \
	-scriptPath "${SCRIPT_DIR}" \
	-postScript ExportJSON.java "${WORK}/out" \
	-postScript ApplySignature.java "${WORK}/out" "${WORK}/ops.tsv" "${WORK}/result.tsv" 30 \
	-analysisTimeoutPerFile 600 \
	-deleteProject

if [ ! -s "${WORK}/out/summary.json" ]; then
	echo "warmup: analyzeHeadless produced no summary.json" >&2
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
