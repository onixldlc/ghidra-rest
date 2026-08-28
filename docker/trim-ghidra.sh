#!/bin/sh
# Strip the parts of a Ghidra install that headless analysis cannot use.
#
# Ghidra unpacks to about 800 MB. Most of that is not analysis: a Windows
# debugger agent, a version-tracking server, BSim's database tooling, the
# packaged extension archives. Removing them is not a diet, it is deleting
# code paths this service never reaches.
#
# Tiers, chosen with GHIDRA_TRIM:
#   none      leave the install exactly as shipped     (~800 MB)
#   standard  drop what headless cannot use            (~530 MB)  [default]
#   minimal   also drop the Function ID databases      (~330 MB)
#
# `minimal` is the only tier that changes analysis results: without the FID
# databases Ghidra stops naming statically linked library functions, so a
# stripped static binary keeps FUN_00401000 names where it would otherwise say
# `memcpy`. Everything `standard` removes is inert for this service.
set -eu

TRIM="${GHIDRA_TRIM:-standard}"
GHIDRA="${1:-/opt/ghidra}"

before="$(du -sm "${GHIDRA}" | cut -f1)"

drop() {
	# Quiet about paths that a future Ghidra release renamed or removed.
	rm -rf "$@"
}

if [ "${TRIM}" = "none" ]; then
	echo "trim: keeping the full install (${before} MB)"
	exit 0
fi

# Documentation and the GUI launcher's Eclipse integration.
drop "${GHIDRA}/docs" "${GHIDRA}/Extensions/Eclipse" "${GHIDRA}/GettingStarted.html"

# The debugger: agents, traces and the whole Debug module tree. analyzeHeadless
# never starts a target.
drop "${GHIDRA}/Ghidra/Debug"

# Ghidra Server and its client tooling: this service uses local projects only.
drop "${GHIDRA}/Ghidra/Features/GhidraServer" "${GHIDRA}/server"

# BSim: similarity search against an external database nobody here provisions.
drop "${GHIDRA}/Ghidra/Features/BSim" "${GHIDRA}/Ghidra/Features/BSimPlugin"

# PyGhidra and the packaged extension archives. The export script is Java, and
# extensions are shipped as zips that are only unpacked if a user installs one.
drop "${GHIDRA}/Ghidra/Features/PyGhidra" "${GHIDRA}/Extensions"

# Version tracking is a GUI workflow.
drop "${GHIDRA}/Ghidra/Features/VersionTracking"

if [ "${TRIM}" = "minimal" ]; then
	# The FID databases are ~195 MB of function signatures. Dropping the data
	# but keeping the module leaves the analyzer in place with nothing to
	# match, which is a clean no-op rather than a missing-module error.
	find "${GHIDRA}/Ghidra/Features/FunctionID/data" -name '*.fidb' -delete 2>/dev/null || true
fi

after="$(du -sm "${GHIDRA}" | cut -f1)"
echo "trim: ${TRIM}: ${before} MB -> ${after} MB"
