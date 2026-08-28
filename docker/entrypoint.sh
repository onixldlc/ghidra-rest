#!/bin/sh
set -eu

DATA_DIR="${GHIDRAREST_DATA_DIR:-/data}"
GHIDRA_HOME="${GHIDRAREST_GHIDRA_HOME:-/opt/ghidra}"

# The data directory is normally a volume, so its ownership comes from the
# host and may not match the runtime user. Fail loudly instead of dying on
# the first upload.
if [ ! -w "${DATA_DIR}" ]; then
    echo "entrypoint: data dir ${DATA_DIR} is not writable by $(id -un)" >&2
    echo "entrypoint: chown it on the host to uid $(id -u), or bind-mount a writable path" >&2
    exit 1
fi

if [ ! -x "${GHIDRA_HOME}/support/analyzeHeadless" ]; then
    echo "entrypoint: no analyzeHeadless under ${GHIDRA_HOME}" >&2
    exit 1
fi

# Ghidra writes its settings and its compiled-script cache under $HOME. If
# that is unset or read-only every job pays a javac compile, or fails.
if [ -z "${HOME:-}" ] || [ ! -w "${HOME}" ]; then
    echo "entrypoint: HOME=${HOME:-unset} is not writable; Ghidra needs it for its settings dir" >&2
    exit 1
fi

# Deliberately NOT exec: this shell stays as pid 1 to reap orphans.
#
# Cancelling a job kills the analyzeHeadless process group. The launcher shell
# dies first, so its JVM is reparented to pid 1 and stays a zombie unless pid 1
# waits for it. The server cannot do that reaping itself without racing
# os/exec for its own children's exit statuses, so pid 1 is a shell blocked in
# `wait`, which consumes any orphan that lands on it.
#
# The trap keeps `docker stop` graceful: SIGTERM is forwarded to the server,
# which finishes shutting down its HTTP listener before this shell exits.
/usr/local/bin/ghidrarest "$@" &
pid=$!

forward() {
    kill -TERM "${pid}" 2>/dev/null || true
}
trap forward TERM INT

wait "${pid}"
code=$?

# A trapped signal makes `wait` return 128+signo before the child has actually
# exited; wait again for its real status.
if [ "${code}" -gt 128 ]; then
    wait "${pid}"
    code=$?
fi

exit "${code}"
