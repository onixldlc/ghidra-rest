# ghidra-rest

A REST API in front of Ghidra's headless analyzer. Upload a binary, poll the
job, read back functions, decompiled C, strings, symbols, imports, exports,
types, cross references and raw bytes as JSON.

No AI, no plugins, no web UI, no MCP layer. It is a Go binary that runs
`analyzeHeadless`, and an HTTP API over what came out.

```
POST /v1/jobs  ->  analyzeHeadless -import ... -postScript ExportJSON.java
                   |
                   v
              artifacts/*.json on disk
                   |
                   v
GET /v1/results/{id}/functions, /function/{addr}/decompile, /strings, ...
```

## Why it looks like this

**Go, not Python or Bun.** The server does no analysis of its own; it spawns
Ghidra, waits, and serves JSON files. That workload wants a small static
binary with a real scheduler and cheap concurrency, not a runtime that adds
hundreds of megabytes to an image that is already carrying a JDK. The server
binary is about 6 MB and has zero dependencies -- `go list -m all` prints one
module, and CI fails if that ever changes.

**Analysis writes files, requests read files.** There is no long-lived Ghidra
process behind the API. One job is one `analyzeHeadless` run that exports a
complete artifact set and exits. A request never blocks on the decompiler, a
crashed analyzer cannot take the server with it, and results survive restarts
because they are just files.

**The cost of that choice:** decompilation happens up front for every function
(bounded by `decompile_max_funcs`), so submitting is slower than a design that
decompiles on demand, and functions past the cap have no C listing. For a
service that is asked for many functions of the same binary, doing it once is
the cheaper end of the trade.

## Quick start

```sh
docker run -d --name ghidra-rest -p 127.0.0.1:8080:8080 \
  -v ghidra-rest-data:/data \
  ghcr.io/onixldlc/ghidra-rest:latest

# submit a binary
curl -sS -F file=@/bin/ls -F decompile=true http://127.0.0.1:8080/v1/jobs

# {"deduplicated":false,"job":{"id":"1f3c...","status":"queued",...}}

# poll it
curl -sS http://127.0.0.1:8080/v1/jobs/1f3c...

# read results
curl -sS 'http://127.0.0.1:8080/v1/results/1f3c.../functions?q=main&limit=5'
curl -sS 'http://127.0.0.1:8080/v1/results/1f3c.../function/401000/decompile?format=c'
```

Or with compose:

```sh
docker compose up -d
```

The image is large (Ghidra plus a JDK). That is inherent, not sloppiness: the
analyzer, its sleigh specs and every processor module have to be there.

## API

Full reference — every endpoint, request field and response body — is in
**[docs/API.md](docs/API.md)**, and the same thing machine-readable in
**[docs/openapi.yaml](docs/openapi.yaml)** (OpenAPI 3.1: paste it into Swagger
Editor, or point a generator at it for a client). The short version:

| | |
| --- | --- |
| Submit | `POST /v1/jobs` (multipart, part named `file`) or `POST /v1/jobs/base64` |
| Poll | `GET /v1/jobs/{id}` until `status` is `done` |
| Read | `GET /v1/results/{id}/{summary,functions,strings,symbols,imports,exports,types,memory}` |
| Dig | `/function/{addr}`, `/function/{addr}/decompile`, `/xrefs/{addr}`, `/hexdump/{addr}` |
| Grab it all | `GET /v1/jobs/{id}/export` -> one zip |

Lists take `?limit=`, `?offset=` and `?q=`. `GET /v1/capabilities` reports the
live limits and endpoint list from the running server, which is the only
description of the API that cannot go stale.

## Running the release binary

The release assets are the **server only**. They contain no Ghidra and no
export script -- the container image is the batteries-included option.

Every target ships as a zip whose single member is a plain `ghidrarest`
(`ghidrarest.exe` on windows), so an extract drops it straight on PATH.

```sh
V=v1.0.0
BASE=https://github.com/onixldlc/ghidra-rest/releases/download/$V
curl -LO $BASE/ghidrarest-linux-amd64-$V.zip
curl -LO $BASE/checksums.txt
sha256sum -c --ignore-missing checksums.txt
unzip ghidrarest-linux-amd64-$V.zip
sudo install -m755 ghidrarest /usr/local/bin/
```

You need three things on that host:

- **JDK 21.** Ghidra rejects other majors, and wants a JDK, not a JRE.
- **A Ghidra install.** Unzip the NSA release; `support/analyzeHeadless` must exist.
- **`scripts/ExportJSON.java`** from this repo. It is not in the archive:

```sh
mkdir -p ~/ghidra-rest/scripts
curl -Lo ~/ghidra-rest/scripts/ExportJSON.java \
  https://raw.githubusercontent.com/onixldlc/ghidra-rest/$V/scripts/ExportJSON.java
```

Then point the server at both and run it:

```sh
GHIDRAREST_GHIDRA_HOME=/opt/ghidra \
GHIDRAREST_SCRIPT_DIR=$HOME/ghidra-rest/scripts \
GHIDRAREST_DATA_DIR=$HOME/ghidra-rest/data \
GHIDRAREST_ADDR=127.0.0.1:8080 \
ghidrarest
```

The startup log prints the Ghidra version it found; `unknown` means
`GHIDRAREST_GHIDRA_HOME` is wrong. The first job is slower than the rest:
Ghidra compiles the export script once and caches the bundle under
`$HOME/.config/ghidra/`, so **HOME has to be writable**.

Two flags: `ghidrarest -version`, and `ghidrarest -healthcheck` (exits 0 or 1
after probing `127.0.0.1:<port>/healthz` -- it is what the image's HEALTHCHECK
runs, which is why the image ships no curl).

The windows asset holds `ghidrarest.exe`, same variables. Cancel there only
kills the launcher, not the JVM: POSIX process groups do not exist on windows.

## Configuration

Everything is environment variables, all prefixed `GHIDRAREST_`. The full list
with defaults and explanations is in [.env.example](.env.example). A bad value
logs a warning and falls back to the default rather than exiting — under a
restart policy, a fatal config error is just a crash loop.

| Variable | Default | Notes |
| --- | --- | --- |
| `GHIDRAREST_ADDR` | `:8080` | Listen address. |
| `GHIDRAREST_DATA_DIR` | `/data` | One directory per job under `jobs/`. |
| `GHIDRAREST_GHIDRA_HOME` | `/opt/ghidra` | Must contain `support/analyzeHeadless`. |
| `GHIDRAREST_SCRIPT_DIR` | `/opt/ghidra-rest/scripts` | Where `ExportJSON.java` lives. |
| `GHIDRAREST_MAX_CONCURRENT` | half the CPUs, max 4 | Concurrent Ghidra runs. Each is a JVM. |
| `GHIDRAREST_QUEUE_SIZE` | 64 | Submissions beyond this get `503`. |
| `GHIDRAREST_JAVA_MAX_MEM` | `2G` | Heap per run, passed through as Ghidra's `MAXMEM`. |
| `GHIDRAREST_ANALYSIS_TIMEOUT` | `30m` | Ghidra's own analysis timer is set to 3/4 of this, so it stops in time to still write results. |
| `GHIDRAREST_MAX_UPLOAD_BYTES` | 256 MiB | |
| `GHIDRAREST_DECOMPILE` | `true` | Default for the `decompile` option. |
| `GHIDRAREST_DECOMPILE_MAX_FUNCS` | 20000 | |
| `GHIDRAREST_DECOMPILE_TIMEOUT` | 60 | Seconds per function. |
| `GHIDRAREST_MAX_EXPORT_BYTES` | 256 MiB | Cap on the raw memory dumps per job. |
| `GHIDRAREST_MAX_HEXDUMP_BYTES` | 65536 | Cap on one hexdump request. |
| `GHIDRAREST_PAGE_SIZE` / `_MAX_PAGE_SIZE` | 100 / 5000 | List paging. |
| `GHIDRAREST_API_TOKEN` | empty | Bearer token (or `X-API-Key`). Empty means open. |
| `GHIDRAREST_CORS_ORIGIN` | empty | Set to enable CORS for one origin. |
| `GHIDRAREST_RETENTION` | unset | Delete finished jobs older than this. Unset keeps them. |
| `GHIDRAREST_KEEP_PROJECT` | `false` | Keep the Ghidra project dir per job. Large; debugging only. |
| `GHIDRAREST_MAX_CPU` | 0 | Passed to `analyzeHeadless -max-cpu` when > 0. |
| `GHIDRAREST_VERBOSE` | `false` | Log every request, not just 4xx/5xx. |

Memory is the real constraint: `MAX_CONCURRENT × JAVA_MAX_MEM` is roughly the
peak. The defaults suit a 4-8 GB host.

## Security

- Binaries are **analysed, never executed**. Ghidra disassembles them.
- Uploads still come from whoever can reach the port, so the compose file
  binds to `127.0.0.1` by default and the container runs as a non-root user
  (`ghidra`) with the API token off but available.
- Analysis is not a sandbox boundary. A malicious file that finds a bug in a
  Ghidra loader gets whatever the container has. Run this where that is
  acceptable: a lab, a CI runner, a host you can rebuild.
- The upload cap, the queue depth, the analysis timeout, the decompile cap and
  the memory-export cap all exist so one submission cannot fill the disk or
  pin the CPUs forever.
- Submitted filenames are reduced to a sanitised basename, so a job cannot
  write outside its own directory.

## Layout

```
src/main.go                        startup, signals, graceful shutdown, -healthcheck/-version
src/internal/config/config.go      environment -> Config
src/internal/jobs/jobs.go          job records, queue, worker pool, on-disk store
src/internal/jobs/ghidra.go        the analyzeHeadless invocation
src/internal/jobs/artifacts.go     artifact parsing, paging, address normalisation, hexdump
src/internal/jobs/proc_unix.go     process-group kill, so cancelling kills the JVM too
src/internal/jobs/proc_windows.go  the portable fallback
src/internal/api/server.go         routes, middleware (auth, CORS, logging, recovery)
src/internal/api/handlers.go       service info, submission, job lifecycle
src/internal/api/results.go        result endpoints over the artifact files
src/internal/api/export.go         zip export of a job's artifacts
scripts/ExportJSON.java            the Ghidra post-script that writes every artifact
docs/                              API.md (prose), openapi.yaml (OpenAPI 3.1)
docker/                            Dockerfile, entrypoint.sh, verify.sh, warmup.sh, build-dist.sh
```

`internal/jobs` knows nothing about HTTP and `internal/api` never runs Ghidra:
the API layer only reads files that a finished job left behind. `main` is the
only package outside `internal`, which keeps the import graph one-directional
and lets `go vet ./...` catch a layering mistake as a compile error.

On disk, per job:

```
/data/jobs/<id>/meta.json          the job record
/data/jobs/<id>/input/<name>       the submitted bytes
/data/jobs/<id>/headless.log       analyzeHeadless output
/data/jobs/<id>/artifacts/         summary, functions, strings, ...
/data/jobs/<id>/artifacts/decompiled/<addr>.json
/data/jobs/<id>/artifacts/memory/block-N.bin
/data/jobs/<id>/project/           Ghidra project, deleted unless KEEP_PROJECT
```

## Building

```sh
docker build -f docker/Dockerfile --target runtime -t ghidra-rest:dev .
```

The build downloads the pinned Ghidra release and checks its sha256, then runs
`warmup.sh`: one real headless analysis of a stock system binary. That fails
the build if `ExportJSON.java` does not compile against this Ghidra's API, and
leaves the compiled script cached in the image so the first job does not pay
for `javac`.

Without Docker you need a JDK 21 and a Ghidra install:

```sh
go build -o ghidrarest ./src
GHIDRAREST_GHIDRA_HOME=/opt/ghidra \
GHIDRAREST_SCRIPT_DIR=./scripts \
GHIDRAREST_DATA_DIR=./data \
./ghidrarest
```

For the published binaries rather than a local build, see
[Running the release binary](#running-the-release-binary).

## CI

[.github/workflows/build.yml](.github/workflows/build.yml) vets, tests and
builds on every push and PR. It smoke tests the built image by submitting a
real binary and waiting for the analysis to reach `done`, because an image
where Ghidra cannot start answers `/healthz` perfectly well. Only a pushed
`v*` tag logs in, publishes the multi-arch image to GHCR and cuts a release.

## Ghidra version

Pinned in [docker/Dockerfile](docker/Dockerfile) as `GHIDRA_VERSION` with its
`GHIDRA_SHA256`. To move: change both, rebuild, and let `warmup.sh` tell you
whether the export script still compiles.
