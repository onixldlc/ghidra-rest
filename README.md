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

---

# API reference

## Conventions

**Base URL.** Everything versioned lives under `/v1`. `/healthz` is outside
the version prefix on purpose: it is the container healthcheck and must never
change shape.

**Content types.** Responses are `application/json; charset=utf-8` unless the
endpoint is documented otherwise (`text/plain` for logs and `?format=text`,
`text/x-c` for `?format=c`, `application/octet-stream` for raw bytes and job
input, `application/zip` for exports).

**Authentication.** If `GHIDRAREST_API_TOKEN` is set, every endpoint except
`/healthz` requires it, as either header:

```
Authorization: Bearer <token>
X-API-Key: <token>
```

Comparison is constant time. A missing or wrong token gets `401` with a
`WWW-Authenticate: Bearer realm="ghidra-rest"` header. If the variable is
unset the API is fully open — that is the default, and the log says so at
startup.

**CORS.** Off unless `GHIDRAREST_CORS_ORIGIN` is set; when set, that origin is
echoed and `OPTIONS` preflights answer `204`.

**Addresses.** `{addr}` accepts `401000`, `0x401000`, `00401000` and
`RAM:00401000` — all normalise to the same key (lower case, no `0x`, no
leading zeros, address space prefix kept). Responses always use the normalised
form in `address`, and keep Ghidra's own rendering in `address_display`.

**Paging and search.** Every list endpoint takes:

| Param | Default | Notes |
| --- | --- | --- |
| `limit` | `GHIDRAREST_PAGE_SIZE` (100) | Clamped to `GHIDRAREST_MAX_PAGE_SIZE` (5000). |
| `offset` | 0 | Past the end returns an empty `items`, not an error. |
| `q` | none | Case-insensitive substring over whichever of `name`, `full_name`, `value`, `address`, `library`, `type`, `kind` that artifact has. |

Envelope:

```json
{
  "total": 575,
  "count": 2,
  "limit": 2,
  "offset": 0,
  "query": "main",
  "items": [ /* artifact entries */ ]
}
```

`total` is the count *after* filtering, so `?q=` plus paging is coherent.

**Errors.** Every error is the same object:

```json
{"error": "job is running, results are not available", "status": 409}
```

| Status | When |
| --- | --- |
| 400 | Malformed body, bad base64, missing `file` part, empty upload. |
| 401 | Token required and missing/wrong. |
| 404 | No such job, endpoint, address, or the artifact was never written. |
| 409 | Results requested before the job is `done`; delete of a non-terminal job; cancel of an already-finished job. |
| 413 | Upload over `GHIDRAREST_MAX_UPLOAD_BYTES`. |
| 416 | Hexdump address is inside a known block but past its exported bytes. |
| 503 | Queue full (`Retry-After: 30`). |

---

## Service

### `GET /healthz`

Plain text `ok`. Never requires the token. This is what the image's
`HEALTHCHECK` runs (via `ghidrarest -healthcheck`, so the image needs no curl).

### `GET /v1/health`

```json
{"status": "ok", "jobs": 12, "running": 1, "queued": 3, "workers": 4}
```

### `GET /v1/version`

```json
{
  "service": "ghidra-rest",
  "version": "1.0.0",
  "api": "v1",
  "ghidra_version": "12.1.3",
  "ghidra_home": "/opt/ghidra"
}
```

`ghidra_version` is read out of `$GHIDRA_HOME/Ghidra/application.properties`
at startup, not from an env var, so it cannot lie about what analysed a binary.

### `GET /v1/capabilities`

Limits, feature list and the full endpoint list. Machine-readable equivalent of
this section, useful for clients that want to discover caps rather than hard
code them.

```json
{
  "service": "ghidra-rest",
  "version": "1.0.0",
  "ghidra_version": "12.1.3",
  "limits": {
    "max_upload_bytes": 268435456,
    "max_concurrent": 4,
    "queue_size": 64,
    "analysis_timeout_sec": 1800,
    "decompile_timeout_sec": 60,
    "decompile_max_funcs": 20000,
    "max_export_bytes": 268435456,
    "max_page_size": 5000,
    "max_hexdump_bytes": 65536
  },
  "features": ["multipart-upload", "base64-upload", "sha256-dedup", "cancel", "..."],
  "endpoints": ["GET /healthz", "POST /v1/jobs", "..."]
}
```

---

## Jobs

### `POST /v1/jobs` — submit (multipart)

`multipart/form-data`. The binary goes in a part named `file`; everything else
is an ordinary form field.

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/jobs \
  -F file=@/bin/ls \
  -F name=ls.bin \
  -F decompile=true \
  -F decompile_max_funcs=5000 \
  -F analysis_timeout_sec=900
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `file` | file | **required** | The binary. Sent as bytes, never executed. |
| `name` | string | the upload's filename | Stored name. Sanitised to a basename, max 128 chars. |
| `decompile` | bool | `GHIDRAREST_DECOMPILE` (true) | Decompile functions during the run. `1`/`true`/`yes` are true. |
| `decompile_max_funcs` | int | 20000 | Stop decompiling after this many functions. Analysis still completes. |
| `decompile_timeout_sec` | int | 60 | Per-function decompiler timeout. |
| `analysis_timeout_sec` | int | 1800 | Wall-clock budget for the whole job. Ghidra's own `-analysisTimeoutPerFile` is set to 3/4 of it so the exporter still gets to run. |
| `processor` | string | auto | Force a language id, e.g. `x86:LE:64:default`. |
| `compiler_spec` | string | auto | Force a compiler spec id, e.g. `gcc`. |
| `loader` | string | auto | Force a Ghidra loader, e.g. `BinaryLoader`. |
| `force` | bool | false | Analyse even if these exact bytes were analysed before. |

**Response** `202 Accepted` (new job) or `200 OK` (deduplicated), with a
`Location: /v1/jobs/{id}` header:

```json
{
  "deduplicated": false,
  "job": {
    "id": "346ab74fe7fee34191cc8adb",
    "filename": "ls.bin",
    "size": 143368,
    "sha256": "833d6f9cf3ede2225d80eaa159ef78a141c92842a691179aec37d182cc808a5c",
    "status": "queued",
    "options": {
      "decompile": true,
      "decompile_max_funcs": 20000,
      "decompile_timeout_sec": 60,
      "analysis_timeout_sec": 1800
    },
    "created_at": "2026-08-27T21:42:04Z",
    "ghidra_version": "12.1.3"
  }
}
```

Identical bytes are deduplicated by sha256: resubmitting returns `200` with
the existing job and `"deduplicated": true` instead of burning another Ghidra
run. Jobs that ended `failed` or `canceled` are not reused. `force=true` opts
out entirely.

### `POST /v1/jobs/base64` — submit (JSON)

Same thing for clients that would rather not build a multipart body.

```sh
curl -sS -X POST http://127.0.0.1:8080/v1/jobs/base64 \
  -H 'Content-Type: application/json' \
  -d "{\"filename\":\"ls.bin\",\"data_base64\":\"$(base64 -w0 /bin/ls)\"}"
```

| Key | Type | Notes |
| --- | --- | --- |
| `data_base64` | string | **required.** Standard base64. `data` is accepted as an alias. |
| `filename` | string | Stored name. |
| `force` | bool | As above. |
| `decompile` | bool or null | Null/absent means the server default. |
| `decompile_max_funcs`, `decompile_timeout_sec`, `analysis_timeout_sec` | int | 0 means the server default. |
| `processor`, `compiler_spec`, `loader` | string | As above. |

Response is identical to the multipart endpoint. Note the body limit is
`max_upload_bytes × 4/3 + 1 MiB`, since base64 costs a third more than the
payload it carries.

### The job record

Returned by every job endpoint and stored at `meta.json`.

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | 24 hex chars, from `crypto/rand`. |
| `filename`, `size`, `sha256` | string/int/string | About the submitted bytes. |
| `status` | enum | `queued` → `running` → `done` \| `failed` \| `canceled`. |
| `error` | string | Set on `failed`/`canceled`. Failures carry the tail of the headless log. |
| `options` | object | The **resolved** options — what actually ran, not what was asked for. |
| `created_at`, `started_at`, `finished_at` | RFC3339 UTC | Last two absent until they happen. |
| `duration_ms` | int | Analysis wall time. |
| `ghidra_version` | string | The Ghidra that produced this. |
| `language`, `executable_format` | string | Lifted from `summary.json` when the job finishes. |
| `counts` | object | `{"functions":575,"strings":510,"symbols":1833,"imports":122,"exports":18,"types":76,"xref_entries":1483,"decompiled":575,"decompile_failed":0}` |

Jobs that were `queued` or `running` when the process died come back as
`failed` with `"interrupted by a server restart"` — half-written artifacts are
never presented as results.

### `GET /v1/jobs` — list

`?status=queued|running|done|failed|canceled`, plus `limit`/`offset`. Newest
first.

```json
{"total": 12, "count": 2, "limit": 2, "offset": 0, "jobs": [ /* job records */ ]}
```

### `GET /v1/jobs/{id}`

One job record. `404` if unknown.

### `POST /v1/jobs/{id}/cancel`

Cancels a queued job outright; for a running one, kills the whole
`analyzeHeadless` process group (the launcher shell *and* the JVM it exec'd)
and marks the job `canceled`. `200` with the updated record, `404` unknown,
`409` if it already finished.

### `DELETE /v1/jobs/{id}`

Removes the job directory — input, log and artifacts. `204` on success, `409`
while it is still queued or running (cancel it first), `404` unknown.

### `GET /v1/jobs/{id}/log`

The raw `analyzeHeadless` transcript as `text/plain`, starting with the exact
argv that was run. `?tail=4000` returns only the last N bytes, which is what
you want on a job that has been running for twenty minutes. Available while
the job is still running.

### `GET /v1/jobs/{id}/input`

The submitted bytes back, `application/octet-stream` with a
`Content-Disposition` filename.

### `GET /v1/jobs/{id}/export`

Every artifact plus `meta.json` and `headless.log` as one deflate zip,
streamed rather than staged on disk. Requires `status: done`.

```
artifacts/summary.json
artifacts/functions.json
artifacts/decompiled/<addr>.json
artifacts/memory/block-0.bin
meta.json
headless.log
```

---

## Results

All of these need `status: done`; anything earlier answers `409`, and an
unknown id answers `404`. If a particular artifact was never written (for
example decompilation on a `decompile=false` job) the endpoint answers `404`
with a reason.

### `GET /v1/results/{id}/summary`

The whole `summary.json`, served through untouched.

```json
{
  "name": "ls.bin",
  "executable_format": "Executable and Linking Format (ELF)",
  "md5": "5229649db44886ed74f9096b373032f4",
  "sha256": "833d6f9cf3ede2225d80eaa159ef78a141c92842a691179aec37d182cc808a5c",
  "language": "x86:LE:64:default",
  "processor": "x86",
  "endian": "little",
  "address_size": 64,
  "compiler_spec": "gcc",
  "image_base": "100000",
  "min_address": "100000",
  "max_address": "_elfsectionheaders::77f",
  "ghidra_version": "12.1.3",
  "memory_bytes_exported": 157979,
  "counts": {"functions": 575, "strings": 510, "symbols": 1833, "imports": 122,
             "exports": 18, "types": 76, "xref_entries": 1483,
             "decompiled": 575, "decompile_failed": 0},
  "entry_points": ["127280", "11b000", "104ad7"]
}
```

`summary.json` is written **last** by the export script, so its presence is
what marks an artifact set complete.

### `GET /v1/results/{id}/functions`

Paged list. `?q=` matches name and address.

```json
{
  "address": "104000",
  "address_display": "00104000",
  "name": "_DT_INIT",
  "namespace": "Global",
  "signature": "undefined _DT_INIT(void)",
  "calling_convention": "unknown",
  "return_type": "undefined",
  "size": 23,
  "parameter_count": 0,
  "is_thunk": false,
  "is_external": false,
  "is_inline": false,
  "has_varargs": false,
  "no_return": false,
  "stack_frame_size": 8,
  "parameters": [{"name": "param_1", "type": "int", "ordinal": 0}],
  "calls": [{"address": "129228", "name": "__gmon_start__"}],
  "called_by": []
}
```

### `GET /v1/results/{id}/function/{addr}`

One function record — the same object, unwrapped, no paging envelope. `404` if
no function starts at that address.

### `GET /v1/results/{id}/function/{addr}/decompile`

```json
{
  "address": "104000",
  "address_display": "00104000",
  "name": "_DT_INIT",
  "signature": "void _DT_INIT(void);",
  "ok": true,
  "error": "",
  "c": "\nvoid _DT_INIT(void)\n\n{\n  __gmon_start__();\n  return;\n}\n\n"
}
```

`?format=c` returns just the C as `text/x-c`, which is what you want in a
terminal or an editor.

A `404` here distinguishes its causes: submitted with `decompile=false`, past
`decompile_max_funcs`, external, or not a function.

### `GET /v1/results/{id}/decompiled`

Index of what was decompiled and how big each listing is — cheaper than
walking every function.

```json
{"address": "104030", "name": "__ctype_toupper_loc", "ok": true, "length": 203}
```

### `GET /v1/results/{id}/xrefs/{addr}`

References in both directions.

```json
{
  "address": "104000",
  "to":   [{"address": "1000f8", "address_display": "001000f8", "type": "DATA",
            "is_call": false, "is_jump": false, "is_data": true, "source": "IMPORTED"}],
  "from": [],
  "indexed": true
}
```

`indexed: false` with empty arrays means the address is not in the xref index
— which distinguishes "nothing references this" from a typo'd address. Always
`200`.

### `GET /v1/results/{id}/strings`

```json
{"address": "100394", "address_display": "00100394",
 "value": "/lib64/ld-linux-x86-64.so.2", "type": "TerminatedCString",
 "length": 28, "reference_count": 2}
```

### `GET /v1/results/{id}/symbols`

Symbol table, dynamic symbols excluded.

```json
{"address": "external:1", "address_display": "EXTERNAL:00000001",
 "name": "__ctype_toupper_loc", "full_name": "<EXTERNAL>::__ctype_toupper_loc",
 "type": "Function", "source": "IMPORTED", "namespace": "<EXTERNAL>",
 "primary": true, "global": false, "external": true, "reference_count": 1}
```

### `GET /v1/results/{id}/imports`

External locations with their library. `thunk_address` is where to look the
symbol up in the other artifacts.

```json
{"library": "<EXTERNAL>", "name": "getenv", "original_name": "",
 "is_function": true, "address": "", "thunk_address": "external:2"}
```

### `GET /v1/results/{id}/exports`

External entry points.

```json
{"address": "127290", "address_display": "00127290", "name": "optind", "is_function": false}
```

### `GET /v1/results/{id}/types`

Structs, unions, enums, typedefs and function definitions from the program's
data type manager. `?q=` matches name, path and kind.

```json
{"name": "__blkcnt_t", "path": "/types.h/__blkcnt_t", "kind": "typedef",
 "size": 8, "base_type": "long"}
```

Struct and union entries additionally carry `fields[]` with each member's
`name`, `type`, `offset` and `size`; enums carry `values[]`.

### `GET /v1/results/{id}/memory`

The memory block index, served whole (not paged).

```json
[{"name": "segment_2.1", "start": "100000", "start_display": "00100000",
  "end": "10034f", "size": 848, "read": true, "write": false, "execute": false,
  "volatile": false, "initialized": true, "overlay": false, "type": "Default",
  "source": "Elf Loader", "file": "block-0.bin", "bytes_exported": 848}]
```

`bytes_exported` can be below `size`: the exporter stops at
`GHIDRAREST_MAX_EXPORT_BYTES` across the whole program.

### `GET /v1/results/{id}/hexdump/{addr}`

Reads from the block dumps. `?length=` defaults to 256 and is clamped to
`GHIDRAREST_MAX_HEXDUMP_BYTES` (64 KiB). Reads stop at the end of a block
rather than running into the next one, which may not be contiguous.

| `format` | Response |
| --- | --- |
| absent (default) | JSON: `address`, `block`, `length`, `base64`, `hex` |
| `text` | `text/plain`, `hexdump -C` layout with program addresses in the left column |
| `raw` | `application/octet-stream`, the bytes |

```json
{
  "address": "100394",
  "block": "segment_2.1",
  "length": 16,
  "base64": "L2xpYjY0L2xkLWxpbnV4...",
  "hex": "00100394  2f 6c 69 62 36 34 2f 6c  64 2d 6c 69 6e 75 78 2d  |/lib64/ld-linux-|\n"
}
```

`404` if the address is in no block or the block is uninitialised (`.bss`);
`416` if it is inside a block but past the exported bytes.

---

## End to end

```sh
API=http://127.0.0.1:8080

id=$(curl -sS -F file=@/bin/ls $API/v1/jobs | jq -r .job.id)

# wait for it
until [ "$(curl -sS $API/v1/jobs/$id | jq -r .status)" != "running" ] \
   && [ "$(curl -sS $API/v1/jobs/$id | jq -r .status)" != "queued" ]; do sleep 5; done

curl -sS $API/v1/results/$id/summary | jq .counts

# find something and read it
addr=$(curl -sS "$API/v1/results/$id/functions?q=main&limit=1" | jq -r .items[0].address)
curl -sS "$API/v1/results/$id/function/$addr/decompile?format=c"
curl -sS "$API/v1/results/$id/xrefs/$addr" | jq '.to | length'

# everything at once
curl -sS -o artifacts.zip "$API/v1/jobs/$id/export"
```

---

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

Released binaries are the server only -- they still need a Ghidra install.

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
