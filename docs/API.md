# ghidra-rest API reference

Every endpoint, its request fields and its response body. The same API in
machine-readable form is [openapi.yaml](openapi.yaml) (OpenAPI 3.1). For what
this service is and how to run it, see [../README.md](../README.md).

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
| `counts` | object | `{"functions":575,"strings":510,"symbols":1833,"imports":122,"exports":18,"types":76,"xref_entries":1483,"instructions":21609,"decompiled":575,"decompile_failed":0}` |

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
artifacts/disasm/<addr>.json
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

### `GET /v1/results/{id}/disasm/{addr}`

The instruction listing for one function, as Ghidra's listing renders it.
Written during the same export pass as everything else, so no second analysis
run is involved.

```json
{
  "address": "104310",
  "address_display": "00104310",
  "name": "memset",
  "instructions": [
    {"address": "104310", "address_display": "00104310", "bytes": "ff2582ac0300",
     "mnemonic": "JMP", "operands": "qword ptr [->memset]", "text": "JMP qword ptr [->memset]",
     "comment": "", "length": 6, "is_call": false, "is_jump": true,
     "is_terminal": false, "flow": ""}
  ],
  "count": 1,
  "truncated": false
}
```

`flow` is the single known call/jump target, empty when the instruction has
none or more than one. `truncated` means the per-function instruction cap
(200000) was hit.

`?format=text` renders the listing as plain text, one instruction per line:

```
00104310  ff2582ac0300  JMP qword ptr [->memset]
```

`404` if the address is external, a data address, or from a job analysed
before this artifact existed.

### `GET /v1/results/{id}/disasm`

Instruction count per function, paged like the other lists.

```json
{"address": "104310", "name": "memset", "count": 1}
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
