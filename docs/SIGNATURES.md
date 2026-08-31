# Editing function signatures

Every other endpoint in ghidra-rest reads what an analysis left on disk. These
three write back into Ghidra.

---

## Why this exists

Ghidra guesses a prototype for every function it finds and is usually
conservative about it. A function it never resolved is stored as:

```
undefined make_secret(void)
```

`undefined` return type, zero recorded parameters. The decompiler window then
renders that `undefined` as `void`, while its *local* analysis of the same
function independently recovers a parameter out of `RDI` and prints it. So you
get a listing that reads

```c
void make_secret(long param_1)          // the callee: "returns nothing"
...
local_f8 = make_secret(local_e5);       // the caller: assigns its return value
```

Both are the decompiler's opinion, formed per function, and neither consults
the other. The binary settles it — `make_secret` ends `CALL hash; LEAVE; RET`
with nothing writing `RAX` in between, so it does return `hash`'s value — but
nothing in the artifacts changes until the stored signature does.

Correcting it means telling Ghidra the real prototype and letting the
decompiler run again. That is what these endpoints do.

Before:

```c
void make_secret(long param_1)
{
  long local_10;
  for (local_10 = 0; obf_bytes[local_10] != '\0'; local_10 = local_10 + 1) {
    *(byte *)(local_10 + param_1) = obf_bytes[local_10] ^ 0xaa;
  }
  *(undefined1 *)(param_1 + 0xc) = 0;
  hash(param_1);
  return;
}
```

After `long make_secret(byte *secret)`:

```c
long make_secret(byte *secret)
{
  long lVar1;
  long local_10;
  for (local_10 = 0; obf_bytes[local_10] != '\0'; local_10 = local_10 + 1) {
    secret[local_10] = obf_bytes[local_10] ^ 0xaa;
  }
  secret[0xc] = 0;
  lVar1 = hash(secret);
  return lVar1;
}
```

The casts collapse, the pointer arithmetic becomes indexing, and the dropped
return value comes back.

---

## How it works

ghidra-rest has no long-lived Ghidra process. Analysis is one `analyzeHeadless`
run that writes JSON and exits, and that is deliberate: a request never blocks
on the decompiler and a crashed job cannot take the server down.

A retype cannot follow that model — it has to modify program state. So it
re-opens the job's Ghidra project:

```
analyzeHeadless <job>/project ghidrarest \
    -process -noanalysis \
    -scriptPath <scripts> -postScript ApplySignature.java \
    <job>/artifacts <ops.tsv> <result.tsv> <decompileTimeout>
```

`-noanalysis` is the point. The analysis is already in the project; only the
decompiler needs to run again. `-process` is passed **without a file name**:
each job's project holds exactly one program, and Ghidra may sanitise the name
on import, so naming it would be a guess that silently matches nothing.

`ApplySignature.java` then:

1. parses each prototype with Ghidra's own C parser
   (`CParserUtils.parseSignature`), the same one behind *Edit Function
   Signature* in the GUI;
2. applies it with `ApplyFunctionSignatureCmd(..., USER_DEFINED,
   preserveCallingConvention=true, ..., FunctionRenameOption.NO_CHANGE)`, in a
   transaction that is rolled back whole if anything fails;
3. optionally sets the calling convention, after validating the name against
   the program;
4. rewrites `functions.json`, and re-decompiles **the retyped function plus
   every caller of it**.

Callers are included because a caller's C text names the callee's parameters
and consumes its return value; leaving them alone would put stale text next to
fresh text. Callers *of* callers are not followed — their text refers only to
their direct callee.

Deliberately **not** rewritten: `decompiled/index.json` (its `length` field goes
stale for the rewritten functions and nothing reads it for correctness),
`disasm/*` (instructions do not change) and `summary.json` (counts do not
change).

A run costs a JVM start plus a handful of decompilations — tens of seconds,
not the minutes a re-analysis would take. Runs are serialised across the whole
server: each is a JVM sized by `GHIDRAREST_JAVA_MAX_MEM`, and letting HTTP
handlers fan out into as many as there are requests is a much worse failure
than a queue.

### What it needs

**`GHIDRAREST_KEEP_PROJECT` must have been on when the binary was analysed.**
The project directory is what gets re-opened; a job analysed with it deleted
has nothing left to edit. It now defaults to `true` for exactly this reason.
Turning it off saves roughly the size of the analysis database per job and
gives up retyping — for that job, permanently. Jobs analysed by an older build
that defaulted to off answer `409` and have to be resubmitted.

### The ledger

`<data>/jobs/<id>/signatures.json` records what has been edited:

```json
{
  "version": 1,
  "entries": {
    "10135e": {
      "address": "10135e",
      "prototype": "long make_secret(byte * secret)",
      "calling_convention": "__stdcall",
      "original": "undefined make_secret(void)",
      "original_calling_convention": "unknown",
      "at": "2026-08-31T09:14:02Z"
    }
  }
}
```

The **project** is the source of truth, not this file: applying a prototype is
a delta against a program that already remembers every earlier one. The ledger
exists for the one thing the program can no longer answer — what the analyser
said before anyone touched it. Ghidra has no undo across processes, so a reset
is a re-apply of `original`, not an undo. The types come back; their
provenance does not (the restored signature is stored as `USER_DEFINED` where
the original may have been an analyser guess).

---

## Endpoints

### `GET /v1/results/{id}/signatures`

What has been retyped on this job, and whether it can be retyped at all.

```json
{
  "job": "b8e1096aef55db4bfeb3404c",
  "editable": true,
  "count": 1,
  "signature": [
    {
      "address": "10135e",
      "prototype": "long make_secret(byte * secret)",
      "original": "undefined make_secret(void)",
      "at": "2026-08-31T09:14:02Z"
    }
  ],
  "calling_conventions": ["MSABI", "__stdcall", "__thiscall", "processEntry", "syscall"]
}
```

- `editable` — `false` when the job kept no Ghidra project. A client should
  stop offering the action rather than fail per click.
- `calling_conventions` — what this program's compiler spec defines, and the
  only names `PUT` will accept. New analyses carry them in `summary.json`;
  older ones grow `conventions.json` the first time a signature is applied, so
  an empty list is a normal answer rather than an error.

### `PUT /v1/results/{id}/function/{addr}/signature`

```http
PUT /v1/results/b8e1096aef55db4bfeb3404c/function/10135e/signature
Content-Type: application/json

{ "prototype": "long make_secret(byte *secret)", "calling_convention": "__stdcall" }
```

`prototype` is C — exactly the text Ghidra's *Edit Function Signature* dialog
takes. The **function name in it is ignored**: renaming is a separate concern,
and a retype quietly renaming a function would fight whatever rename layer sits
above it.

`calling_convention` is optional and separate from the prototype on purpose.
Ghidra's C parser accepts `__cdecl` inside the signature text and then discards
it, leaving a function whose parameter storage is locked while its convention
is still `unknown` — which is what produces the decompiler's
`/* WARNING: Unknown calling convention -- yet parameter storage is locked */`.
Send it here and it is applied properly. Omit it and the convention is left
alone.

PUT, not POST, because setting a prototype is idempotent: sending the same one
twice must not stack up two edits.

`200`:

```json
{
  "job": "b8e1096aef55db4bfeb3404c",
  "address": "10135e",
  "ok": true,
  "before": "undefined make_secret(void)",
  "prototype": "long make_secret(byte * secret)",
  "calling_convention": "__stdcall",
  "original": "undefined make_secret(void)",
  "set_at": "2026-08-31T09:14:02Z",
  "function": { "address": "10135e", "name": "make_secret", "...": "the fresh functions.json entry" },
  "redecompiled": ["10135e", "1013d0"],
  "duration_ms": 21344
}
```

`redecompiled` is the retyped function plus its callers — everything whose
`/decompile` response just changed. A client that repaints only the edited
function leaves stale text on screen.

Errors:

| status | meaning |
| --- | --- |
| `400` | body is not `{"prototype": "..."}` |
| `404` | no function at that address |
| `409` | job is not `done`, **or** it kept no Ghidra project |
| `422` | the prototype did not parse, or the convention is not one this program defines |
| `500` | the headless run failed; the message carries the tail of its output |

`422` is the interesting one — the request was well formed and the *input* was
not, which is a field error, not a failure:

```json
{
  "error": "this program has no calling convention \"__cdecl\"; it accepts MSABI, __stdcall, __thiscall, processEntry, syscall",
  "status": 422,
  "address": "10135e",
  "before": "long make_secret(byte * secret)",
  "duration_ms": 19870
}
```

Nothing was applied: the transaction is rolled back whole, so a convention
rejected *after* the signature landed does not leave half an edit behind.

### `DELETE /v1/results/{id}/function/{addr}/signature`

Puts `original` back and drops the ledger row. `404` if that address was never
edited. Same response shape as `PUT`.

---

## Using it

```sh
ID=b8e1096aef55db4bfeb3404c
API=http://localhost:8080
AUTH="Authorization: Bearer $GHIDRAREST_API_TOKEN"

# what does Ghidra think today, and what conventions may I use
curl -s -H "$AUTH" "$API/v1/results/$ID/function/10135e" | jq '{signature, return_type, parameter_count}'
curl -s -H "$AUTH" "$API/v1/results/$ID/signatures"      | jq '{editable, calling_conventions}'

# retype
curl -s -X PUT -H "$AUTH" -H 'content-type: application/json' \
  -d '{"prototype":"long make_secret(byte *secret)","calling_convention":"__stdcall"}' \
  "$API/v1/results/$ID/function/10135e/signature" | jq '{ok, before, prototype, redecompiled, duration_ms}'

# read the result
curl -s -H "$AUTH" "$API/v1/results/$ID/function/10135e/decompile?format=c"

# and back out
curl -s -X DELETE -H "$AUTH" "$API/v1/results/$ID/function/10135e/signature" | jq .ok
```

Expect each write to take **tens of seconds**. Set your client's timeout
accordingly; `GHIDRAREST_SIGNATURE_TIMEOUT` (default `10m`) bounds the server
side.

### Writing a prototype

It is C, resolved against the program's own type manager, so anything that
analysis produced is in scope:

```
long make_secret(byte *secret)
int  parse(char *buf, size_t len)
void handler(struct sockaddr *addr, int flags)
undefined8 main(void)
```

Rules worth knowing:

- The function name is required by the parser but ignored on apply.
- `void` for no parameters, not an empty list.
- **An unknown type is not an error.** Ghidra's parser creates a placeholder
  for a name it has never seen and applies the signature anyway, exactly as the
  GUI does, so `struct nonexistent_t *make_secret(byte *s)` comes back `200`
  with `return_type: "nonexistent_t *"`. Check the `prototype` in the response
  regardless: it is what Ghidra actually stored, which is not always what you
  sent. Builtins (`undefined`, `undefined1`..`8`, `byte`, `word`, `dword`,
  `qword`, `code`) and anything analysis or a header import created behave as
  you would expect.
- **A pointer return type is normalised before parsing.** Ghidra's C parser
  binds a `*` that touches the function name to the declarator, and since the
  name is discarded (`FunctionRenameOption.NO_CHANGE`) the pointer would be
  discarded with it — `long *f(void)` silently applied as `long f(void)`. The
  script rewrites `long *f(...)` to `long * f(...)` first, so both spellings
  behave identically. A function-pointer return (`void (*fp)(int)`) is left
  untouched and is still rejected by the parser.
- What *does* fail to parse is malformed C — an unbalanced paren, a missing
  return type — and that comes back `422` with the parser's own message.
- Do not put `__cdecl` in the text. Use `calling_convention`.
- Single line only — the transport between the server and the Ghidra script is
  tab separated, so tabs and newlines are refused rather than mangled.

### Do it in bulk

There is no batch endpoint: each call is one headless run, and runs are
serialised anyway. Loop, and expect it to take a while.

```sh
jq -r '.[] | [.address, .prototype] | @tsv' my-types.tsv | while IFS=$'\t' read -r a p; do
  curl -s -X PUT -H "$AUTH" -H 'content-type: application/json' \
    -d "$(jq -nc --arg p "$p" '{prototype:$p}')" \
    "$API/v1/results/$ID/function/$a/signature" | jq -c '{a:.address, ok, e:.error}'
done
```

---

## Limits

- **One program per job.** `-process` with no name relies on it.
- **Not a full editor.** Prototypes and calling conventions only: no struct
  editing, no local variable types, no data type creation, no renames (guttex
  owns those, and they never reach Ghidra).
- **Serialised.** One retype at a time across the whole server, regardless of
  job.
- **Not undoable, only restorable.** See the ledger, above.
- **Exported artifacts drift.** `GET /v1/jobs/{id}/export` zips the artifact
  directory as it stands, so it includes retypes — but `decompiled/index.json`
  keeps its pre-edit `length` values.
