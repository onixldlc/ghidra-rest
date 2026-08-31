# Type management — design

**Status: proposal. Not implemented.** Nothing in this document describes code
that exists yet; `docs/SIGNATURES.md` is the reference for what does.

Mirrors the signature feature's shape. Decisions taken: keep the signature
feature as built; a type edit re-decompiles the **target set only**, with
staleness elsewhere surfaced to the client rather than chased by the server.

## Topology

No new process, language or tier. Go endpoint → TSV ops file →
`analyzeHeadless -process -noanalysis` running `ApplyTypes.java` against the
kept project → rewrite touched artifacts → `arts.dropJob(id)`.

Reuses the `sigRuns` mutex: one JVM at a time, server-wide. A type edit and a
signature edit must not race on the same project.

## Why the rev counter is load-bearing

"Target set only" means the server re-decompiles the functions whose signature
directly names the edited type, and nothing else. Every other function that
touches the type keeps its old on-disk `decompiled/<addr>.json`.

A client refetch alone therefore returns the *same stale text* — the artifact
was never regenerated. So staleness has to be visible:

- `summary.json` gains `types_rev` (monotonic int, bumped per applied type edit)
- each `decompiled/<addr>.json` records the `types_rev` it was produced at
- `GET /v1/results/{id}/function/{addr}/decompiled` returns `stale: true` when
  the artifact's rev is below the job's current `types_rev`

guttex reads `stale` and decides what to do: badge it, offer a refresh. The
server never walks the graph on its own.

## Refresh endpoint

Staleness needs a resolution path or `stale: true` is a dead end.

    POST /v1/results/{id}/decompile   {"addresses": ["10135e", "101309"]}

Re-decompiles exactly the listed functions at the current `types_rev` and
rewrites their artifacts. One JVM for the whole batch — which is why it takes a
list, not a single address. guttex batches the stale set rather than firing one
request per function.

## Type endpoints

    GET    /v1/results/{id}/types              list (name, kind, size, source)
    GET    /v1/results/{id}/types/{name}       one type, members expanded
    PUT    /v1/results/{id}/types/{name}       define/replace from C text
    DELETE /v1/results/{id}/types/{name}       revert to the pre-edit definition

`PUT` body mirrors the signature endpoint:

    { "definition": "struct foo { int a; char *b; };" }

Ledger, same as signatures: the first touch records the original definition so
`DELETE` can restore it. Ghidra has no cross-process undo.

## ApplyTypes.java

TSV in, TSV out, same contract as `ApplySignature.java`.

- one transaction per op; `applied = false` in the catch so a partial edit rolls
  back whole — the lesson from `setCallingConvention`
- resolve with `DataTypeConflictHandler.REPLACE_HANDLER`: a type edit that
  silently produces `foo.conflict` is worse than an error
- target set = functions whose prototype names the edited type, computed from
  `functions.json`. No graph walk.

Rewrites `types.json`, `functions.json` (signatures re-render) and
`decompiled/<addr>.json` for the target set. Bumps `types_rev` in `summary.json`.

## Open questions

- **A new script is not shipped until the Dockerfile copies it.** `ApplySignature.java`
  was written, tested and pushed, and the published image never contained it:
  `docker/Dockerfile` copies scripts by name, so every apply failed on the
  `apply script not found` check while the routes answered normally. Adding
  `ApplyTypes.java` means adding a `COPY` line *and* a `-postScript` in
  `docker/warmup.sh` with an empty ops file, so a Java error fails the build
  instead of the first user request.

- **Struct members go through the same parser that just bit us.** A member
  declaration (`char *name;`) is a declarator too. `ApplySignature.java` needed
  `detachReturnStars()` because a `*` adjacent to the declared name bound to the
  name and was discarded with it; see `docs/SIGNATURES.md`. Whether the struct
  parser has the equivalent flaw is **unverified** — test it before trusting it,
  the failure mode is silent and stores the wrong type.
- Is `REPLACE_HANDLER` safe when the old definition is referenced by live
  function signatures? Test: edit a struct used by two functions, confirm no
  `.conflict` type appears.
- Does a type edit invalidate `disasm/*`? Believed not — disassembly is not
  type-dependent. Confirm rather than assume.

## Rejected

- Following the type→function reference graph server-side. That is the "every
  function referencing the type" option; it puts graph-walking complexity in
  ghidra-rest to save the client a refetch.
- Whole-program re-decompile on every type edit: minutes, not seconds.
- Type creation driven from the decompiler's auto-fill. Out of scope.
