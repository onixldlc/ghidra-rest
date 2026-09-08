# Architecture

Where ghidra-rest is today, what is wrong with that shape, and the
provider/module structure it is being refactored into. This is a plan: nothing
under "Target" is built yet.

The goal is not tidiness. It is that **adding a feature should cost one new
file and one line in a list**, and removing one should cost deleting them — so
that a feature that turns out to be a bad idea can be deleted without
archaeology, and a half-finished one can sit behind a switch without rotting.

---

## 1. Where it is today

6,263 lines: 3,743 of Go under `src/`, 2,520 of Java under `scripts/`.

```
src/
  main.go                  startup, shutdown, -healthcheck
  internal/config/         every env knob, resolved once
  internal/jobs/           queue, workers, disk layout, Ghidra invocation,
                           artifact readers, signature editing, byte patching
  internal/api/            routing, middleware, handlers
scripts/
  ExportJSON.java          analysis -> artifacts
  ApplySignature.java      retype a function in a kept project
  ApplyPatch.java          write bytes into a kept project
```

The layering that exists is real and worth keeping: `api` never talks to
Ghidra, `jobs` never talks to HTTP, `config` is the only thing that reads the
environment. The problems are inside those layers, not between them.

### 1.1 The same operation, written twice, in Go

`jobs/signature.go:applySignatures` and `jobs/patch.go:applyPatches` are the
same procedure with three substitutions (script name, temp-dir prefix, column
count). Both: refuse a job with no kept project, stat `analyzeHeadless`, stat
the script, make a temp dir, write `ops.tsv`, create an empty `result.tsv` so a
JVM that died before writing is distinguishable from one that reported nothing,
bound the run by `SignatureTimeout`, build a nearly identical argument vector,
take `editRuns`, call `runHeadlessTool`, parse a TSV, and drop the artifact
cache for the job.

| Duplicate pair | Lines each |
|---|---|
| `applyPatches` / `applySignatures` | ~85 |
| `readPatchResults` / `readSigResults` | ~25 |
| `Patches`+`writePatches` / `Signatures`+`writeSignatures` | ~45 |
| `pickPatch` / `pick` | 8 |
| `api/patch.go:patchError` / `api/signature.go:signatureError` | ~12 |

About 350 lines.

### 1.2 The same helpers, written three times, in Java

Measured by diffing the blocks against each other:

| Block | Lines | Copies | Divergence |
|---|---|---|---|
| `key` `fileKey` `open` `mkdirs` `field` `num` `bool` `esc` | 92 | 3 | `ApplySignature` and `ApplyPatch` are byte-identical; `ExportJSON` differs by 5 lines, all of them comments |
| `writeFunction` + `writeAddrList` | ~58 | 3 | 1 line between the two edit scripts |
| `lineMap` | ~42 | 3 | the two edit scripts are identical |
| `readOps` `writeResult` `tsv` `countOk` `rootMessage` `Op` | ~75 | 2 | — |
| `hexBytes` `operandText` `commentText` `flowTarget` | ~45 | 2 | — |
| `writeDecompiled` | ~45 | 2 | — |

About 549 redundant lines, 22% of the Java.

The code has not drifted. The *comments* have: `esc()` explains why control
characters and lone surrogates are escaped — decompiled C and raw strings out
of a binary contain both — and that explanation survives only in
`ExportJSON.java`. The two copies kept the behaviour and dropped the reason.
That is the shape of a bug that has not happened yet.

Worth noting what is *not* wrong: the `run()` method at the top of each script
is clean. `ExportJSON.run()` is forty lines and reads like a table of contents.
The bloat is entirely in the private helpers below it.

### 1.3 Adding a feature costs six edits

To add one endpoint that writes into a kept project:

1. `scripts/NewThing.java`
2. `src/internal/jobs/newthing.go`
3. `src/internal/api/newthing.go`
4. `src/internal/api/server.go` — route registration
5. `src/internal/api/handlers.go` — the `endpoints` and `features` lists
6. `docker/Dockerfile` — a `COPY` for the script, and `docker/warmup.sh` for
   the compile check

Nothing enforces steps 4–6. Both have already failed:

- **Step 5 has drifted.** `handleCapabilities` hand-lists 30 endpoints. All
  four byte-patch routes are missing from it, and `features` advertises
  `signature-edit` but nothing about patching. A client that trusts
  `/v1/capabilities` cannot discover a feature that shipped.
- **Step 6 is a known failure mode.** A route registered without its script
  copied into the image answers, then fails at the JVM with a missing-script
  error — the endpoint looks implemented and is not.

There are in fact **four** hand-maintained descriptions of the same route
table, and a fifth place the feature should have been mentioned:

| List | Entries | Knows about byte-patching |
|---|---|---|
| `api/server.go` | 30 routes | yes — this is the truth |
| `api/handlers.go` capabilities | 30 | **no, stale** |
| `docs/openapi.yaml` | 30 paths | yes |
| `docs/API.md` | 43 headings | yes |
| `README.md` | — | **no, zero mentions** |

Worth being precise about the failure: it is not that nobody updates the
lists. The docs *were* updated when patching shipped; `capabilities` and the
README were the two that were missed. Four copies of one fact will lose
synchronisation eventually no matter how careful anyone is, which is the
argument for generating them rather than for trying harder.

`openapi.yaml` is 1,468 lines that are a restatement of the route table plus
the request and response shapes. It should be generated from the registry
alongside `/v1/capabilities` (§2.7), not hand-edited.

### 1.4 Everything assumes Ghidra

`Job` carries `GhidraVersion`, `Language`, `executable_format`. `JobOptions`
carries `Processor`, `CompilerSpec`, `Loader` — three analyzeHeadless flags.
`/v1/version` reports `ghidra_home`. Honest for what the service does today,
wrong for what it is being asked to do next.

### 1.5 `Manager` is a god object

`jobs.Manager` has **27 exported methods**, and `api` calls **22** of them.
They sort cleanly into five unrelated jobs:

| Concern | Methods | Count |
|---|---|---|
| queue + disk layout | `Submit` `Get` `List` `Cancel` `Delete` `Start` `Stop` `SweepLoop` `MetaPath` `LogPath` `ArtifactsDir` `InputPath` | 12 |
| artifact reading | `LoadArray` `LoadObject` `ReadMemory` | 3 |
| the Ghidra engine | `GhidraVersion` `HasProject` `LogTail` | 3 |
| the patch feature | `PatchPath` `Patches` `SetPatches` `ClearPatch` | 4 |
| the signature feature | `SignaturePath` `Signatures` `Conventions` `SetSignature` `ClearSignature` | 5 |

Nine of those belong to features, not to a job manager. They are on `Manager`
because there was nowhere else to put them.

One piece of good news from the audit: `api` and `jobs` are already separate
packages, so `api` can only touch exported symbols. There is no hidden
coupling to unpick — the split is mechanical.

---

## 2. Target

Two seams, and the same registry pattern on both sides of the JVM boundary.
A **provider** is an analysis engine. A **module** is a feature. Providers are
chosen per input; modules mount only where the chosen provider supports them.

### 2.1 One Java entry point, many task files

**This is verified working — see §2.2 for the evidence.**

Today each operation is its own `-postScript`, each script is an island, and
that islanding is why everything got copy-pasted. Instead: one script Ghidra is
ever pointed at, which dispatches by task name.

```
scripts/
  RestScript.java        the only file Ghidra is ever given
  RestRegistry.java      the list. one line per task.
  Task.java              the interface

  TaskExport.java        what ExportJSON.java does today
  TaskSignature.java     what ApplySignature.java does today
  TaskPatch.java         what ApplyPatch.java does today

  RestJson.java          esc, field, num, bool, open, mkdirs
  RestAddr.java          key, fileKey
  RestFunc.java          writeFunction, writeAddrList
  RestDecomp.java        writeDecompiled, lineMap
  RestDisasm.java        hexBytes, operandText, commentText, flowTarget
  RestOps.java           Op, readOps, writeResult, tsv, countOk, rootMessage
```

```java
public class RestScript extends GhidraScript {
	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		Task t = RestRegistry.get(args[0]);
		if (t == null) {
			throw new IllegalArgumentException(
				"unknown task " + args[0] + "; have " + RestRegistry.names());
		}
		t.run(new Ctx(this, currentProgram, new File(args[1])), rest(args));
	}
}
```

```java
public interface Task {
	String name();     // "patch"
	String usage();
	void run(Ctx c, String[] args) throws Exception;
}
```

`Ctx` carries the program, the output directory and the shared writers, so a
new task inherits the plumbing instead of copying it.

Line budget: 2,520 → roughly 1,950, with `esc()` existing exactly once.

**What this removes, beyond the duplication.** Four of the six edit points in
§1.3 disappear:

| Edit point | Today | With one entry script |
|---|---|---|
| new `.java` | yes | yes |
| `Dockerfile` `COPY` line | yes | **gone** — `COPY scripts/ /opt/ghidra-rest/scripts/` takes the directory |
| `warmup.sh` `-postScript` line | yes | **gone** — warmup calls `RestScript.java selftest`, which walks the registry |
| Go: which script implements which edit | yes | **gone** — the Go always says `RestScript.java <task>` |
| `server.go` route | yes | yes (Go side, §2.6) |
| `handlers.go` capabilities list | yes | **gone** — generated (§2.7) |

And one thing it adds: `RestScript.java tasks` can print the registry as JSON,
so the Go side **asks the image what it can do** at startup rather than keeping
a second list that drifts from the first. The drift in §1.3 stops being
expressible.

### 2.2 Evidence

Run against `ghcr.io/onixldlc/ghidra-rest:latest` (Ghidra 12.1.3), importing
`/bin/date`, with five files in `-scriptPath`: a plain `RestJson` helper class,
a `Task` interface referencing a Ghidra type, a `TaskHello` implementation, a
`RestRegistry`, and the `RestScript` entry point.

```
RestScript.java> SPIKE OK: registry=hello task=hello program="date" funcs=276 args=1
```

That proves, in one line: a non-`GhidraScript` class in the script directory
compiles and is callable; an interface in its own file compiles; polymorphic
dispatch through a registry works; and a task reaches `currentProgram`.

A second run, after adding `TaskCount.java` and one line to `RestRegistry`, and
changing nothing else:

```
RestScript.java> SPIKE OK: registry=hello,count task=count symbols=2970 blocks=33
```

Picked up on the next run, no stale-compile problem.

**Consequence: no jar, no classpath change, no build step.** The fallback plan
of compiling shared classes into a jar at image build time is not needed.

### 2.3 Provider

A provider is selected by the bytes submitted, not configured globally. A
`.jar` must never reach `analyzeHeadless`.

```go
package engine

// Detect is what a provider is shown in order to bid on an input.
type Detect struct {
	Filename string
	Head     []byte // first 4 KiB, enough for every magic that matters
	Size     int64
}

type Provider interface {
	Name() string    // "ghidra"
	Version() string

	// Accepts scores an input. 0 means it cannot handle it at all.
	// Highest score wins.
	Accepts(Detect) int

	// Caps is what this provider will produce and what edits it can make,
	// so modules can decline to mount rather than 500 later.
	Caps() Caps

	Analyze(ctx context.Context, r Run) error
	Edit(ctx context.Context, req EditRequest) ([]Row, error)
	HasProject(jobID string) bool
}

type Caps struct {
	Artifacts []string // "functions.json", "disasm/", "memory/"
	Edits     []string // "signature", "patch"
}
```

Scoring rather than an if-chain, so a specialist outbids a generalist without
anyone editing a dispatch table:

| Provider | Input | Score |
|---|---|---|
| ghidra | ELF / PE / Mach-O magic | 10 |
| ghidra | anything else | 1 |
| java | PK zip containing `.class` entries | 100 |
| dotnet | PE with a CLI header | 100 |

Ghidra stays the fallback because it does genuinely eat a lot. A .NET assembly
*is* a PE, so Ghidra bids 10 on it and the specialist takes it at 100.

Only the Ghidra provider is being implemented now. The interface exists so the
second one is an addition rather than a rewrite.

`Edit` is the single method that absorbs both `applyPatches` and
`applySignatures` whole. `EditRequest{Op string, Rows [][]string, Timeout}` in,
`[]Row` out. The ops-file/result-file/TSV round trip becomes an implementation
detail of the Ghidra provider, because it is a fact about analyzeHeadless and
nothing else. For the Ghidra provider, `Edit` always invokes
`RestScript.java <op>`; for a hypothetical .NET provider the same `"patch"`
maps to a dnlib call and no JVM. The module never learns which.

### 2.4 The job model has to split

`JobOptions` is Ghidra-shaped. A `.jar` has no processor, compiler spec or
loader. It becomes common options plus an opaque per-provider bag:

```go
type JobOptions struct {
	Decompile         bool
	DecompileMaxFuncs int
	DecompileTimeout  int
	AnalysisTimeout   int

	// Provider-specific knobs, validated by the provider that claimed the
	// input. Ghidra reads processor / compiler_spec / loader from here.
	Provider map[string]string `json:"provider,omitempty"`
}
```

Likewise `Job.GhidraVersion` becomes `Job.Provider` + `Job.ProviderVersion`,
with no deprecated alias kept — see §3.0. guttex reads `ghidra_version` today
and is updated alongside.

The on-disk ledgers do not need migrating. `Ledger[PatchEntry]` serialises to
the same `{"version": 1, "entries": {...}}` shape `patches.json` already has,
so jobs sitting in `/data` keep their recorded originals and stay revertible.

### 2.5 Breaking up `Manager`

Per §1.5, into three types plus the feature methods that leave entirely:

```
jobs.Store        queue, workers, disk layout, meta.json     12 methods
artifact.Reader   LoadArray, LoadObject, ReadMemory           3
engine.Provider   Version, HasProject, Edit, Analyze, LogTail 3 + the new ones
module/patch      the 4 patch methods, now on the module
module/signature  the 5 signature methods, now on the module
```

`ledger` carries the shared durable-record shape:

```go
type Ledger[T any] struct {
	Version int           `json:"version"`
	Entries map[string]*T `json:"entries"`
}
```

`patches.json` becomes `Ledger[PatchEntry]`, `signatures.json` becomes
`Ledger[SigEntry]`, and the next feature's ledger costs nothing. The
temp-file-then-rename write is written once, which matters more than the line
count: a torn ledger loses recorded originals, and an original cannot be
recovered once the program has been written over.

### 2.6 Module, and the same registry on the Go side

```go
package module

type Module interface {
	Name() string          // "patch"
	Feature() string       // "byte-patching", for /v1/capabilities
	Needs() Needs
	Routes(Deps) []Route   // {Method, Pattern, http.HandlerFunc}
	Errors() map[error]int // ErrNoProject: 409, ErrBadPatch: 400
}

type Needs struct {
	Edit      string   // mount only if the provider's Caps().Edits has it
	Artifacts []string // "memory/" for hexdump
	Project   bool     // needs the kept Ghidra project
}
```

The Go registry deliberately mirrors `RestRegistry.java` — the same mental
model on both sides of the JVM boundary:

```go
// src/internal/module/all/all.go
func All() []module.Module {
	return []module.Module{
		results.New(),
		signature.New(),
		patch.New(),
		// <-- a new feature is one line here plus one new directory
	}
}
```

An explicit list rather than `init()` plus blank imports. Same one-line cost,
but registration stays visible, and a test can build a registry holding a
subset.

**One prerequisite.** `writeJSON`, `writeError`, `pageParams` and `resultJob`
are unexported inside `api` (`server.go:182–228`). Module packages cannot reach
them, so they move to an exported `httpx` package first. About 60 mechanical
lines, no behaviour change. No import cycle results: `module/*` imports `jobs`,
`engine` and `httpx`; `api` imports the module registry; `module` never imports
`api`.

`Errors()` replaces `patchError` and `signatureError` with one mapper fed by
each module's own table.

### 2.7 What falls out

- **`/v1/capabilities` is generated** from the registry and from
  `RestScript.java tasks`. It cannot drift, because there is no second list.
- **Unmet needs mean the routes do not exist.** With `KEEP_PROJECT=0` the
  signature and patch modules do not mount, are not advertised, and return the
  ordinary 404. Today that condition is special-cased in three places.
- **On a `.jar` job, `hexdump` and byte patching are simply absent** — not 404
  after a lookup, not advertised, not offered by a UI reading capabilities.
- **Deleting a feature is `rm -r` plus one line, in each language.**

### 2.8 Layout

```
src/internal/
  config/              unchanged
  engine/              Provider, Caps, EditRequest, Row, selection by score
    ghidra/            analyzeHeadless invocation, process-group kill,
                       version detection, RestScript task dispatch
  jobs/                queue, workers, disk layout, meta.json — no Ghidra
  artifact/            LoadArray, LoadObject, cache, NormAddr, Hexdump,
                       ReadMemory
  ledger/              generic Ledger[T]
  httpx/               writeJSON, writeError, pageParams, resultJob
  module/              Module, Registry, Route, Needs
    all/               the one list
    results/           the read-only result routes
    signature/
    patch/
  api/                 server, middleware, mounts the registry
```

`results` is a module too. Uniformity is the point — and it is what lets a
`.jar` job drop `hexdump` without a special case.

---

## 3. Order of work

### 3.0 This is a major version, and it breaks compatibility

Decided deliberately: the refactor lands as a new major version and nothing is
kept for the sake of old clients. guttex is the only consumer, and it is
updated in step with the server.

What that buys, beyond less code:

- **No deprecated aliases.** `ghidra_version`, `processor`, `compiler_spec`
  and `loader` are replaced outright rather than shadowed (§2.4).
- **Endpoint shapes can be regularised.** Today a signature is edited at
  `PUT /v1/results/{id}/function/{addr}/signature` while patches live at both
  `PUT /v1/results/{id}/patches` and
  `PUT /v1/results/{id}/function/{addr}/patch` — two different shapes for the
  same idea, because each was added on its own. Modules can settle on one
  shape and every future feature inherits it.
- **The generated OpenAPI document describes one consistent API** rather than
  faithfully recording the inconsistencies.

What it does not excuse: changing behaviour by accident. The steps below still
each get reviewed against the golden test, but the test is now a *diff to read*
rather than a gate that must stay green. A change it reports is either intended
and written down, or it is a bug.

0. **Git.** Repository initialised, `origin` pointed at
   `github.com/onixldlc/ghidra-rest`, nothing committed. The working tree is
   upstream `main` plus the unpushed byte-patch feature
   (`scripts/ApplyPatch.java`, `src/internal/jobs/patch.go`,
   `src/internal/api/patch.go`, and edits to `server.go`, `signature.go`, the
   Dockerfile, `warmup.sh` and the docs). Commit that as a feature, then tag
   `pre-refactor`, before step 1.

1. **~~Spike the Java loading question~~ — done.** §2.2. It works with no build
   changes.

2. **Golden test.** Record every route's response against a live job; replay
   after each step below and read the differences. With compatibility dropped
   (§3.0) its job is not to stay green — it is to make sure every difference
   between v1 and v2 is one somebody chose. `api_test.go` is 122 lines and `jobs_test.go` is 216
   — not enough to refactor behind. This is the net. Without it the rest is
   guesswork.

   Specifically: the eleven existing tests are `TestHTTPBasics`,
   `TestResultsBeforeDone`, `TestAuthToken`, `TestNormAddr`, `TestAddrOffset`,
   `TestSanitizeName`, `TestHexdump`, `TestArtifactPaging`,
   `TestSubmitDedupAndLifecycle`, `TestUploadTooLarge` and
   `TestReloadMarksInterrupted`. **None of them touches signature editing or
   byte patching** — the two features this refactor moves. The untested
   surface is exactly the surface that changes, so the golden test must cover
   the eight signature and patch routes before step 5 begins.

3. **~~Java: `RestScript` + registry + tasks~~ — done.** §2.1 is built.
   2,520 lines became 2,167 across 13 files; `ExportJSON.java`,
   `ApplySignature.java` and `ApplyPatch.java` are gone, replaced by
   `RestScript` + `RestRegistry` + three `Task*` classes over six `Rest*`
   helpers. Verified in §3.1.

4. **Go: extract `httpx`** (§2.6). Mechanical, unblocks everything after it.

5. **Go: split `Manager`** into `jobs.Store`, `artifact.Reader` and the engine
   (§2.5), and extract `ledger`. This is where the ~350 duplicated Go lines
   die.

6. **Go: `engine.Provider`,** one provider registered.

7. **Go: module registry;** convert `results`, `signature`, `patch`.

8. **Generate `/v1/capabilities` and `docs/openapi.yaml`** from the registry
   and the task list (§2.7), and add the byte-patch feature to the README.
   Four hand-kept copies of the route table (§1.3) become one generated
   pair.

9. **Prove it.** Mount `GET /v1/results/{id}/conventions` as a new module: one
   directory, one registry line. `Manager.Conventions` already exists at
   `jobs/signature.go:130` and has never been routed — a real feature one line
   of plumbing away, which makes it an honest test of whether the plumbing got
   better.

### 3.1 What the Java step was verified against

Both script sets were run over the same binary (`/bin/date`, 200 functions) in
`ghcr.io/onixldlc/ghidra-rest:latest`, and every artifact compared by checksum.

**442 files each. 439 byte-identical** — including all 216 `disasm/*.json` and
all 216 `decompiled/*.json`.

Three files differed: `summary.json`, `functions.json`, `xrefs.json`. Running
the **old** scripts twice differs in exactly the same three, so the refactor
contributes none of it:

| Comparison | Files differing |
|---|---|
| old vs old (same scripts, two runs) | `summary.json`, `functions.json`, `xrefs.json` |
| old vs new (the refactor) | `summary.json`, `functions.json`, `xrefs.json` |

The causes are pre-existing and worth writing down, because step 2's golden
test has to know about them:

- `summary.json` carries `creation_date`, which is the wall clock.
- `functions.json` and `xrefs.json` order `called_by` and the reference lists
  by the iteration order of a Ghidra `Set`, which is not stable between runs.
  Same members, same byte length, different sequence.

**The artifact set is therefore not reproducible byte-for-byte**, and never
was. A golden test over these three files has to compare them
order-insensitively, or normalise before diffing.

The edit tasks were exercised against a kept project:

```
res_sig.tsv    111c40  ok  undefined FUN_00111c40(void)  int FUN_00111c40(char * arg)
res_patch.tsv  111c40  ok  5548  111c40
               0       error     no memory at 0
```

and the discovery and selftest paths answer:

```
{"tasks":[{"name":"export","usage":"<outdir> [decompile] [maxFuncs] ..."},
          {"name":"signature","usage":"<outdir> <opsFile> <resultFile> ..."},
          {"name":"patch","usage":"<outdir> <opsFile> <resultFile> ..."}]}
RestScript: selftest ok tasks=export, signature, patch
```

All six log patterns guttex's progress bar matches (`state/progress.svelte.ts`)
still fire against the new export task, which is why the tasks keep their old
log tags rather than being renamed to match their files. See `Task.logTag`.

## 4. Explicitly out of scope

- The web UI. guttex gets the same treatment separately, after this lands.
- A second provider. The interface is built now; `java` and `dotnet` are not.
- Any change to the artifact JSON schema. The schema is the contract between
  provider and module, and changing it during a refactor would make the golden
  test meaningless.
