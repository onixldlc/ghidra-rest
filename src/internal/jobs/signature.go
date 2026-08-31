package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Retyping a function is the one operation that writes back into Ghidra. It
// works by re-opening the job's *kept* project with -noanalysis and running
// ApplySignature.java over it, so the cost is a JVM start plus the decompiler
// on the retyped function and its callers -- not a re-analysis.
//
// Two consequences worth being explicit about:
//
//   - It needs GHIDRAREST_KEEP_PROJECT. A job analysed with the project
//     deleted has nothing left to edit; ErrNoProject says so rather than
//     silently re-analysing for minutes.
//   - The project is the source of truth, not the ledger below. Applying a
//     prototype is a delta against a program that already remembers every
//     earlier one. The ledger exists for one thing the program cannot answer:
//     what the analyser said before anyone edited it.

var (
	// ErrNoProject means this job kept no Ghidra project, so there is nothing
	// to apply a signature to.
	ErrNoProject = errors.New("this job kept no Ghidra project; signature editing needs GHIDRAREST_KEEP_PROJECT=1 at analysis time")
	// ErrNoFunction means the address is not a function entry point.
	ErrNoFunction = errors.New("no function at that address")
)

// SigOp is one prototype to apply. Convention is optional: empty leaves the
// function's calling convention alone.
type SigOp struct {
	Addr       string
	Prototype  string
	Convention string
}

// SigResult is what ApplySignature.java reported for one op.
type SigResult struct {
	Address   string `json:"address"`
	OK        bool   `json:"ok"`
	Before    string `json:"before"`
	Prototype string `json:"prototype,omitempty"`
	Error     string `json:"error,omitempty"`
}

// SigEntry is the durable record of one edited function. Original is captured
// the first time the function is touched, which is what makes a later reset
// possible: Ghidra has no undo across processes.
type SigEntry struct {
	Address    string `json:"address"`
	Prototype  string `json:"prototype"`
	Convention string `json:"calling_convention,omitempty"`
	Original   string `json:"original"`
	// OriginalConvention is what the analyser chose, so a reset puts the ABI
	// back too and not just the types.
	OriginalConvention string    `json:"original_calling_convention,omitempty"`
	At                 time.Time `json:"at"`
}

// SigLedger is <data>/jobs/<id>/signatures.json.
type SigLedger struct {
	Version int                  `json:"version"`
	Entries map[string]*SigEntry `json:"entries"`
}

// sigRuns serialises signature runs across the whole server. Each one is a
// JVM sized by JAVA_MAX_MEM; letting an HTTP handler fan out into as many of
// them as there are requests is a much worse failure than a queue.
var sigRuns sync.Mutex

// SignaturePath is the per-job record of edited prototypes.
func (m *Manager) SignaturePath(id string) string {
	return filepath.Join(m.jobDir(id), "signatures.json")
}

// HasProject reports whether this job's Ghidra project survived analysis.
func (m *Manager) HasProject(id string) bool {
	entries, err := os.ReadDir(m.projectDir(id))
	return err == nil && len(entries) > 0
}

// Signatures reads the ledger. A job that was never edited has an empty one
// rather than an error: "no edits" is a normal answer.
func (m *Manager) Signatures(id string) (*SigLedger, error) {
	led := &SigLedger{Version: 1, Entries: map[string]*SigEntry{}}
	b, err := os.ReadFile(m.SignaturePath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return led, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, led); err != nil {
		return nil, fmt.Errorf("signatures.json is corrupt: %w", err)
	}
	if led.Entries == nil {
		led.Entries = map[string]*SigEntry{}
	}
	return led, nil
}

func (m *Manager) writeSignatures(id string, led *SigLedger) error {
	led.Version = 1
	b, err := json.MarshalIndent(led, "", "  ")
	if err != nil {
		return err
	}
	// Write then rename, like the job records: a torn signatures.json would
	// lose every recorded original, and an original cannot be recovered once
	// the program has been retyped over it.
	tmp := m.SignaturePath(id) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.SignaturePath(id))
}

// Conventions lists the calling convention names this program accepts. New
// analyses carry them in summary.json; older ones only grow conventions.json
// the first time a signature is applied, so both are consulted and an empty
// list is a normal answer rather than an error.
func (m *Manager) Conventions(id string) []string {
	var names []string
	if b, err := os.ReadFile(filepath.Join(m.ArtifactsDir(id), "summary.json")); err == nil {
		var sum struct {
			Conventions []string `json:"calling_conventions"`
		}
		if json.Unmarshal(b, &sum) == nil && len(sum.Conventions) > 0 {
			return sum.Conventions
		}
	}
	if b, err := os.ReadFile(filepath.Join(m.ArtifactsDir(id), "conventions.json")); err == nil {
		if json.Unmarshal(b, &names) == nil {
			return names
		}
	}
	return nil
}

// currentSig reads what functions.json says about a function right now. The
// ledger's Original is what it said before guttex ever touched it; these two
// differ exactly when the function has been edited.
func (m *Manager) currentSig(id, addr string) (proto, cc string, err error) {
	art, err := m.LoadArray(id, "functions.json")
	if err != nil {
		return "", "", err
	}
	raw, found := art.Find(NormAddr(addr))
	if !found {
		return "", "", ErrNoFunction
	}
	var fn struct {
		Signature  string `json:"signature"`
		Convention string `json:"calling_convention"`
	}
	if err := json.Unmarshal(raw, &fn); err != nil {
		return "", "", err
	}
	return fn.Signature, fn.Convention, nil
}

// SetSignature applies one prototype and records it. The returned entry is the
// ledger row as it now stands; a nil entry with an ok=false result means the
// prototype did not parse.
func (m *Manager) SetSignature(ctx context.Context, job *Job, addr, prototype, convention string) (*SigEntry, *SigResult, error) {
	addr = NormAddr(addr)
	prototype = strings.TrimSpace(prototype)
	convention = strings.TrimSpace(convention)
	if prototype == "" {
		return nil, nil, errors.New("prototype is empty")
	}
	// Fail on a bad address before paying for a JVM.
	before, beforeCC, err := m.currentSig(job.ID, addr)
	if err != nil {
		return nil, nil, err
	}

	led, err := m.Signatures(job.ID)
	if err != nil {
		return nil, nil, err
	}

	res, err := m.applySignatures(ctx, job, []SigOp{
		{Addr: addr, Prototype: prototype, Convention: convention},
	})
	if err != nil {
		return nil, nil, err
	}
	r := pick(res, addr)
	if r == nil {
		return nil, nil, errors.New("the apply script reported nothing for " + addr)
	}
	if !r.OK {
		return nil, r, nil
	}

	e := led.Entries[addr]
	if e == nil {
		// First edit of this function: whatever it looked like a moment ago is
		// the only "original" that will ever be recoverable.
		e = &SigEntry{
			Address:            addr,
			Original:           firstNonEmpty(r.Before, before),
			OriginalConvention: beforeCC,
		}
		led.Entries[addr] = e
	}
	e.Prototype = r.Prototype
	e.Convention = convention
	e.At = time.Now().UTC()
	if err := m.writeSignatures(job.ID, led); err != nil {
		return nil, nil, err
	}
	return e, r, nil
}

// ClearSignature puts the recorded original back and drops the ledger row.
// This is a re-apply, not an undo: the restored signature is stored as
// USER_DEFINED where the original may have been an analyser guess, so the
// types come back but their provenance does not.
func (m *Manager) ClearSignature(ctx context.Context, job *Job, addr string) (*SigResult, error) {
	addr = NormAddr(addr)
	led, err := m.Signatures(job.ID)
	if err != nil {
		return nil, err
	}
	e := led.Entries[addr]
	if e == nil {
		return nil, ErrNotFound
	}
	res, err := m.applySignatures(ctx, job, []SigOp{
		{Addr: addr, Prototype: e.Original, Convention: e.OriginalConvention},
	})
	if err != nil {
		return nil, err
	}
	r := pick(res, addr)
	if r == nil {
		return nil, errors.New("the apply script reported nothing for " + addr)
	}
	if !r.OK {
		return r, nil
	}
	delete(led.Entries, addr)
	if err := m.writeSignatures(job.ID, led); err != nil {
		return nil, err
	}
	return r, nil
}

func pick(res []SigResult, addr string) *SigResult {
	for i := range res {
		if res[i].Address == addr {
			return &res[i]
		}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// applySignatures runs one headless pass over the kept project.
func (m *Manager) applySignatures(ctx context.Context, job *Job, ops []SigOp) ([]SigResult, error) {
	if !m.HasProject(job.ID) {
		return nil, ErrNoProject
	}
	bin := filepath.Join(m.cfg.GhidraHome, "support", "analyzeHeadless")
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("analyzeHeadless not found under %s: %w", m.cfg.GhidraHome, err)
	}
	script := filepath.Join(m.cfg.ScriptDir, "ApplySignature.java")
	if _, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("apply script not found: %w", err)
	}

	dir, err := os.MkdirTemp(m.tmpDir(), "sig-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	opsPath := filepath.Join(dir, "ops.tsv")
	resPath := filepath.Join(dir, "result.tsv")
	var sb strings.Builder
	for _, op := range ops {
		// The script splits fields on tabs and records on newlines, so neither
		// may appear inside a value. Reject rather than mangle.
		if strings.ContainsAny(op.Prototype, "\t\r\n") || strings.ContainsAny(op.Convention, "\t\r\n") {
			return nil, errors.New("prototype and calling convention must each be a single line")
		}
		fmt.Fprintf(&sb, "%s\t%s\t%s\n", op.Addr, op.Prototype, op.Convention)
	}
	if err := os.WriteFile(opsPath, []byte(sb.String()), 0o644); err != nil {
		return nil, err
	}
	// The script overwrites this; create it empty so a JVM that died before
	// writing is distinguishable from one that reported nothing.
	if err := os.WriteFile(resPath, nil, 0o644); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, m.cfg.SignatureTimeout)
	defer cancel()

	// -process with no file name: the project holds exactly one program and
	// Ghidra may have sanitised its name on import, so naming it here would be
	// a guess that fails silently by matching nothing.
	args := []string{
		m.projectDir(job.ID), "ghidrarest",
		"-process",
		"-noanalysis",
		"-scriptPath", m.cfg.ScriptDir,
		"-postScript", "ApplySignature.java",
		m.ArtifactsDir(job.ID),
		opsPath,
		resPath,
		strconv.Itoa(job.Options.DecompileTimeout),
	}

	sigRuns.Lock()
	defer sigRuns.Unlock()

	out, runErr := m.runHeadlessTool(ctx, job, bin, args, "signature")

	results, parseErr := readSigResults(resPath)
	if parseErr != nil || len(results) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("analyzeHeadless failed: %v\n%s", runErr, tail(out, 2000))
		}
		return nil, fmt.Errorf("the apply script produced no result\n%s", tail(out, 2000))
	}

	// Artifacts on disk have just changed under the cache; the next read must
	// come from the files, not from what was parsed before the edit.
	m.arts.dropJob(job.ID)
	return results, nil
}

func readSigResults(path string) ([]SigResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []SigResult
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		r := SigResult{Address: f[0], OK: f[1] == "ok", Before: f[2]}
		if r.OK {
			r.Prototype = f[3]
		} else {
			r.Error = f[3]
		}
		out = append(out, r)
	}
	return out, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(s[len(s)-n:])
}
