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
	"time"
)

// Patching bytes is the second operation that writes back into Ghidra, and it
// works the same way retyping does: re-open the job's *kept* project with
// -noanalysis and run a script over it. See signature.go for the shape.
//
// The reason it is worth having at all: the obvious way to make Ghidra look at
// patched bytes is to submit the patched file as a new job. On a 239 MiB
// binary that is another 1.1 GB on disk and another full analysis, for four
// changed bytes. Here the program already knows everything except those bytes,
// so the cost is a JVM start plus re-disassembling and re-decompiling one
// function.
//
// The ledger is not a cache of what the program contains -- the program is the
// truth. It exists for the one thing the program cannot answer once it has
// been written over: what was there before.

var (
	// ErrNoBytes means the ops carried nothing to write.
	ErrNoBytes = errors.New("no bytes to patch")
	// ErrNotPatched means the address has no recorded patch to revert.
	ErrNotPatched = errors.New("no patch has been applied at that address")
	// ErrBadPatch means the request itself was malformed -- bad hex, too many
	// bytes -- as opposed to bytes Ghidra refused to place.
	ErrBadPatch = errors.New("bad patch")
)

const (
	// maxPatchBytes bounds one op. A patch is an edit, not a way to stream a
	// new program in through the side door.
	maxPatchBytes = 64 << 10
	// maxPatchOps bounds one run. Every op is cheap, but the result file is
	// read into memory and the whole set lands in one transaction each.
	maxPatchOps = 4096
)

// PatchOp is one run of bytes to write at one address.
type PatchOp struct {
	Addr string
	// Bytes is contiguous lowercase hex, no separators: "9090909090".
	Bytes string
}

// PatchResult is what ApplyPatch.java reported for one op.
type PatchResult struct {
	Address string `json:"address"`
	OK      bool   `json:"ok"`
	// Before is what those bytes were immediately before this run.
	Before string `json:"before"`
	// Function is the entry point of the function the patch landed in, empty
	// when the address is not inside one.
	Function string `json:"function,omitempty"`
	Error    string `json:"error,omitempty"`
}

// PatchEntry is the durable record of one patched address. Original is
// captured the first time the address is touched, which is what makes a later
// revert possible.
type PatchEntry struct {
	Address  string    `json:"address"`
	Bytes    string    `json:"bytes"`
	Original string    `json:"original"`
	Function string    `json:"function,omitempty"`
	At       time.Time `json:"at"`
}

// PatchLedger is <data>/jobs/<id>/patches.json.
type PatchLedger struct {
	Version int                    `json:"version"`
	Entries map[string]*PatchEntry `json:"entries"`
}

// PatchPath is the per-job record of patched bytes.
func (m *Manager) PatchPath(id string) string {
	return filepath.Join(m.jobDir(id), "patches.json")
}

// Patches reads the ledger. A job that was never patched has an empty one
// rather than an error.
func (m *Manager) Patches(id string) (*PatchLedger, error) {
	led := &PatchLedger{Version: 1, Entries: map[string]*PatchEntry{}}
	b, err := os.ReadFile(m.PatchPath(id))
	if err != nil {
		if os.IsNotExist(err) {
			return led, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(b, led); err != nil {
		return nil, fmt.Errorf("patches.json is corrupt: %w", err)
	}
	if led.Entries == nil {
		led.Entries = map[string]*PatchEntry{}
	}
	return led, nil
}

func (m *Manager) writePatches(id string, led *PatchLedger) error {
	led.Version = 1
	b, err := json.MarshalIndent(led, "", "  ")
	if err != nil {
		return err
	}
	// Write then rename: a torn patches.json would lose recorded originals,
	// and an original cannot be recovered once it has been written over.
	tmp := m.PatchPath(id) + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.PatchPath(id))
}

// SetPatches writes every op in one headless pass and records what each
// address held before. Ops that fail are reported and leave no ledger row; the
// rest still land, because one unparseable address is not a reason to abandon
// the other forty.
func (m *Manager) SetPatches(ctx context.Context, job *Job, ops []PatchOp) ([]PatchResult, error) {
	clean := make([]PatchOp, 0, len(ops))
	for _, op := range ops {
		addr := NormAddr(op.Addr)
		hex := strings.ToLower(strings.TrimSpace(op.Bytes))
		if addr == "" || hex == "" {
			continue
		}
		if err := validHex(hex); err != nil {
			return nil, fmt.Errorf("%s: %w", addr, err)
		}
		clean = append(clean, PatchOp{Addr: addr, Bytes: hex})
	}
	if len(clean) == 0 {
		return nil, ErrNoBytes
	}
	if len(clean) > maxPatchOps {
		return nil, fmt.Errorf("%w: too many patches in one request: %d, the limit is %d",
			ErrBadPatch, len(clean), maxPatchOps)
	}

	res, err := m.applyPatches(ctx, job, clean)
	if err != nil {
		return nil, err
	}

	led, err := m.Patches(job.ID)
	if err != nil {
		return nil, err
	}
	want := map[string]string{}
	for _, op := range clean {
		want[op.Addr] = op.Bytes
	}
	changed := false
	for _, r := range res {
		if !r.OK {
			continue
		}
		e := led.Entries[r.Address]
		original := r.Before
		if e != nil {
			// Second edit of the same address: what it held a moment ago is
			// the previous patch, not the program as it was analysed.
			original = e.Original
		}
		if want[r.Address] == original {
			// Patched back to what the analyser saw. Not a patch any more.
			if e != nil {
				delete(led.Entries, r.Address)
				changed = true
			}
			continue
		}
		led.Entries[r.Address] = &PatchEntry{
			Address:  r.Address,
			Bytes:    want[r.Address],
			Original: original,
			Function: r.Function,
			At:       time.Now().UTC(),
		}
		changed = true
	}
	if changed {
		if err := m.writePatches(job.ID, led); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// ClearPatch writes the recorded original back and drops the ledger row.
func (m *Manager) ClearPatch(ctx context.Context, job *Job, addr string) (*PatchResult, error) {
	addr = NormAddr(addr)
	led, err := m.Patches(job.ID)
	if err != nil {
		return nil, err
	}
	e := led.Entries[addr]
	if e == nil {
		return nil, ErrNotPatched
	}
	res, err := m.applyPatches(ctx, job, []PatchOp{{Addr: addr, Bytes: e.Original}})
	if err != nil {
		return nil, err
	}
	r := pickPatch(res, addr)
	if r == nil {
		return nil, errors.New("the patch script reported nothing for " + addr)
	}
	if !r.OK {
		return r, nil
	}
	delete(led.Entries, addr)
	if err := m.writePatches(job.ID, led); err != nil {
		return nil, err
	}
	return r, nil
}

func pickPatch(res []PatchResult, addr string) *PatchResult {
	for i := range res {
		if res[i].Address == addr {
			return &res[i]
		}
	}
	return nil
}

func validHex(s string) error {
	if len(s)%2 != 0 {
		return fmt.Errorf("%w: bytes must be whole hex pairs", ErrBadPatch)
	}
	if len(s)/2 > maxPatchBytes {
		return fmt.Errorf("%w: patch is %d bytes, the limit is %d",
			ErrBadPatch, len(s)/2, maxPatchBytes)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("%w: bytes must be lowercase hex with no separators", ErrBadPatch)
		}
	}
	return nil
}

// applyPatches runs one headless pass over the kept project.
func (m *Manager) applyPatches(ctx context.Context, job *Job, ops []PatchOp) ([]PatchResult, error) {
	if !m.HasProject(job.ID) {
		return nil, ErrNoProject
	}
	bin := filepath.Join(m.cfg.GhidraHome, "support", "analyzeHeadless")
	if _, err := os.Stat(bin); err != nil {
		return nil, fmt.Errorf("analyzeHeadless not found under %s: %w", m.cfg.GhidraHome, err)
	}
	script := filepath.Join(m.cfg.ScriptDir, "RestScript.java")
	if _, err := os.Stat(script); err != nil {
		return nil, fmt.Errorf("task script not found: %w", err)
	}

	dir, err := os.MkdirTemp(m.tmpDir(), "patch-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	opsPath := filepath.Join(dir, "ops.tsv")
	resPath := filepath.Join(dir, "result.tsv")
	var sb strings.Builder
	for _, op := range ops {
		// Both fields are validated above, so neither can carry a tab or a
		// newline; this is the writer, not an encoder.
		fmt.Fprintf(&sb, "%s\t%s\n", op.Addr, op.Bytes)
	}
	if err := os.WriteFile(opsPath, []byte(sb.String()), 0o644); err != nil {
		return nil, err
	}
	// The script overwrites this; create it empty so a JVM that died before
	// writing is distinguishable from one that reported nothing.
	if err := os.WriteFile(resPath, nil, 0o644); err != nil {
		return nil, err
	}

	// Same budget as a signature run: both are one JVM over a kept project
	// doing a bounded amount of decompilation.
	ctx, cancel := context.WithTimeout(ctx, m.cfg.SignatureTimeout)
	defer cancel()

	args := []string{
		m.projectDir(job.ID), "ghidrarest",
		"-process",
		"-noanalysis",
		"-scriptPath", m.cfg.ScriptDir,
		"-postScript", "RestScript.java",
		"patch",
		m.ArtifactsDir(job.ID),
		opsPath,
		resPath,
		strconv.Itoa(job.Options.DecompileTimeout),
	}

	// Serialised against signature runs as well as against each other: both
	// open the same project in a JVM sized by JAVA_MAX_MEM, and two of those
	// at once on one project is a corrupt project rather than a slow one.
	editRuns.Lock()
	defer editRuns.Unlock()

	out, runErr := m.runHeadlessTool(ctx, job, bin, args, "patch")

	results, parseErr := readPatchResults(resPath)
	if parseErr != nil || len(results) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("analyzeHeadless failed: %v\n%s", runErr, tail(out, 2000))
		}
		return nil, fmt.Errorf("the patch script produced no result\n%s", tail(out, 2000))
	}

	// Artifacts on disk have just changed under the cache; the next read must
	// come from the files, not from what was parsed before the patch.
	m.arts.dropJob(job.ID)
	return results, nil
}

func readPatchResults(path string) ([]PatchResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []PatchResult
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		r := PatchResult{Address: f[0], OK: f[1] == "ok", Before: f[2]}
		if r.OK {
			r.Function = f[3]
		} else {
			r.Error = f[3]
		}
		out = append(out, r)
	}
	return out, nil
}
