package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/onixldlc/ghidra-rest/src/internal/jobs"
)

// Byte patching: the second half of the API that writes into Ghidra instead of
// reading what an analysis left behind. See jobs/patch.go for why it edits the
// kept project rather than analysing a patched copy of the file.

func (s *Server) handlePatches(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	led, err := s.mgr.Patches(job.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	entries := make([]*jobs.PatchEntry, 0, len(led.Entries))
	for _, e := range led.Entries {
		entries = append(entries, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"job":      job.ID,
		"editable": s.mgr.HasProject(job.ID),
		"count":    len(entries),
		"patch":    entries,
	})
}

// handleSetPatch writes bytes at one address.
func (s *Server) handleSetPatch(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	var body struct {
		// Contiguous lowercase hex, no separators: "9090909090".
		Bytes string `json:"bytes"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body must be {\"bytes\": \"90 as hex\"}: "+err.Error())
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	s.runPatch(w, r, job, []jobs.PatchOp{{Addr: addr, Bytes: body.Bytes}})
}

// handleSetPatches writes many addresses in one headless pass. This is the one
// that matters for a client restoring a whole saved state: forty addresses in
// one JVM start rather than forty of them.
func (s *Server) handleSetPatches(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	var body struct {
		Patches []struct {
			Address string `json:"address"`
			Bytes   string `json:"bytes"`
		} `json:"patches"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest,
			"body must be {\"patches\": [{\"address\": \"...\", \"bytes\": \"...\"}]}: "+err.Error())
		return
	}
	ops := make([]jobs.PatchOp, 0, len(body.Patches))
	for _, p := range body.Patches {
		ops = append(ops, jobs.PatchOp{Addr: jobs.NormAddr(p.Address), Bytes: p.Bytes})
	}
	s.runPatch(w, r, job, ops)
}

func (s *Server) runPatch(w http.ResponseWriter, r *http.Request, job *jobs.Job, ops []jobs.PatchOp) {
	start := time.Now()
	res, err := s.mgr.SetPatches(r.Context(), job, ops)
	if err != nil {
		s.patchError(w, err)
		return
	}
	s.writePatchResult(w, job, res, start)
}

func (s *Server) handleClearPatch(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	start := time.Now()
	res, err := s.mgr.ClearPatch(r.Context(), job, addr)
	if err != nil {
		s.patchError(w, err)
		return
	}
	s.writePatchResult(w, job, []jobs.PatchResult{*res}, start)
}

// writePatchResult answers with every op's outcome and the functions whose
// artifacts were rewritten, so a client knows exactly what to re-fetch. A patch
// changes instructions, so both the disassembly and the decompilation of the
// containing function are new -- and so is the decompilation of its callers.
//
// The status is 200 when every op landed and 422 when any did not: the request
// was well formed, the bytes were not placeable. Partial success is still 422
// with the per-op detail, because a client that ignored the body and looked
// only at the code would otherwise believe a half-applied state is whole.
func (s *Server) writePatchResult(w http.ResponseWriter, job *jobs.Job, res []jobs.PatchResult,
	start time.Time) {

	funcs := map[string]bool{}
	applied := 0
	failed := 0
	for _, r := range res {
		if r.OK {
			applied++
			if r.Function != "" {
				funcs[r.Function] = true
			}
		} else {
			failed++
		}
	}
	stale := make([]string, 0, len(funcs))
	for a := range funcs {
		stale = append(stale, a)
	}

	out := map[string]any{
		"job":         job.ID,
		"ok":          failed == 0,
		"applied":     applied,
		"failed":      failed,
		"patch":       res,
		"functions":   stale,
		"duration_ms": time.Since(start).Milliseconds(),
	}
	status := http.StatusOK
	if failed > 0 {
		status = http.StatusUnprocessableEntity
		out["error"] = "some patches did not apply"
		out["status"] = status
	}
	writeJSON(w, status, out)
}

func (s *Server) patchError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jobs.ErrNoProject):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, jobs.ErrNotPatched):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, jobs.ErrNoBytes), errors.Is(err, jobs.ErrBadPatch):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
