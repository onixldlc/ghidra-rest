package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/onixldlc/ghidra-rest/src/internal/jobs"
)

// Function signature editing: the only part of the API that writes back into
// Ghidra rather than reading what an analysis left behind. See
// jobs/signature.go for why it needs the kept project, and docs/SIGNATURES.md
// for the shape of a prototype.

func (s *Server) handleSignatures(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	led, err := s.mgr.Signatures(job.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// A list, not the on-disk map: clients page and sort lists everywhere
	// else, and the address is already inside each entry.
	entries := make([]*jobs.SigEntry, 0, len(led.Entries))
	for _, e := range led.Entries {
		entries = append(entries, e)
	}
	conventions := s.mgr.Conventions(job.ID)
	if conventions == nil {
		conventions = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"job":       job.ID,
		"editable":  s.mgr.HasProject(job.ID),
		"count":     len(entries),
		"signature": entries,
		// what this program's compiler spec accepts; empty when the analysis
		// predates the field and no signature has been applied yet
		"calling_conventions": conventions,
	})
}

func (s *Server) handleSetSignature(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	var body struct {
		Prototype string `json:"prototype"`
		// Optional. Ghidra's C parser accepts `__cdecl` inside the prototype
		// and then discards it, which leaves a function with locked parameter
		// storage and an "unknown" convention -- the state that makes the
		// decompiler print "parameter storage is locked". Send it here instead.
		Convention string `json:"calling_convention"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "body must be {\"prototype\": \"...\"}: "+err.Error())
		return
	}

	addr := jobs.NormAddr(r.PathValue("addr"))
	start := time.Now()
	entry, res, err := s.mgr.SetSignature(r.Context(), job, addr, body.Prototype, body.Convention)
	if err != nil {
		s.signatureError(w, err)
		return
	}
	if !res.OK {
		// The request was well formed, the prototype was not. 422 keeps this
		// distinct from "no such function" (404) and from a broken run (500),
		// which is what a UI needs to decide between showing a field error and
		// showing a failure.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":       res.Error,
			"status":      http.StatusUnprocessableEntity,
			"address":     addr,
			"before":      res.Before,
			"prototype":   body.Prototype,
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return
	}
	s.writeSignatureOK(w, job, addr, entry, res, start)
}

func (s *Server) handleClearSignature(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	start := time.Now()
	res, err := s.mgr.ClearSignature(r.Context(), job, addr)
	if err != nil {
		if errors.Is(err, jobs.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no signature has been set on "+addr)
			return
		}
		s.signatureError(w, err)
		return
	}
	if !res.OK {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":       res.Error,
			"status":      http.StatusUnprocessableEntity,
			"address":     addr,
			"before":      res.Before,
			"duration_ms": time.Since(start).Milliseconds(),
		})
		return
	}
	s.writeSignatureOK(w, job, addr, nil, res, start)
}

// writeSignatureOK answers with the function as it now reads, plus the callers
// that were re-decompiled alongside it. A caller's C text names the callee's
// parameters and consumes its return value, so a client that repaints only the
// edited function would leave stale text on screen next to fresh text.
func (s *Server) writeSignatureOK(w http.ResponseWriter, job *jobs.Job, addr string,
	entry *jobs.SigEntry, res *jobs.SigResult, start time.Time) {

	out := map[string]any{
		"job":         job.ID,
		"address":     addr,
		"ok":          true,
		"before":      res.Before,
		"prototype":   res.Prototype,
		"duration_ms": time.Since(start).Milliseconds(),
	}
	if entry != nil {
		out["original"] = entry.Original
		out["set_at"] = entry.At
		if entry.Convention != "" {
			out["calling_convention"] = entry.Convention
		}
	}

	// Reload from disk: applySignatures dropped the cache, so this is the file
	// the apply script just wrote.
	if art, err := s.mgr.LoadArray(job.ID, "functions.json"); err == nil {
		if raw, found := art.Find(addr); found {
			out["function"] = json.RawMessage(raw)
			var fn struct {
				CalledBy []struct {
					Address string `json:"address"`
				} `json:"called_by"`
			}
			if json.Unmarshal(raw, &fn) == nil {
				stale := make([]string, 0, len(fn.CalledBy)+1)
				stale = append(stale, addr)
				for _, c := range fn.CalledBy {
					stale = append(stale, c.Address)
				}
				out["redecompiled"] = stale
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) signatureError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jobs.ErrNoProject):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, jobs.ErrNoFunction):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, jobs.ErrArtifactMissing):
		writeError(w, http.StatusNotFound, "this job has no function list")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
