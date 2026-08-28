package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/onixldlc/ghidra-rest/src/internal/jobs"
)

// serveArtifactFile streams a JSON artifact through untouched. Used where the
// document is served whole (summary, memory index): re-encoding it would only
// cost CPU and risk changing it.
func (s *Server) serveArtifactFile(w http.ResponseWriter, jobID, rel string) {
	f, err := os.Open(filepath.Join(s.mgr.ArtifactsDir(jobID), filepath.FromSlash(rel)))
	if err != nil {
		writeError(w, http.StatusNotFound, "artifact "+rel+" is not present for this job")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	io.Copy(w, f)
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	s.serveArtifactFile(w, job.ID, "summary.json")
}

func (s *Server) handleMemory(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	s.serveArtifactFile(w, job.ID, "memory/index.json")
}

// handleArray builds a paged, filterable handler over one array artifact.
func (s *Server) handleArray(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		job, ok := s.resultJob(w, r)
		if !ok {
			return
		}
		art, err := s.mgr.LoadArray(job.ID, name)
		if errors.Is(err, jobs.ErrArtifactMissing) {
			writeError(w, http.StatusNotFound, "artifact "+name+" is not present for this job")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		limit, offset, q := s.pageParams(r)
		p := art.Page(q, limit, offset)
		p.Query = q
		writeJSON(w, http.StatusOK, p)
	}
}

func (s *Server) handleDecompiledIndex(w http.ResponseWriter, r *http.Request) {
	s.handleArray("decompiled/index.json")(w, r)
}

func (s *Server) handleFunction(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	art, err := s.mgr.LoadArray(job.ID, "functions.json")
	if err != nil {
		writeError(w, http.StatusNotFound, "no function list for this job")
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	raw, found := art.Find(addr)
	if !found {
		writeError(w, http.StatusNotFound, "no function at "+addr)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(raw)
	w.Write([]byte("\n"))
}

func (s *Server) handleDecompile(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	// Address keys can carry an address space prefix; the export script writes
	// those files with ':' replaced, so apply the same mapping here.
	file := strings.NewReplacer(":", "_", "/", "_").Replace(addr) + ".json"
	b, err := os.ReadFile(filepath.Join(s.mgr.ArtifactsDir(job.ID), "decompiled", file))
	if err != nil {
		if !job.Options.Decompile {
			writeError(w, http.StatusNotFound, "this job was submitted with decompile=false")
			return
		}
		writeError(w, http.StatusNotFound,
			"no decompilation for "+addr+"; it may be past decompile_max_funcs, external, or not a function")
		return
	}
	if r.URL.Query().Get("format") == "c" {
		var d struct {
			C string `json:"c"`
		}
		if err := json.Unmarshal(b, &d); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/x-c; charset=utf-8")
		io.WriteString(w, d.C)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(b)
}

func (s *Server) handleDisasmIndex(w http.ResponseWriter, r *http.Request) {
	s.handleArray("disasm/index.json")(w, r)
}

// handleDisasm serves one function's instruction listing. `?format=text`
// renders it the way a listing window would, which is what a terminal client
// wants and what the web UI falls back to.
func (s *Server) handleDisasm(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	file := strings.NewReplacer(":", "_", "/", "_").Replace(addr) + ".json"
	b, err := os.ReadFile(filepath.Join(s.mgr.ArtifactsDir(job.ID), "disasm", file))
	if err != nil {
		writeError(w, http.StatusNotFound,
			"no disassembly for "+addr+"; it may be external, a data address, or from a job analysed before disasm export existed")
		return
	}
	if r.URL.Query().Get("format") == "text" {
		var d struct {
			Instructions []struct {
				AddressDisplay string `json:"address_display"`
				Bytes          string `json:"bytes"`
				Text           string `json:"text"`
				Comment        string `json:"comment"`
			} `json:"instructions"`
		}
		if err := json.Unmarshal(b, &d); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for _, in := range d.Instructions {
			line := in.AddressDisplay + "  " + in.Bytes + "  " + in.Text
			if in.Comment != "" {
				line += "  ; " + in.Comment
			}
			io.WriteString(w, line+"\n")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(b)
}

func (s *Server) handleXrefs(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	obj, err := s.mgr.LoadObject(job.ID, "xrefs.json")
	if err != nil {
		writeError(w, http.StatusNotFound, "no xref index for this job")
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	raw, found := obj[addr]
	if !found {
		// An address with no references is a legitimate answer, but so is a
		// typo'd address. Say which by reporting emptiness explicitly.
		writeJSON(w, http.StatusOK, map[string]any{
			"address": addr,
			"to":      []any{},
			"from":    []any{},
			"indexed": false,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	out := map[string]json.RawMessage{"address": json.RawMessage(strconv.Quote(addr))}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inner); err == nil {
		for k, v := range inner {
			out[k] = v
		}
	}
	out["indexed"] = json.RawMessage("true")
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleHexdump(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}
	addr := jobs.NormAddr(r.PathValue("addr"))
	length := 256
	if v := r.URL.Query().Get("length"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			length = n
		}
	}
	if length > s.cfg.MaxHexdumpBytes {
		length = s.cfg.MaxHexdumpBytes
	}

	data, block, err := s.mgr.ReadMemory(job.ID, addr, length)
	if err != nil {
		status := http.StatusNotFound
		if block != nil {
			status = http.StatusRequestedRangeNotSatisfiable
		}
		writeError(w, status, err.Error())
		return
	}
	base, _ := jobs.AddrOffset(addr)
	if r.URL.Query().Get("format") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, jobs.Hexdump(base, data))
		return
	}
	if r.URL.Query().Get("format") == "raw" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"address": addr,
		"block":   block.Name,
		"length":  len(data),
		"base64":  base64.StdEncoding.EncodeToString(data),
		"hex":     jobs.Hexdump(base, data),
	})
}
