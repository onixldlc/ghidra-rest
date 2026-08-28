package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/onixldlc/ghidra-rest/src/internal/jobs"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "ok\n")
}

func (s *Server) handleHealthJSON(w http.ResponseWriter, r *http.Request) {
	_, total := s.mgr.List("", 0, 0)
	_, running := s.mgr.List(string(jobs.StatusRunning), 0, 0)
	_, queued := s.mgr.List(string(jobs.StatusQueued), 0, 0)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"jobs":    total,
		"running": running,
		"queued":  queued,
		"workers": s.cfg.MaxConcurrent,
	})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":        "ghidra-rest",
		"version":        s.version,
		"api":            "v1",
		"ghidra_version": s.mgr.GhidraVersion(),
		"ghidra_home":    s.cfg.GhidraHome,
	})
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":        "ghidra-rest",
		"version":        s.version,
		"ghidra_version": s.mgr.GhidraVersion(),
		"limits": map[string]any{
			"max_upload_bytes":      s.cfg.MaxUploadBytes,
			"max_concurrent":        s.cfg.MaxConcurrent,
			"queue_size":            s.cfg.QueueSize,
			"analysis_timeout_sec":  int(s.cfg.AnalysisTimeout.Seconds()),
			"decompile_timeout_sec": s.cfg.DecompileTimeout,
			"decompile_max_funcs":   s.cfg.DecompileMaxFuncs,
			"max_export_bytes":      s.cfg.MaxExportBytes,
			"max_page_size":         s.cfg.MaxPageSize,
			"max_hexdump_bytes":     s.cfg.MaxHexdumpBytes,
		},
		"features": []string{
			"multipart-upload", "base64-upload", "sha256-dedup", "cancel",
			"decompilation", "xrefs", "strings", "symbols", "imports", "exports",
			"types", "memory-hexdump", "artifact-zip-export",
		},
		"endpoints": []string{
			"GET /healthz",
			"GET /v1/health",
			"GET /v1/version",
			"GET /v1/capabilities",
			"POST /v1/jobs",
			"POST /v1/jobs/base64",
			"GET /v1/jobs",
			"GET /v1/jobs/{id}",
			"DELETE /v1/jobs/{id}",
			"POST /v1/jobs/{id}/cancel",
			"GET /v1/jobs/{id}/log",
			"GET /v1/jobs/{id}/input",
			"GET /v1/jobs/{id}/export",
			"GET /v1/results/{id}/summary",
			"GET /v1/results/{id}/functions",
			"GET /v1/results/{id}/function/{addr}",
			"GET /v1/results/{id}/function/{addr}/decompile",
			"GET /v1/results/{id}/decompiled",
			"GET /v1/results/{id}/xrefs/{addr}",
			"GET /v1/results/{id}/strings",
			"GET /v1/results/{id}/symbols",
			"GET /v1/results/{id}/imports",
			"GET /v1/results/{id}/exports",
			"GET /v1/results/{id}/types",
			"GET /v1/results/{id}/memory",
			"GET /v1/results/{id}/hexdump/{addr}",
		},
	})
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotFound, "no such endpoint; see GET /v1/capabilities")
}

// -------------------------------------------------------------- submission

func (s *Server) optionsFromForm(get func(string) string) jobs.JobOptions {
	o := jobs.JobOptions{Decompile: s.cfg.DecompileDefault}
	if v := get("decompile"); v != "" {
		o.Decompile = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	}
	atoi := func(key string) int {
		n, err := strconv.Atoi(get(key))
		if err != nil || n < 0 {
			return 0
		}
		return n
	}
	o.DecompileMaxFuncs = atoi("decompile_max_funcs")
	o.DecompileTimeout = atoi("decompile_timeout_sec")
	o.AnalysisTimeout = atoi("analysis_timeout_sec")
	o.Processor = get("processor")
	o.CompilerSpec = get("compiler_spec")
	o.Loader = get("loader")
	return o
}

func (s *Server) handleSubmitMultipart(w http.ResponseWriter, r *http.Request) {
	// +1 MiB of slack for the multipart framing and the option fields.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "cannot parse multipart form: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, `expected a file part named "file"`)
		return
	}
	defer file.Close()

	name := r.FormValue("name")
	if name == "" && header != nil {
		name = header.Filename
	}
	force := r.FormValue("force") == "1" || strings.EqualFold(r.FormValue("force"), "true")

	s.submit(w, name, file, s.optionsFromForm(r.FormValue), force)
}

type base64Request struct {
	Filename string `json:"filename"`
	Data     string `json:"data_base64"`
	DataAlt  string `json:"data"`
	Force    bool   `json:"force"`

	Decompile         *bool  `json:"decompile"`
	DecompileMaxFuncs int    `json:"decompile_max_funcs"`
	DecompileTimeout  int    `json:"decompile_timeout_sec"`
	AnalysisTimeout   int    `json:"analysis_timeout_sec"`
	Processor         string `json:"processor"`
	CompilerSpec      string `json:"compiler_spec"`
	Loader            string `json:"loader"`
}

func (s *Server) handleSubmitBase64(w http.ResponseWriter, r *http.Request) {
	// base64 costs a third more bytes than the payload it carries.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes*4/3+(1<<20))
	var req base64Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "cannot parse JSON body: "+err.Error())
		return
	}
	data := req.Data
	if data == "" {
		data = req.DataAlt
	}
	if data == "" {
		writeError(w, http.StatusBadRequest, `field "data_base64" is required`)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
	if err != nil {
		writeError(w, http.StatusBadRequest, "data_base64 is not valid base64: "+err.Error())
		return
	}

	opts := jobs.JobOptions{
		Decompile:         s.cfg.DecompileDefault,
		DecompileMaxFuncs: req.DecompileMaxFuncs,
		DecompileTimeout:  req.DecompileTimeout,
		AnalysisTimeout:   req.AnalysisTimeout,
		Processor:         req.Processor,
		CompilerSpec:      req.CompilerSpec,
		Loader:            req.Loader,
	}
	if req.Decompile != nil {
		opts.Decompile = *req.Decompile
	}

	s.submit(w, req.Filename, strings.NewReader(string(raw)), opts, req.Force)
}

func (s *Server) submit(w http.ResponseWriter, name string, body io.Reader, opts jobs.JobOptions, force bool) {
	job, existing, err := s.mgr.Submit(name, body, opts, force)
	switch {
	case errors.Is(err, jobs.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		return
	case errors.Is(err, jobs.ErrQueueFull):
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Location", "/v1/jobs/"+job.ID)
	status := http.StatusAccepted
	if existing {
		// Same bytes as a job that already exists. Returning 200 with the old
		// job, rather than re-analysing, is the whole point of the dedup.
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{"job": job, "deduplicated": existing})
}

// ------------------------------------------------------------ job lifecycle

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	limit, offset, _ := s.pageParams(r)
	status := r.URL.Query().Get("status")
	list, total := s.mgr.List(status, limit, offset)
	writeJSON(w, http.StatusOK, map[string]any{
		"total":  total,
		"count":  len(list),
		"limit":  limit,
		"offset": offset,
		"jobs":   list,
	})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.mgr.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such job")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.mgr.Cancel(r.PathValue("id"))
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such job")
	case err != nil:
		writeError(w, http.StatusConflict, err.Error())
	default:
		writeJSON(w, http.StatusOK, job)
	}
}

func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	err := s.mgr.Delete(r.PathValue("id"))
	switch {
	case errors.Is(err, jobs.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such job")
	case errors.Is(err, jobs.ErrNotTerminal):
		writeError(w, http.StatusConflict, "cancel the job before deleting it")
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleJobLog(w http.ResponseWriter, r *http.Request) {
	job, err := s.mgr.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such job")
		return
	}
	f, err := os.Open(s.mgr.LogPath(job.ID))
	if err != nil {
		writeError(w, http.StatusNotFound, "this job has no headless log yet")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if n, err := strconv.ParseInt(r.URL.Query().Get("tail"), 10, 64); err == nil && n > 0 {
		io.WriteString(w, s.mgr.LogTail(job.ID, n))
		return
	}
	io.Copy(w, f)
}

func (s *Server) handleJobInput(w http.ResponseWriter, r *http.Request) {
	job, err := s.mgr.Get(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such job")
		return
	}
	f, err := os.Open(s.mgr.InputPath(job))
	if err != nil {
		writeError(w, http.StatusNotFound, "the submitted file is gone")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+job.Filename+`"`)
	w.Header().Set("Content-Length", strconv.FormatInt(job.Size, 10))
	io.Copy(w, f)
}
