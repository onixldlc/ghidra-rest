// Package api is the HTTP layer: routing, middleware and handlers. It reads
// artifacts through the jobs package and never talks to Ghidra itself.
package api

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/onixldlc/ghidra-rest/src/internal/config"
	"github.com/onixldlc/ghidra-rest/src/internal/jobs"
)

type Server struct {
	cfg     *config.Config
	mgr     *jobs.Manager
	version string
}

// New wires a server. version is the build stamp reported by /v1/version; it
// lives in main so -ldflags "-X main.version=..." keeps working.
func New(cfg *config.Config, mgr *jobs.Manager, version string) *Server {
	if version == "" {
		version = "dev"
	}
	return &Server{cfg: cfg, mgr: mgr, version: version}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/health", s.handleHealthJSON)
	mux.HandleFunc("GET /v1/version", s.handleVersion)
	mux.HandleFunc("GET /v1/capabilities", s.handleCapabilities)

	mux.HandleFunc("POST /v1/jobs", s.handleSubmitMultipart)
	mux.HandleFunc("POST /v1/jobs/base64", s.handleSubmitBase64)
	mux.HandleFunc("GET /v1/jobs", s.handleListJobs)
	mux.HandleFunc("GET /v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("DELETE /v1/jobs/{id}", s.handleDeleteJob)
	mux.HandleFunc("POST /v1/jobs/{id}/cancel", s.handleCancelJob)
	mux.HandleFunc("GET /v1/jobs/{id}/log", s.handleJobLog)
	mux.HandleFunc("GET /v1/jobs/{id}/input", s.handleJobInput)
	mux.HandleFunc("GET /v1/jobs/{id}/export", s.handleJobExport)

	mux.HandleFunc("GET /v1/results/{id}/summary", s.handleSummary)
	mux.HandleFunc("GET /v1/results/{id}/functions", s.handleArray("functions.json"))
	mux.HandleFunc("GET /v1/results/{id}/strings", s.handleArray("strings.json"))
	mux.HandleFunc("GET /v1/results/{id}/symbols", s.handleArray("symbols.json"))
	mux.HandleFunc("GET /v1/results/{id}/imports", s.handleArray("imports.json"))
	mux.HandleFunc("GET /v1/results/{id}/exports", s.handleArray("exports.json"))
	mux.HandleFunc("GET /v1/results/{id}/types", s.handleArray("types.json"))
	mux.HandleFunc("GET /v1/results/{id}/memory", s.handleMemory)
	mux.HandleFunc("GET /v1/results/{id}/function/{addr}", s.handleFunction)
	mux.HandleFunc("GET /v1/results/{id}/function/{addr}/decompile", s.handleDecompile)
	mux.HandleFunc("GET /v1/results/{id}/decompiled", s.handleDecompiledIndex)
	mux.HandleFunc("GET /v1/results/{id}/xrefs/{addr}", s.handleXrefs)
	mux.HandleFunc("GET /v1/results/{id}/hexdump/{addr}", s.handleHexdump)

	mux.HandleFunc("/", s.handleNotFound)

	var h http.Handler = mux
	h = s.auth(h)
	h = s.cors(h)
	h = s.logging(h)
	return recoverer(h)
}

// ------------------------------------------------------------- middleware

func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				log.Printf("panic: %v\n%s", v, debug.Stack())
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Verbose && r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		if s.cfg.Verbose || sw.status >= 400 {
			log.Printf("%s %s %d %dB %s", r.Method, r.URL.RequestURI(), sw.status, sw.bytes,
				time.Since(start).Round(time.Millisecond))
		}
	})
}

// auth is a single shared bearer token, off by default. This is a lab service
// that runs an analyzer on attacker-supplied files; anything past a token
// belongs in a reverse proxy in front of it.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.APIToken == "" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.Header.Get("X-API-Key")
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.APIToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ghidra-rest"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid API token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.CORSOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", s.cfg.CORSOrigin)
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		log.Printf("write: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "status": status})
}

func (s *Server) pageParams(r *http.Request) (limit, offset int, q string) {
	limit = s.cfg.DefaultPageSize
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > s.cfg.MaxPageSize {
		limit = s.cfg.MaxPageSize
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset, strings.TrimSpace(r.URL.Query().Get("q"))
}

// resultJob resolves an id and refuses anything that has no artifacts, so
// result endpoints never serve half of a running analysis.
func (s *Server) resultJob(w http.ResponseWriter, r *http.Request) (*jobs.Job, bool) {
	id := r.PathValue("id")
	job, err := s.mgr.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "no such job")
		return nil, false
	}
	if job.Status != jobs.StatusDone {
		writeError(w, http.StatusConflict, "job is "+string(job.Status)+", results are not available")
		return nil, false
	}
	return job, true
}
