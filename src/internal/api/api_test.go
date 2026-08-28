package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/onixldlc/ghidra-rest/src/internal/config"
	"github.com/onixldlc/ghidra-rest/src/internal/jobs"
)

// newTestServer builds a manager with no workers started, so submitted jobs
// stay queued and no Ghidra install is needed.
func newTestServer(t *testing.T) (*Server, *jobs.Manager) {
	t.Helper()
	cfg := config.Load()
	cfg.DataDir = t.TempDir()
	cfg.MaxConcurrent = 1
	cfg.DefaultPageSize = 100
	cfg.MaxPageSize = 1000
	mgr, err := jobs.NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return New(cfg, mgr, "test"), mgr
}

func TestHTTPBasics(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("healthz = %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/version", nil))
	var v map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("version body: %v", err)
	}
	if v["service"] != "ghidra-rest" {
		t.Fatalf("version = %v", v)
	}
	if v["version"] != "test" {
		t.Fatalf("build stamp not reported: %v", v["version"])
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/nope", nil))
	if rec.Code != 404 {
		t.Fatalf("unknown route = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/jobs/base64",
		strings.NewReader(`{"filename":"x","data_base64":"!!!"}`)))
	if rec.Code != 400 {
		t.Fatalf("bad base64 = %d", rec.Code)
	}
}

// Results are refused while a job has none, rather than serving half of a
// running analysis.
func TestResultsBeforeDone(t *testing.T) {
	srv, mgr := newTestServer(t)
	job, _, err := mgr.Submit("sample.bin", strings.NewReader("MZ hello"), jobs.JobOptions{}, false)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/v1/results/"+job.ID+"/summary", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("summary of a queued job = %d, want 409", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/v1/results/nosuchjob/summary", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("summary of an unknown job = %d, want 404", rec.Code)
	}
}

func TestAuthToken(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.cfg.APIToken = "s3cret"
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/jobs", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}

	// The health endpoint stays open so container healthchecks keep working.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 {
		t.Fatalf("healthz with a token set = %d", rec.Code)
	}

	req := httptest.NewRequest("GET", "/v1/jobs", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("authenticated = %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/v1/jobs", nil)
	req.Header.Set("X-API-Key", "s3cret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("X-API-Key = %d", rec.Code)
	}
}
