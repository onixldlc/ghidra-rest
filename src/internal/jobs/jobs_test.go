package jobs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onixldlc/ghidra-rest/src/internal/config"
)

// testConfig points a real Config at a temp dir. No workers are started in
// these tests, so submitted jobs stay queued and no Ghidra install is needed.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Load()
	cfg.DataDir = t.TempDir()
	cfg.MaxConcurrent = 1
	cfg.DefaultPageSize = 100
	cfg.MaxPageSize = 1000
	return cfg
}

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	mgr, err := NewManager(testConfig(t))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func TestNormAddr(t *testing.T) {
	cases := map[string]string{
		"0x00401000": "401000",
		"00401000":   "401000",
		"401000":     "401000",
		"0X401000":   "401000",
		"  401000 ":  "401000",
		"00000000":   "0",
		"ram:001000": "ram:1000",
		"EXTERNAL:1": "external:1",
	}
	for in, want := range cases {
		if got := NormAddr(in); got != want {
			t.Errorf("NormAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAddrOffset(t *testing.T) {
	n, err := AddrOffset("0x00401000")
	if err != nil || n != 0x401000 {
		t.Fatalf("AddrOffset = %x, %v", n, err)
	}
	if _, err := AddrOffset("ram:00ff"); err != nil {
		t.Fatalf("space prefix should parse: %v", err)
	}
	if _, err := AddrOffset("nothex"); err == nil {
		t.Fatal("expected an error for a non-hex address")
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd": "passwd",
		"":                 "binary",
		"..":               "binary",
		"a/b/c.exe":        "c.exe",
		"plain.bin":        "plain.bin",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeName(strings.Repeat("x", 500)); len(got) != 128 {
		t.Errorf("long name not truncated: %d", len(got))
	}
}

func TestHexdump(t *testing.T) {
	out := Hexdump(0x401000, []byte("AB\x00\xff"))
	if !strings.HasPrefix(out, "00401000  41 42 00 ff ") {
		t.Errorf("unexpected hex column: %q", out)
	}
	if !strings.Contains(out, "|AB..|") {
		t.Errorf("unexpected ascii column: %q", out)
	}
}

func TestArtifactPaging(t *testing.T) {
	mgr := newTestManager(t)
	id := "jobid"
	dir := mgr.ArtifactsDir(id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `[{"name":"main","address":"401000"},{"name":"helper","address":"401100"},{"name":"other","address":"401200"}]`
	if err := os.WriteFile(filepath.Join(dir, "functions.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	art, err := mgr.LoadArray(id, "functions.json")
	if err != nil {
		t.Fatalf("LoadArray: %v", err)
	}
	p := art.Page("", 2, 0)
	if p.Total != 3 || p.Count != 2 || p.Offset != 0 {
		t.Fatalf("page = %+v", p)
	}
	p = art.Page("", 2, 2)
	if p.Count != 1 {
		t.Fatalf("second page = %+v", p)
	}
	p = art.Page("help", 100, 0)
	if p.Total != 1 || p.Count != 1 {
		t.Fatalf("filtered page = %+v", p)
	}
	// Offsets past the end return an empty page, not an error or a panic.
	if p := art.Page("", 10, 99); p.Count != 0 {
		t.Fatalf("out of range page = %+v", p)
	}
	if _, ok := art.Find("401100"); !ok {
		t.Fatal("Find missed an address that is present")
	}
	if _, ok := art.Find("999999"); ok {
		t.Fatal("Find matched an address that is absent")
	}
}

func TestSubmitDedupAndLifecycle(t *testing.T) {
	mgr := newTestManager(t)

	job, existing, err := mgr.Submit("sample.bin", strings.NewReader("MZ hello"), JobOptions{}, false)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if existing {
		t.Fatal("first submit reported a duplicate")
	}
	if job.Status != StatusQueued {
		t.Fatalf("status = %s", job.Status)
	}

	same, existing, err := mgr.Submit("sample.bin", strings.NewReader("MZ hello"), JobOptions{}, false)
	if err != nil {
		t.Fatalf("second Submit: %v", err)
	}
	if !existing || same.ID != job.ID {
		t.Fatalf("identical bytes were not deduplicated: %v %s", existing, same.ID)
	}

	forced, _, err := mgr.Submit("sample.bin", strings.NewReader("MZ hello"), JobOptions{}, true)
	if err != nil {
		t.Fatalf("forced Submit: %v", err)
	}
	if forced.ID == job.ID {
		t.Fatal("force=true reused the existing job")
	}

	// A queued job cancels without a running analyzer.
	if _, err := mgr.Cancel(job.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if got, _ := mgr.Get(job.ID); got.Status != StatusCanceled {
		t.Fatalf("status after cancel = %s", got.Status)
	}
	if err := mgr.Delete(job.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := mgr.Get(job.ID); err == nil {
		t.Fatal("deleted job is still readable")
	}
}

func TestUploadTooLarge(t *testing.T) {
	mgr := newTestManager(t)
	mgr.cfg.MaxUploadBytes = 8
	if _, _, err := mgr.Submit("big.bin", strings.NewReader("123456789"), JobOptions{}, false); err == nil {
		t.Fatal("oversized upload was accepted")
	}
}

func TestReloadMarksInterrupted(t *testing.T) {
	cfg := testConfig(t)
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	job, _, err := mgr.Submit("x.bin", strings.NewReader("data"), JobOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	// Pretend the process died mid-analysis.
	mgr.mu.Lock()
	mgr.jobs[job.ID].Status = StatusRunning
	now := time.Now().UTC()
	mgr.jobs[job.ID].StartedAt = &now
	stored := *mgr.jobs[job.ID]
	mgr.mu.Unlock()
	mgr.persist(&stored)

	reloaded, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Get(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusFailed || !strings.Contains(got.Error, "interrupted") {
		t.Fatalf("reloaded job = %s %q", got.Status, got.Error)
	}
}
