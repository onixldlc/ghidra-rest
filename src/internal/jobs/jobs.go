// Package jobs owns the analysis queue, the worker pool, the on-disk job
// layout and the readers for the artifacts a run produces. It knows nothing
// about HTTP.
package jobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/onixldlc/ghidra-rest/src/internal/config"
)

type JobStatus string

const (
	StatusQueued   JobStatus = "queued"
	StatusRunning  JobStatus = "running"
	StatusDone     JobStatus = "done"
	StatusFailed   JobStatus = "failed"
	StatusCanceled JobStatus = "canceled"
)

func (s JobStatus) terminal() bool {
	return s == StatusDone || s == StatusFailed || s == StatusCanceled
}

var (
	ErrNotFound    = errors.New("job not found")
	ErrTooLarge    = errors.New("upload exceeds the configured maximum size")
	ErrQueueFull   = errors.New("analysis queue is full")
	ErrNotTerminal = errors.New("job is still queued or running")
)

// JobOptions are the per-submission knobs. Zero values mean "use the server
// default", which is resolved at submit time so the stored job records what
// actually ran.
type JobOptions struct {
	Decompile         bool   `json:"decompile"`
	DecompileMaxFuncs int    `json:"decompile_max_funcs"`
	DecompileTimeout  int    `json:"decompile_timeout_sec"`
	AnalysisTimeout   int    `json:"analysis_timeout_sec"`
	Processor         string `json:"processor,omitempty"`
	CompilerSpec      string `json:"compiler_spec,omitempty"`
	Loader            string `json:"loader,omitempty"`
}

type Job struct {
	ID       string     `json:"id"`
	Filename string     `json:"filename"`
	Size     int64      `json:"size"`
	SHA256   string     `json:"sha256"`
	Status   JobStatus  `json:"status"`
	Error    string     `json:"error,omitempty"`
	Options  JobOptions `json:"options"`

	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	DurationMS int64      `json:"duration_ms,omitempty"`

	GhidraVersion string           `json:"ghidra_version,omitempty"`
	Language      string           `json:"language,omitempty"`
	Format        string           `json:"executable_format,omitempty"`
	Counts        map[string]int64 `json:"counts,omitempty"`
}

// Manager owns the job queue, the worker pool and the on-disk layout:
//
//	<data>/jobs/<id>/meta.json
//	<data>/jobs/<id>/input/<filename>
//	<data>/jobs/<id>/headless.log
//	<data>/jobs/<id>/artifacts/...
//	<data>/jobs/<id>/project/        (removed unless KEEP_PROJECT)
type Manager struct {
	cfg *config.Config

	mu       sync.RWMutex
	jobs     map[string]*Job
	bySHA    map[string]string
	cancels  map[string]context.CancelFunc
	canceled map[string]bool

	queue chan string
	wg    sync.WaitGroup
	quit  chan struct{}
	once  sync.Once

	ghidraVersion string
	arts          *artifactCache
}

func NewManager(cfg *config.Config) (*Manager, error) {
	m := &Manager{
		cfg:      cfg,
		jobs:     map[string]*Job{},
		bySHA:    map[string]string{},
		cancels:  map[string]context.CancelFunc{},
		canceled: map[string]bool{},
		queue:    make(chan string, cfg.QueueSize),
		quit:     make(chan struct{}),
		arts:     newArtifactCache(16),
	}
	for _, d := range []string{m.jobsRoot(), m.tmpDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	m.ghidraVersion = detectGhidraVersion(cfg.GhidraHome)
	if err := m.load(); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) jobsRoot() string        { return filepath.Join(m.cfg.DataDir, "jobs") }
func (m *Manager) tmpDir() string          { return filepath.Join(m.cfg.DataDir, "tmp") }
func (m *Manager) jobDir(id string) string { return filepath.Join(m.jobsRoot(), id) }

// MetaPath is the job record on disk.
func (m *Manager) MetaPath(id string) string { return filepath.Join(m.jobDir(id), "meta.json") }

// LogPath is the analyzeHeadless transcript of a job.
func (m *Manager) LogPath(id string) string { return filepath.Join(m.jobDir(id), "headless.log") }

// ArtifactsDir is the directory ExportJSON.java writes into.
func (m *Manager) ArtifactsDir(id string) string {
	return filepath.Join(m.jobDir(id), "artifacts")
}

func (m *Manager) projectDir(id string) string { return filepath.Join(m.jobDir(id), "project") }

func (m *Manager) GhidraVersion() string { return m.ghidraVersion }

// InputPath returns the stored copy of the submitted file.
func (m *Manager) InputPath(j *Job) string {
	return filepath.Join(m.jobDir(j.ID), "input", j.Filename)
}

// load rebuilds the in-memory index from disk. Jobs that were mid-flight when
// the process died are marked failed: their artifacts are half written, and
// silently re-queueing them would surprise anyone who submitted a 40 minute
// analysis.
func (m *Manager) load() error {
	entries, err := os.ReadDir(m.jobsRoot())
	if err != nil {
		return err
	}
	interrupted := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var j Job
		b, err := os.ReadFile(m.MetaPath(e.Name()))
		if err != nil {
			log.Printf("store: skipping %s: %v", e.Name(), err)
			continue
		}
		if err := json.Unmarshal(b, &j); err != nil {
			log.Printf("store: skipping %s: %v", e.Name(), err)
			continue
		}
		if !j.Status.terminal() {
			j.Status = StatusFailed
			j.Error = "interrupted by a server restart"
			now := time.Now().UTC()
			j.FinishedAt = &now
			interrupted++
			m.persist(&j)
		}
		m.jobs[j.ID] = &j
		if j.SHA256 != "" {
			m.bySHA[j.SHA256] = j.ID
		}
	}
	log.Printf("store: loaded %d jobs (%d marked interrupted)", len(m.jobs), interrupted)
	return nil
}

func (m *Manager) persist(j *Job) {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		log.Printf("store: marshal %s: %v", j.ID, err)
		return
	}
	tmp := m.MetaPath(j.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		log.Printf("store: write %s: %v", j.ID, err)
		return
	}
	if err := os.Rename(tmp, m.MetaPath(j.ID)); err != nil {
		log.Printf("store: rename %s: %v", j.ID, err)
	}
}

func (m *Manager) Start() {
	for i := 0; i < m.cfg.MaxConcurrent; i++ {
		m.wg.Add(1)
		go m.worker(i)
	}
}

func (m *Manager) Stop() {
	m.once.Do(func() {
		close(m.quit)
		close(m.queue)
		m.mu.Lock()
		for _, cancel := range m.cancels {
			cancel()
		}
		m.mu.Unlock()
	})
	m.wg.Wait()
}

func (m *Manager) worker(n int) {
	defer m.wg.Done()
	for id := range m.queue {
		select {
		case <-m.quit:
			return
		default:
		}
		m.runJob(n, id)
	}
}

func newID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not survivable and not worth a fallback that
		// silently produces guessable ids.
		panic(fmt.Sprintf("rand: %v", err))
	}
	return hex.EncodeToString(b)
}

// sanitizeName keeps the submitted filename recognisable without letting it
// escape the job directory.
func sanitizeName(name string) string {
	name = filepath.Base(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\x00", "")
	if name == "" || name == "." || name == ".." {
		return "binary"
	}
	if len(name) > 128 {
		name = name[:128]
	}
	return name
}

func (m *Manager) resolveOptions(o JobOptions) JobOptions {
	if o.DecompileMaxFuncs <= 0 {
		o.DecompileMaxFuncs = m.cfg.DecompileMaxFuncs
	}
	if o.DecompileTimeout <= 0 {
		o.DecompileTimeout = m.cfg.DecompileTimeout
	}
	if o.AnalysisTimeout <= 0 {
		o.AnalysisTimeout = int(m.cfg.AnalysisTimeout / time.Second)
	}
	return o
}

// Submit stores the uploaded bytes and queues an analysis. Identical content
// is deduplicated by sha256 unless force is set, so re-uploading the same
// binary returns the finished job instead of burning another Ghidra run.
func (m *Manager) Submit(name string, r io.Reader, opts JobOptions, force bool) (*Job, bool, error) {
	if err := os.MkdirAll(m.tmpDir(), 0o755); err != nil {
		return nil, false, err
	}
	tmp, err := os.CreateTemp(m.tmpDir(), "upload-*")
	if err != nil {
		return nil, false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	limit := m.cfg.MaxUploadBytes
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(r, limit+1))
	tmp.Close()
	if err != nil {
		return nil, false, err
	}
	if n > limit {
		return nil, false, ErrTooLarge
	}
	if n == 0 {
		return nil, false, errors.New("empty upload")
	}
	sum := hex.EncodeToString(h.Sum(nil))

	if !force {
		m.mu.RLock()
		id, ok := m.bySHA[sum]
		var existing *Job
		if ok {
			existing = m.jobs[id]
		}
		m.mu.RUnlock()
		if existing != nil && existing.Status != StatusFailed && existing.Status != StatusCanceled {
			cp := *existing
			return &cp, true, nil
		}
	}

	job := &Job{
		ID:            newID(),
		Filename:      sanitizeName(name),
		Size:          n,
		SHA256:        sum,
		Status:        StatusQueued,
		Options:       m.resolveOptions(opts),
		CreatedAt:     time.Now().UTC(),
		GhidraVersion: m.ghidraVersion,
	}

	dir := m.jobDir(job.ID)
	if err := os.MkdirAll(filepath.Join(dir, "input"), 0o755); err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(m.ArtifactsDir(job.ID), 0o755); err != nil {
		return nil, false, err
	}
	if err := os.Rename(tmpName, m.InputPath(job)); err != nil {
		return nil, false, err
	}
	m.persist(job)

	m.mu.Lock()
	m.jobs[job.ID] = job
	m.bySHA[sum] = job.ID
	m.mu.Unlock()

	select {
	case m.queue <- job.ID:
	default:
		m.mu.Lock()
		job.Status = StatusFailed
		job.Error = ErrQueueFull.Error()
		now := time.Now().UTC()
		job.FinishedAt = &now
		m.mu.Unlock()
		m.persist(job)
		return nil, false, ErrQueueFull
	}

	cp := *job
	return &cp, false, nil
}

func (m *Manager) runJob(worker int, id string) {
	m.mu.Lock()
	job := m.jobs[id]
	if job == nil || job.Status == StatusCanceled {
		m.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	job.Status = StatusRunning
	job.StartedAt = &now
	timeout := time.Duration(job.Options.AnalysisTimeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	m.cancels[id] = cancel
	started := *job
	m.mu.Unlock()
	m.persist(&started)

	log.Printf("job %s: worker %d analysing %s (%d bytes)", id, worker, job.Filename, job.Size)
	start := time.Now()
	err := m.runHeadless(ctx, job)
	cancel()

	m.mu.Lock()
	delete(m.cancels, id)
	userCanceled := m.canceled[id]
	delete(m.canceled, id)
	fin := time.Now().UTC()
	job.FinishedAt = &fin
	job.DurationMS = time.Since(start).Milliseconds()
	switch {
	case userCanceled:
		job.Status = StatusCanceled
		job.Error = "canceled"
	case err != nil:
		job.Status = StatusFailed
		job.Error = err.Error()
		if ctx.Err() == context.DeadlineExceeded {
			job.Error = fmt.Sprintf("analysis timed out after %s", timeout)
		}
	default:
		job.Status = StatusDone
		job.Error = ""
	}
	status, dur := job.Status, job.DurationMS
	m.mu.Unlock()

	if status == StatusDone {
		m.applySummary(job)
	}
	m.mu.RLock()
	finished := *job
	m.mu.RUnlock()
	m.persist(&finished)
	log.Printf("job %s: %s in %dms", id, status, dur)
}

// applySummary lifts the handful of fields worth having on the job record
// itself, so `GET /v1/jobs` is useful without a second request per job.
func (m *Manager) applySummary(job *Job) {
	b, err := os.ReadFile(filepath.Join(m.ArtifactsDir(job.ID), "summary.json"))
	if err != nil {
		return
	}
	var s struct {
		Language string           `json:"language"`
		Format   string           `json:"executable_format"`
		Ghidra   string           `json:"ghidra_version"`
		Counts   map[string]int64 `json:"counts"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	job.Language = s.Language
	job.Format = s.Format
	job.Counts = s.Counts
	if s.Ghidra != "" {
		job.GhidraVersion = s.Ghidra
	}
}

func (m *Manager) Get(id string) (*Job, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	j, ok := m.jobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *j
	return &cp, nil
}

// List returns jobs newest first, optionally filtered by status.
func (m *Manager) List(status string, limit, offset int) ([]*Job, int) {
	m.mu.RLock()
	out := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		if status != "" && string(j.Status) != status {
			continue
		}
		cp := *j
		out = append(out, &cp)
	}
	m.mu.RUnlock()

	sort.Slice(out, func(i, k int) bool { return out[i].CreatedAt.After(out[k].CreatedAt) })
	total := len(out)
	if offset >= total {
		return []*Job{}, total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return out[offset:end], total
}

func (m *Manager) Cancel(id string) (*Job, error) {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return nil, ErrNotFound
	}
	switch j.Status {
	case StatusQueued:
		j.Status = StatusCanceled
		j.Error = "canceled before it started"
		now := time.Now().UTC()
		j.FinishedAt = &now
	case StatusRunning:
		m.canceled[id] = true
		if cancel := m.cancels[id]; cancel != nil {
			cancel()
		}
	default:
		m.mu.Unlock()
		return nil, fmt.Errorf("job is already %s", j.Status)
	}
	cp := *j
	m.mu.Unlock()
	m.persist(&cp)
	return &cp, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	j, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if !j.Status.terminal() {
		m.mu.Unlock()
		return ErrNotTerminal
	}
	delete(m.jobs, id)
	if m.bySHA[j.SHA256] == id {
		delete(m.bySHA, j.SHA256)
	}
	m.mu.Unlock()

	m.arts.dropJob(id)
	return os.RemoveAll(m.jobDir(id))
}

// SweepLoop deletes terminal jobs older than the retention window. Retention
// of 0 keeps everything, which is the default: this is a lab tool, and losing
// a 40 minute analysis to a background timer is worse than disk use.
func (m *Manager) SweepLoop(every time.Duration) {
	if m.cfg.Retention <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-m.quit:
			return
		case <-t.C:
			m.sweep()
		}
	}
}

func (m *Manager) sweep() {
	cutoff := time.Now().UTC().Add(-m.cfg.Retention)
	m.mu.RLock()
	var stale []string
	for id, j := range m.jobs {
		if j.Status.terminal() && j.FinishedAt != nil && j.FinishedAt.Before(cutoff) {
			stale = append(stale, id)
		}
	}
	m.mu.RUnlock()
	for _, id := range stale {
		if err := m.Delete(id); err != nil {
			log.Printf("sweep: %s: %v", id, err)
			continue
		}
		log.Printf("sweep: removed %s (older than %s)", id, m.cfg.Retention)
	}
}
