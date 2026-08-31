package jobs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// detectGhidraVersion reads the version out of the install rather than taking
// it from an env var, so /v1/version cannot lie about what analysed a binary.
func detectGhidraVersion(home string) string {
	f, err := os.Open(filepath.Join(home, "Ghidra", "application.properties"))
	if err != nil {
		return "unknown"
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if v, ok := strings.CutPrefix(line, "application.version="); ok {
			return strings.TrimSpace(v)
		}
	}
	return "unknown"
}

// runHeadless is the whole Ghidra integration: one analyzeHeadless invocation
// per job, with ExportJSON.java as the post-script. Nothing is kept warm and
// nothing is shared between jobs, so a program that crashes the analyzer takes
// down only its own run.
func (m *Manager) runHeadless(ctx context.Context, job *Job) error {
	bin := filepath.Join(m.cfg.GhidraHome, "support", "analyzeHeadless")
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("analyzeHeadless not found under %s: %w", m.cfg.GhidraHome, err)
	}
	script := filepath.Join(m.cfg.ScriptDir, "ExportJSON.java")
	if _, err := os.Stat(script); err != nil {
		return fmt.Errorf("export script not found: %w", err)
	}

	artDir := m.ArtifactsDir(job.ID)
	projDir := m.projectDir(job.ID)
	for _, d := range []string{artDir, projDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}

	// Ghidra's own per-file analysis timer is set below the job deadline, so
	// analysis gives up in time for the post-script to still write artifacts.
	// Being killed by the context instead produces a job with no results.
	perFile := job.Options.AnalysisTimeout * 3 / 4
	if perFile < 30 {
		perFile = 30
	}

	args := []string{
		projDir, "ghidrarest",
		"-import", m.InputPath(job),
		"-scriptPath", m.cfg.ScriptDir,
		"-postScript", "ExportJSON.java",
		artDir,
		strconv.FormatBool(job.Options.Decompile),
		strconv.Itoa(job.Options.DecompileMaxFuncs),
		strconv.Itoa(job.Options.DecompileTimeout),
		strconv.FormatInt(m.cfg.MaxExportBytes, 10),
		"-analysisTimeoutPerFile", strconv.Itoa(perFile),
	}
	if !m.cfg.KeepProject {
		args = append(args, "-deleteProject")
	}
	if m.cfg.MaxCPU > 0 {
		args = append(args, "-max-cpu", strconv.Itoa(m.cfg.MaxCPU))
	}
	if job.Options.Processor != "" {
		args = append(args, "-processor", job.Options.Processor)
	}
	if job.Options.CompilerSpec != "" {
		args = append(args, "-cspec", job.Options.CompilerSpec)
	}
	if job.Options.Loader != "" {
		args = append(args, "-loader", job.Options.Loader)
	}

	logf, err := os.Create(m.LogPath(job.ID))
	if err != nil {
		return err
	}
	defer logf.Close()
	fmt.Fprintf(logf, "# analyzeHeadless %s\n\n", strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = m.jobDir(job.ID)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.Env = append(os.Environ(),
		"MAXMEM="+m.cfg.JavaMaxMem,
		// Ghidra's launcher wants a writable settings dir. If HOME is not
		// writable every run recompiles the script, or fails outright.
		"GHIDRA_HOME="+m.cfg.GhidraHome,
	)
	// analyzeHeadless is a shell script that execs a JVM: killing the shell
	// alone orphans the JVM, which then keeps writing into a job the server
	// thinks is dead. Kill the whole process group instead.
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = 10 * time.Second

	runErr := cmd.Run()

	if !m.cfg.KeepProject {
		os.RemoveAll(projDir)
	}

	summary := filepath.Join(artDir, "summary.json")
	st, statErr := os.Stat(summary)
	if statErr != nil || st.Size() == 0 {
		if runErr != nil {
			return fmt.Errorf("analyzeHeadless failed: %v\n%s", runErr, m.LogTail(job.ID, 2000))
		}
		return fmt.Errorf("analyzeHeadless produced no summary.json\n%s", m.LogTail(job.ID, 2000))
	}
	// summary.json is written last by the export script, so its presence means
	// the artifact set is complete even if the launcher exited non-zero
	// afterwards (it sometimes does, on cleanup).
	if runErr != nil {
		fmt.Fprintf(logf, "\n# note: exporter completed but analyzeHeadless exited: %v\n", runErr)
	}
	return nil
}

// runHeadlessTool runs analyzeHeadless for something other than a fresh
// analysis -- today that is only ApplySignature. The transcript is appended to
// the job's own headless.log rather than a second file: a retype is part of
// what happened to that job, and GET /v1/jobs/{id}/log should show it.
// The combined output is returned as well, because an error message that says
// only "exit 1" is useless to whoever called the endpoint.
func (m *Manager) runHeadlessTool(ctx context.Context, job *Job, bin string, args []string, what string) (string, error) {
	logf, err := os.OpenFile(m.LogPath(job.ID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	defer logf.Close()
	fmt.Fprintf(logf, "\n# %s %s: analyzeHeadless %s\n\n", time.Now().UTC().Format(time.RFC3339), what,
		strings.Join(args, " "))

	var buf strings.Builder
	sink := io.MultiWriter(logf, &buf)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = m.jobDir(job.ID)
	cmd.Stdout = sink
	cmd.Stderr = sink
	cmd.Env = append(os.Environ(),
		"MAXMEM="+m.cfg.JavaMaxMem,
		"GHIDRA_HOME="+m.cfg.GhidraHome,
	)
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	cmd.WaitDelay = 10 * time.Second

	err = cmd.Run()
	return buf.String(), err
}

// LogTail returns the last n bytes of a job's headless log, for error strings
// and for GET /v1/jobs/{id}/log?tail=N.
func (m *Manager) LogTail(id string, n int64) string {
	f, err := os.Open(m.LogPath(id))
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	off := st.Size() - n
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil {
		return ""
	}
	return strings.TrimSpace(string(buf))
}
