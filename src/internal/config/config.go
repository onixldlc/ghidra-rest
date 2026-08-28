// Package config resolves every runtime knob from the environment, once, at
// startup. Nothing else in the tree reads os.Getenv.
package config

import (
	"log"
	"os"
	"runtime"
	"strconv"
	"time"
)

// Config is resolved once at startup from the environment. Every knob is
// documented in .env.example.
type Config struct {
	Addr string

	DataDir    string
	GhidraHome string
	ScriptDir  string

	MaxUploadBytes int64
	MaxConcurrent  int
	QueueSize      int

	// AnalysisTimeout bounds one headless run end to end. It is also handed
	// to analyzeHeadless as -analysisTimeoutPerFile, so Ghidra stops analysing
	// and still runs the export script instead of being killed mid-write.
	AnalysisTimeout time.Duration

	DecompileDefault  bool
	DecompileTimeout  int
	DecompileMaxFuncs int
	MaxExportBytes    int64

	JavaMaxMem  string
	MaxCPU      int
	KeepProject bool

	Retention time.Duration

	APIToken   string
	CORSOrigin string
	Verbose    bool

	DefaultPageSize int
	MaxPageSize     int
	MaxHexdumpBytes int
}

// Env reads one string setting. Exported because the -healthcheck path in
// main needs the listen address before a Config exists.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		// Warn and carry on rather than exiting. Under a restart policy a
		// fatal config error becomes a crash-loop, which is a worse failure
		// than running with the default.
		log.Printf("config: %s=%q is not a number (%v); using default %d", key, v, err, def)
		return def
	}
	return n
}

func envDur(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("config: %s=%q is not a duration (%v); using default %s", key, v, err, def)
		return def
	}
	return d
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	switch v {
	case "":
		return def
	case "1", "true", "TRUE", "yes", "on":
		return true
	case "0", "false", "FALSE", "no", "off":
		return false
	}
	log.Printf("config: %s=%q is not a boolean; using default %v", key, v, def)
	return def
}

// Load builds a Config from the environment, falling back to defaults.
func Load() *Config {
	workers := int(envInt("GHIDRAREST_MAX_CONCURRENT", int64(defaultWorkers())))
	if workers < 1 {
		workers = 1
	}

	c := &Config{
		Addr:       Env("GHIDRAREST_ADDR", ":8080"),
		DataDir:    Env("GHIDRAREST_DATA_DIR", "./data"),
		GhidraHome: Env("GHIDRAREST_GHIDRA_HOME", "/opt/ghidra"),
		ScriptDir:  Env("GHIDRAREST_SCRIPT_DIR", "/opt/ghidra-rest/scripts"),

		MaxUploadBytes: envInt("GHIDRAREST_MAX_UPLOAD_BYTES", 256<<20),
		MaxConcurrent:  workers,
		QueueSize:      int(envInt("GHIDRAREST_QUEUE_SIZE", 64)),

		AnalysisTimeout: envDur("GHIDRAREST_ANALYSIS_TIMEOUT", 30*time.Minute),

		DecompileDefault:  envBool("GHIDRAREST_DECOMPILE", true),
		DecompileTimeout:  int(envInt("GHIDRAREST_DECOMPILE_TIMEOUT", 60)),
		DecompileMaxFuncs: int(envInt("GHIDRAREST_DECOMPILE_MAX_FUNCS", 20000)),
		MaxExportBytes:    envInt("GHIDRAREST_MAX_EXPORT_BYTES", 256<<20),

		JavaMaxMem:  Env("GHIDRAREST_JAVA_MAX_MEM", "2G"),
		MaxCPU:      int(envInt("GHIDRAREST_MAX_CPU", 0)),
		KeepProject: envBool("GHIDRAREST_KEEP_PROJECT", false),

		Retention: envDur("GHIDRAREST_RETENTION", 0),

		APIToken:   os.Getenv("GHIDRAREST_API_TOKEN"),
		CORSOrigin: os.Getenv("GHIDRAREST_CORS_ORIGIN"),
		Verbose:    envBool("GHIDRAREST_VERBOSE", false),

		DefaultPageSize: int(envInt("GHIDRAREST_PAGE_SIZE", 100)),
		MaxPageSize:     int(envInt("GHIDRAREST_MAX_PAGE_SIZE", 5000)),
		MaxHexdumpBytes: int(envInt("GHIDRAREST_MAX_HEXDUMP_BYTES", 65536)),
	}

	if c.QueueSize < 1 {
		c.QueueSize = 1
	}
	if c.DefaultPageSize < 1 {
		c.DefaultPageSize = 100
	}
	if c.MaxPageSize < c.DefaultPageSize {
		c.MaxPageSize = c.DefaultPageSize
	}
	return c
}

// defaultWorkers keeps concurrent Ghidra runs low on purpose: each one is a
// JVM that will happily take the whole heap it was given.
func defaultWorkers() int {
	n := runtime.NumCPU() / 2
	if n < 1 {
		return 1
	}
	if n > 4 {
		return 4
	}
	return n
}
