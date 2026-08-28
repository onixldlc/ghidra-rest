// Command ghidrarest is a REST front end to Ghidra's headless analyzer.
//
// Everything of substance lives under src/internal: config parsing, the job
// queue and Ghidra integration (internal/jobs) and the HTTP layer
// (internal/api). This file is startup, shutdown and two flags.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/onixldlc/ghidra-rest/src/internal/api"
	"github.com/onixldlc/ghidra-rest/src/internal/config"
	"github.com/onixldlc/ghidra-rest/src/internal/jobs"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Two flags, handled before anything else touches the environment:
	// -healthcheck is what the container HEALTHCHECK runs, which is why the
	// image needs no curl, and -version is for the released binaries.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-healthcheck", "--healthcheck":
			os.Exit(healthcheck())
		case "-version", "--version":
			fmt.Println(version)
			return
		}
	}

	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("ghidrarest: ")

	cfg := config.Load()

	mgr, err := jobs.NewManager(cfg)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	mgr.Start()
	go mgr.SweepLoop(15 * time.Minute)

	srv := api.New(cfg, mgr, version)

	httpSrv := &http.Server{
		Addr:    cfg.Addr,
		Handler: srv.Handler(),
		// No WriteTimeout: an export zip of a large program, or a slow client
		// pulling a big decompilation, would trip it.
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("version %s, ghidra %s", version, mgr.GhidraVersion())
		log.Printf("data dir %s (ghidra home %s)", cfg.DataDir, cfg.GhidraHome)
		log.Printf("workers=%d queue=%d analysis timeout=%s", cfg.MaxConcurrent, cfg.QueueSize, cfg.AnalysisTimeout)
		if cfg.APIToken == "" {
			log.Printf("no GHIDRAREST_API_TOKEN set: every endpoint is open")
		}
		log.Printf("listening on %s", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	httpSrv.Shutdown(ctx)

	// Running analyses are killed rather than waited for: a Ghidra import can
	// take minutes, and their jobs are marked interrupted on restart anyway.
	mgr.Stop()
}

// healthcheck probes the local /healthz and exits 0 or 1. Keeping it in the
// same binary is what lets the runtime image ship without curl -- and with it,
// without apt lists, which were 53 MB of the image.
func healthcheck() int {
	addr := config.Env("GHIDRAREST_ADDR", ":8080")
	port := addr[strings.LastIndex(addr, ":")+1:]
	if port == "" {
		port = "8080"
	}
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %v\n", err)
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}
