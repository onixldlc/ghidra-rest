package api

import (
	"archive/zip"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// handleJobExport streams every artifact of a job as one zip: the artifact
// tree, the job record and the headless log. Written straight to the socket
// rather than staged on disk, because the artifact set of a large program is
// itself large.
func (s *Server) handleJobExport(w http.ResponseWriter, r *http.Request) {
	job, ok := s.resultJob(w, r)
	if !ok {
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+job.ID+`-artifacts.zip"`)

	zw := zip.NewWriter(w)
	defer zw.Close()

	base := s.mgr.ArtifactsDir(job.ID)
	err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		return addFile(zw, "artifacts/"+filepath.ToSlash(rel), path)
	})
	if err != nil {
		// The zip stream has already started, so there is no status code left
		// to send. Log it and let the client notice the truncated archive.
		log.Printf("export %s: %v", job.ID, err)
		return
	}

	for _, extra := range []struct{ name, path string }{
		{"meta.json", s.mgr.MetaPath(job.ID)},
		{"headless.log", s.mgr.LogPath(job.ID)},
	} {
		if err := addFile(zw, extra.name, extra.path); err != nil && !os.IsNotExist(err) {
			log.Printf("export %s: %s: %v", job.ID, extra.name, err)
		}
	}
}

func addFile(zw *zip.Writer, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	hdr, err := zip.FileInfoHeader(st)
	if err != nil {
		return err
	}
	hdr.Name = strings.TrimPrefix(name, "/")
	// Deflate: decompiled C and JSON compress by an order of magnitude, and
	// the raw memory dumps compress well too.
	hdr.Method = zip.Deflate
	out, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, f)
	return err
}
