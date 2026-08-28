package jobs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// An Artifact is one JSON file written by ExportJSON.java. Arrays are parsed
// once into raw elements plus the couple of fields worth filtering on, then
// cached: paging through 80k functions should not re-parse the file per page.
type Artifact struct {
	raw    []json.RawMessage
	fields []entryFields
}

// entryFields is the searchable projection shared by every array artifact.
// Whichever of these a given artifact has is what ?q= matches against.
type entryFields struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Value    string `json:"value"`
	Address  string `json:"address"`
	Library  string `json:"library"`
	Type     string `json:"type"`
	Kind     string `json:"kind"`
}

func (e entryFields) matches(q string) bool {
	for _, s := range []string{e.Name, e.FullName, e.Value, e.Address, e.Library, e.Type, e.Kind} {
		if s != "" && strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	return false
}

type artifactCache struct {
	mu      sync.Mutex
	max     int
	entries map[string]*Artifact
	order   []string
}

func newArtifactCache(max int) *artifactCache {
	if max < 1 {
		max = 1
	}
	return &artifactCache{max: max, entries: map[string]*Artifact{}}
}

func (c *artifactCache) get(key string) (*Artifact, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a, ok := c.entries[key]
	return a, ok
}

func (c *artifactCache) put(key string, a *Artifact) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		c.order = append(c.order, key)
	}
	c.entries[key] = a
	for len(c.order) > c.max {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}

// dropJob evicts every cached artifact of a deleted job.
func (c *artifactCache) dropJob(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.order[:0]
	for _, k := range c.order {
		if strings.HasPrefix(k, id+"/") {
			delete(c.entries, k)
			continue
		}
		kept = append(kept, k)
	}
	c.order = kept
}

// ErrArtifactMissing means the job ran but never produced that file.
var ErrArtifactMissing = errors.New("artifact not present for this job")

// LoadArray reads and caches one array artifact.
func (m *Manager) LoadArray(jobID, name string) (*Artifact, error) {
	key := jobID + "/" + name
	if a, ok := m.arts.get(key); ok {
		return a, nil
	}
	b, err := os.ReadFile(filepath.Join(m.ArtifactsDir(jobID), name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrArtifactMissing
		}
		return nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("artifact %s is not a JSON array: %w", name, err)
	}
	fields := make([]entryFields, len(raw))
	for i, r := range raw {
		// Ignore per-element decode errors: an artifact element that lacks
		// these keys is simply not searchable, not a failure.
		_ = json.Unmarshal(r, &fields[i])
	}
	a := &Artifact{raw: raw, fields: fields}
	m.arts.put(key, a)
	return a, nil
}

// LoadObject reads one object artifact (currently only xrefs.json) without
// caching: it is looked up by key, not paged.
func (m *Manager) LoadObject(jobID, name string) (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(filepath.Join(m.ArtifactsDir(jobID), name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrArtifactMissing
		}
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, fmt.Errorf("artifact %s is not a JSON object: %w", name, err)
	}
	return obj, nil
}

// Page is one window over an array artifact, optionally filtered.
type Page struct {
	Total  int               `json:"total"`
	Count  int               `json:"count"`
	Limit  int               `json:"limit"`
	Offset int               `json:"offset"`
	Query  string            `json:"query,omitempty"`
	Items  []json.RawMessage `json:"items"`
}

func (a *Artifact) Page(q string, limit, offset int) Page {
	items := a.raw
	if q != "" {
		q = strings.ToLower(q)
		filtered := make([]json.RawMessage, 0, 64)
		for i := range a.raw {
			if a.fields[i].matches(q) {
				filtered = append(filtered, a.raw[i])
			}
		}
		items = filtered
	}
	total := len(items)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := items[offset:end]
	if out == nil {
		out = []json.RawMessage{}
	}
	return Page{Total: total, Count: len(out), Limit: limit, Offset: offset, Items: out}
}

// Find returns the first element whose address field equals addr.
func (a *Artifact) Find(addr string) (json.RawMessage, bool) {
	for i := range a.fields {
		if a.fields[i].Address == addr {
			return a.raw[i], true
		}
	}
	return nil, false
}

// NormAddr canonicalises an address the same way ExportJSON.java does: lower
// case, no 0x, no leading zeros, address space prefix preserved. So
// 0x00401000, 401000 and 00401000 all name the same thing.
func NormAddr(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	prefix := ""
	if i := strings.LastIndex(s, ":"); i >= 0 {
		prefix, s = s[:i+1], s[i+1:]
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		s = "0"
	}
	return prefix + s
}

// AddrOffset parses the numeric part of an address key.
func AddrOffset(s string) (uint64, error) {
	s = NormAddr(s)
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[i+1:]
	}
	return strconv.ParseUint(s, 16, 64)
}

// MemBlock mirrors one entry of memory/index.json.
type MemBlock struct {
	Name          string `json:"name"`
	Start         string `json:"start"`
	End           string `json:"end"`
	Size          int64  `json:"size"`
	Initialized   bool   `json:"initialized"`
	File          string `json:"file"`
	BytesExported int64  `json:"bytes_exported"`
}

func (m *Manager) memoryBlocks(jobID string) ([]MemBlock, error) {
	b, err := os.ReadFile(filepath.Join(m.ArtifactsDir(jobID), "memory", "index.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrArtifactMissing
		}
		return nil, err
	}
	var blocks []MemBlock
	if err := json.Unmarshal(b, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

// ReadMemory returns up to length bytes starting at addr, reading from the
// block dump the export script wrote. Reads stop at the end of a block rather
// than silently continuing into the next one, which may not be contiguous.
func (m *Manager) ReadMemory(jobID, addr string, length int) ([]byte, *MemBlock, error) {
	want, err := AddrOffset(addr)
	if err != nil {
		return nil, nil, fmt.Errorf("bad address %q", addr)
	}
	blocks, err := m.memoryBlocks(jobID)
	if err != nil {
		return nil, nil, err
	}
	for i := range blocks {
		b := blocks[i]
		start, err := AddrOffset(b.Start)
		if err != nil {
			continue
		}
		end, err := AddrOffset(b.End)
		if err != nil {
			continue
		}
		if want < start || want > end {
			continue
		}
		if !b.Initialized || b.File == "" {
			return nil, &b, fmt.Errorf("address %s is in uninitialised block %q", addr, b.Name)
		}
		off := int64(want - start)
		if off >= b.BytesExported {
			return nil, &b, fmt.Errorf("address %s is past the %d exported bytes of block %q", addr, b.BytesExported, b.Name)
		}
		avail := b.BytesExported - off
		if int64(length) > avail {
			length = int(avail)
		}
		f, err := os.Open(filepath.Join(m.ArtifactsDir(jobID), "memory", b.File))
		if err != nil {
			return nil, &b, err
		}
		defer f.Close()
		buf := make([]byte, length)
		n, err := f.ReadAt(buf, off)
		if n == 0 && err != nil {
			return nil, &b, err
		}
		return buf[:n], &b, nil
	}
	return nil, nil, fmt.Errorf("address %s is in no memory block", addr)
}

// Hexdump renders classic `hexdump -C` style output, base offset included so
// the left column is the program address, not a file offset.
func Hexdump(base uint64, data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		row := data[i:end]
		fmt.Fprintf(&sb, "%08x  ", base+uint64(i))
		for j := 0; j < 16; j++ {
			if j < len(row) {
				fmt.Fprintf(&sb, "%02x ", row[j])
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteByte(' ')
			}
		}
		sb.WriteString(" |")
		for _, c := range row {
			if c >= 0x20 && c < 0x7f {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}
