package winaccessibility

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// DefaultSystem32Root is the canonical x64 System32 directory.
const DefaultSystem32Root = `C:\Windows\System32`

// fileCollector hashes every entry of CuratedBinaries() under a
// configurable System32 root. Test seam swaps readFile / statFile.
type fileCollector struct {
	readFile func(string) ([]byte, error)
	statFile func(string) (os.FileInfo, error)
	root     string
}

// NewCollector returns a Collector wired to the canonical System32
// root. Missing root → every curated binary flagged is_missing=1.
func NewCollector() Collector {
	return &fileCollector{
		root:     DefaultSystem32Root,
		readFile: os.ReadFile,
		statFile: os.Stat,
	}
}

func (c *fileCollector) Name() string { return "winaccessibility" }

func (c *fileCollector) Collect(_ context.Context) ([]Binary, error) {
	out := make([]Binary, 0, len(CuratedBinaries()))
	for _, name := range CuratedBinaries() {
		path := filepath.Join(c.root, name)
		bin := Binary{
			FilePath: path,
			FileName: name,
		}
		body, err := c.readFile(path)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				bin.IsMissing = true
				AnnotateSecurity(&bin)
				out = append(out, bin)
				continue
			}
			// Other errors (permission denied, …) — still emit a
			// row so the pipeline knows we tried.
			bin.IsMissing = true
			AnnotateSecurity(&bin)
			out = append(out, bin)
			continue
		}
		bin.FileSizeBytes = int64(len(body))
		bin.FileHash = HashContents(body)
		if fi, err := c.statFile(path); err == nil {
			bin.FileMtime = fi.ModTime().Unix()
		}
		AnnotateSecurity(&bin)
		out = append(out, bin)
	}
	SortBinaries(out)
	return out, nil
}
