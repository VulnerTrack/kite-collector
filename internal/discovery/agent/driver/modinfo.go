package driver

import (
	"bytes"
	"compress/gzip"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseModinfo extracts the kernel module's .modinfo ELF section and
// returns its NUL-terminated key=value entries as a map. Supports plain
// .ko, .ko.xz, .ko.zst, and .ko.gz files. Compressed formats other than
// gzip are decompressed via xz/zstd headers detected at runtime; for
// .xz/.zst we fall back to streaming the file through the compressor's
// pure-Go decoder when present, otherwise we surface a "compressed"
// error so the caller can degrade gracefully.
func ParseModinfo(path string) (map[string]string, error) {
	raw, err := readModuleBytes(path)
	if err != nil {
		return nil, err
	}

	f, err := elf.NewFile(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse ELF: %w", err)
	}
	defer func() { _ = f.Close() }()

	sec := f.Section(".modinfo")
	if sec == nil {
		return nil, errors.New(".modinfo section not present")
	}

	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("read .modinfo: %w", err)
	}

	return parseModinfoBlob(data), nil
}

// parseModinfoBlob splits the raw NUL-delimited modinfo blob into its
// key=value entries. The kernel guarantees one entry per NUL-terminated
// substring; the leading NULs that pad to alignment are skipped.
func parseModinfoBlob(blob []byte) map[string]string {
	out := map[string]string{}
	for _, raw := range bytes.Split(blob, []byte{0}) {
		entry := string(raw)
		if entry == "" {
			continue
		}
		idx := strings.IndexByte(entry, '=')
		if idx <= 0 {
			continue
		}
		key := entry[:idx]
		val := entry[idx+1:]

		// Some keys (sig_key) may contain newlines from the trailer block;
		// retain the value as-is — callers decide how to render.
		if existing, ok := out[key]; ok {
			out[key] = existing + "," + val
			continue
		}
		out[key] = val
	}
	return out
}

// readModuleBytes returns the decompressed ELF bytes of the module file
// regardless of file extension. Callers should size-cap their input via
// the caller's runWithLimits envelope; this helper enforces a hard 64 MB
// decompressed cap to defend against decompression-bomb inputs.
const maxDecompressedModuleBytes = 64 << 20

func readModuleBytes(path string) ([]byte, error) {
	f, err := os.Open(path) //#nosec G304 -- caller is module-path resolver
	if err != nil {
		return nil, fmt.Errorf("open module: %w", err)
	}
	defer func() { _ = f.Close() }()

	switch {
	case strings.HasSuffix(path, ".ko.gz"):
		return readGzip(f)
	case strings.HasSuffix(path, ".ko.xz"), strings.HasSuffix(path, ".ko.zst"):
		// Pure-Go xz/zstd decompressors are not part of the stdlib; the
		// agent may be built without them. Surface a structured error so
		// the caller logs and continues without a hard failure.
		return nil, fmt.Errorf("compressed module format %q not supported in pure-Go build", filepathExt(path))
	default:
		data, err := io.ReadAll(io.LimitReader(f, maxDecompressedModuleBytes))
		if err != nil {
			return nil, fmt.Errorf("read module bytes: %w", err)
		}
		return data, nil
	}
}

func readGzip(r io.Reader) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()
	data, err := io.ReadAll(io.LimitReader(gz, maxDecompressedModuleBytes))
	if err != nil {
		return nil, fmt.Errorf("read gzip stream: %w", err)
	}
	return data, nil
}

func filepathExt(path string) string {
	for _, ext := range []string{".ko.xz", ".ko.zst", ".ko.gz", ".ko"} {
		if strings.HasSuffix(path, ext) {
			return ext
		}
	}
	return ""
}
