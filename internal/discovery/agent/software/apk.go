package software

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

// APK collects installed packages using apk on Alpine Linux.
type APK struct{}

// NewAPK returns a new APK collector.
func NewAPK() *APK { return &APK{} }

// Name returns the stable identifier for this collector.
func (a *APK) Name() string { return "apk" }

// Available reports whether apk is on the PATH.
func (a *APK) Available() bool {
	_, err := exec.LookPath("apk")
	return err == nil
}

// Collect prefers the structured APK 3 query. Older installations use the list
// command with optional metadata from the APK 2 installed database.
func (a *APK) Collect(ctx context.Context) (*Result, error) {
	out, err := runWithLimits(ctx, "apk", "query", "--installed", "--all-matches", "--format", "json",
		"--fields", "name,version,arch,origin,url,license,description", "*")
	if err == nil {
		if result, parseErr := parseAPKJSON(out); parseErr == nil {
			return result, nil
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("apk inventory: %w", ctx.Err())
	}
	out, err = runWithLimits(ctx, "apk", "list", "--installed")
	if err != nil {
		return nil, fmt.Errorf("apk list --installed: %w", err)
	}
	result := ParseAPKOutput(string(out))
	if metadata, readErr := readAPKDatabase(); readErr == nil {
		// The database can change between commands. Enrich only the same
		// installed name/version/architecture; never copy another release.
		byPackage := map[[3]string]model.InstalledSoftware{}
		for _, item := range metadata.Items {
			byPackage[[3]string{item.SoftwareName, item.Version, item.Architecture}] = item
		}
		for i, item := range result.Items {
			if facts, ok := byPackage[[3]string{item.SoftwareName, item.Version, item.Architecture}]; ok {
				facts.ID = item.ID
				result.Items[i] = facts
			}
		}
	}
	return result, nil
}

// ParseAPKOutput parses the raw output of apk list --installed.
// Each line is expected as "name-version arch {origin} (license)".
func ParseAPKOutput(raw string) *Result {
	result := &Result{}
	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "WARNING:") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			result.Errs = append(result.Errs, CollectError{
				Collector: "apk",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("expected 'name-version arch {origin} (license)' format"),
			})
			continue
		}

		name, version := splitNameVersion(parts[0])
		if name == "" || version == "" {
			result.Errs = append(result.Errs, CollectError{
				Collector: "apk",
				Line:      lineNum,
				RawLine:   line,
				Err:       errors.New("cannot split package name and version"),
			})
			continue
		}

		arch := parts[1]

		origin := ""
		for _, p := range parts[2:] {
			if strings.HasPrefix(p, "{") && strings.HasSuffix(p, "}") {
				origin = p[1 : len(p)-1]
				break
			}
		}

		result.Items = append(result.Items, apkSoftware(name, version, arch, origin))
	}

	return result
}

// splitNameVersion splits a "name-version" string at the last hyphen
// followed by a digit. Returns (s, "") if no such boundary exists.
// APK versions can end in -rN; names can themselves contain numeric suffixes.
func splitNameVersion(s string) (string, string) {
	for i := len(s) - 2; i >= 0; i-- {
		if s[i] == '-' && s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

func apkSoftware(name, version, arch, origin string) model.InstalledSoftware {
	item := model.InstalledSoftware{
		ID: uuid.Must(uuid.NewV7()), SoftwareName: name, Version: version,
		PackageManager: "apk", Architecture: arch,
		// origin identifies the source package, never the upstream vendor.
		SourcePackage: origin, CPE23: BuildCPE23WithArch("", name, version, arch),
	}
	if origin != "" {
		// abuild emits origin=$pkgname and pkgver=$pkgver-r$pkgrel for
		// each subpackage. Keep that build version; strip -rN only in resolution.
		item.SourceVersion = version
	}
	return item
}

func parseAPKJSON(raw []byte) (*Result, error) {
	var packages []struct {
		Name, Version, Arch, Origin, URL, License, Description string
	}
	if err := json.Unmarshal(raw, &packages); err != nil {
		return nil, fmt.Errorf("parse apk query JSON: %w", err)
	}
	if packages == nil {
		return nil, errors.New("expected APK package array")
	}
	result := &Result{}
	for _, p := range packages {
		if p.Name == "" || p.Version == "" || p.Arch == "" {
			return nil, errors.New("incomplete APK package record")
		}
		item := apkSoftware(p.Name, p.Version, p.Arch, p.Origin)
		item.Homepage, item.License, item.Description = p.URL, p.License, p.Description
		result.Items = append(result.Items, item)
	}
	return result, nil
}

func readAPKDatabase() (*Result, error) {
	f, err := os.OpenInRoot("/lib/apk/db", "installed")
	if err != nil {
		return nil, fmt.Errorf("open apk installed database: %w", err)
	}
	defer func() { _ = f.Close() }()
	return parseAPKDatabase(io.LimitReader(f, maxOutputBytes+1))
}

// APK 2's installed database stores one package per blank-line-delimited record.
// Ignore file entries; use only installed metadata, never repository candidates.
func parseAPKDatabase(reader io.Reader) (*Result, error) {
	result := &Result{}
	fields := map[byte]string{}
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		if fields['P'] == "" || fields['V'] == "" || fields['A'] == "" {
			return errors.New("incomplete APK database record")
		}
		item := apkSoftware(fields['P'], fields['V'], fields['A'], fields['o'])
		item.Homepage, item.License, item.Description = fields['U'], fields['L'], fields['T']
		result.Items = append(result.Items, item)
		fields = map[byte]string{}
		return nil
	}
	scanner := bufio.NewScanner(reader)
	size := 0
	for scanner.Scan() {
		line := scanner.Text()
		size += len(line) + 1
		if size > maxOutputBytes {
			return nil, errors.New("APK database exceeds size limit")
		}
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
		} else if len(line) >= 2 && line[1] == ':' && strings.ContainsRune("PVAoULT", rune(line[0])) {
			if _, exists := fields[line[0]]; exists {
				return nil, errors.New("duplicate APK metadata field")
			}
			fields[line[0]] = line[2:]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse apk installed database: %w", err)
	}
	return result, flush()
}

// Compile-time interface check.
var _ Collector = (*APK)(nil)
