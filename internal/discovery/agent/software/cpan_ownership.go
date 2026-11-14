package software

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const ownershipBatch = 100

// Only locate files; never require installed modules or evaluate their VERSION
// assignments. Use the same interpreter as cpan so another Perl's @INC cannot
// supply an unrelated package owner.
const perlModulePaths = `use JSON::PP; my %paths;
for my $name (@ARGV) {
    next unless $name =~ /^\w+(?:::\w+)*$/;
    (my $file = $name) =~ s!::!/!g;
    my %files;
    for my $dir (@INC) {
        next if ref($dir) || $dir !~ m!^/!;
        my $path = "$dir/$file.pm";
        $files{$path} = 1 if -f $path;
    }
    # cpan -l can list shadowed copies with different versions. Without a
    # unique file, the module/version row cannot establish a specific owner.
    $paths{$name} = (keys %files)[0] if keys(%files) == 1;
}
print encode_json(\%paths);`

var (
	perlBinaryName    = regexp.MustCompile(`^perl(?:[0-9.]+)?$`)
	debianPackageName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?$`)
)

func cpanInterpreter() string {
	path, err := exec.LookPath("cpan")
	if err != nil {
		return ""
	}
	// Read only inside the PATH directory that supplied cpan. Root-aware
	// opening also rejects a symlink redirected outside that directory.
	f, err := os.OpenInRoot(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	header, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(header), "\n")
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if !strings.HasPrefix(line, "#!") || len(fields) == 0 {
		return ""
	}
	if len(fields) == 2 && fields[0] == "/usr/bin/env" && perlBinaryName.MatchString(fields[1]) {
		path, _ := exec.LookPath(fields[1])
		return path
	}
	if len(fields) == 1 && filepath.IsAbs(fields[0]) && perlBinaryName.MatchString(filepath.Base(fields[0])) {
		return fields[0]
	}
	// Interpreter flags/wrappers can change @INC; leave their ownership unknown.
	return ""
}

func enrichCPANOwnership(ctx context.Context, result *Result) {
	interpreter := cpanInterpreter()
	if interpreter == "" || len(result.Items) == 0 {
		return
	}
	enrichCPANOwnershipWith(ctx, result, interpreter)
}

func enrichCPANOwnershipWith(ctx context.Context, result *Result, interpreter string) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	if _, err := exec.LookPath("dpkg-query"); err != nil {
		return
	}
	// One native inventory query per scan, not one process per module.
	native, err := NewDpkg().Collect(ctx)
	if err != nil {
		// Optional enrichment never discards module inventory.
		return
	}
	packages := map[string]*model.InstalledSoftware{}
	for i := range native.Items {
		p := &native.Items[i]
		key := p.SoftwareName
		if _, exists := packages[key]; exists {
			packages[key] = nil
		} else {
			packages[key] = p
		}
		packages[key+":"+p.Architecture] = p
	}
	for start := 0; start < len(result.Items) && ctx.Err() == nil; start += ownershipBatch {
		end := min(start+ownershipBatch, len(result.Items))
		args := []string{"-e", perlModulePaths, "--"}
		for _, item := range result.Items[start:end] {
			args = append(args, item.SoftwareName)
		}
		out, err := runWithLimits(ctx, interpreter, args...)
		if err != nil {
			continue
		}
		var paths map[string]string
		if json.Unmarshal(out, &paths) != nil {
			continue
		}
		wanted := map[string]bool{}
		search := []string{"-S", "--"}
		for i := start; i < end; i++ {
			path := paths[result.Items[i].SoftwareName]
			// dpkg -S accepts glob patterns. Only literal absolute file paths
			// are ownership evidence; returned names must also match exactly.
			if !filepath.IsAbs(path) || len(path) > 2048 || strings.ContainsAny(path, "*?[]\\\n\r\t") {
				continue
			}
			result.Items[i].InstallPath = path
			if !wanted[path] {
				search = append(search, path)
				wanted[path] = true
			}
		}
		if len(wanted) == 0 {
			continue
		}
		out, _, code, err := runWithLimitsTolerateExit(ctx, "dpkg-query", search...)
		// Exit 1 can mean that only some files have a registered owner.
		if err != nil || (code != 0 && code != 1) {
			continue
		}
		owners := parseDpkgFileOwners(string(out), wanted)
		for i := start; i < end; i++ {
			item := &result.Items[i]
			p := packages[owners[item.InstallPath]]
			if p == nil || p.Version == "" {
				continue
			}
			item.PackageOwner = &model.SoftwarePackageOwner{
				Name: p.SoftwareName, Version: p.Version, PackageManager: "dpkg",
				Architecture: p.Architecture, SourcePackage: p.SourcePackage,
				SourceVersion: p.SourceVersion, Homepage: p.Homepage,
				File: item.InstallPath, Evidence: "dpkg-query-search",
			}
		}
	}
}

func parseDpkgFileOwners(raw string, wanted map[string]bool) map[string]string {
	owners := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		pkg, path, ok := strings.Cut(line, ": ")
		if !ok || !wanted[path] {
			continue
		}
		// Multiple owners, diversions and malformed output are not unique proof.
		if !debianPackageName.MatchString(pkg) {
			owners[path] = ""
			continue
		}
		if previous, seen := owners[path]; seen && previous != pkg {
			owners[path] = ""
		} else if !seen {
			owners[path] = pkg
		}
	}
	return owners
}
