package wingpo

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultLocalGPORoot is the canonical local-machine + user GPO
// cache directory.
const DefaultLocalGPORoot = `C:\Windows\System32\GroupPolicy`

// DefaultPerUserGPORoot is the canonical per-user GPO cache
// directory (subdirs named by SID).
const DefaultPerUserGPORoot = `C:\Windows\System32\GroupPolicyUsers`

// fileCollector walks the GPO trees from a configurable base.
// Test seam swaps readFile / readDir / statFile.
type fileCollector struct {
	readFile    func(string) ([]byte, error)
	readDir     func(string) ([]os.DirEntry, error)
	statFile    func(string) (os.FileInfo, error)
	localRoot   string
	perUserRoot string
}

// NewCollector returns a Collector wired to the canonical
// GroupPolicy + GroupPolicyUsers directories.
func NewCollector() Collector {
	return &fileCollector{
		localRoot:   DefaultLocalGPORoot,
		perUserRoot: DefaultPerUserGPORoot,
		readFile:    os.ReadFile,
		readDir:     os.ReadDir,
		statFile:    os.Stat,
	}
}

func (c *fileCollector) Name() string { return "wingpo" }

func (c *fileCollector) Collect(_ context.Context) ([]Artifact, error) {
	out := make([]Artifact, 0, 16)

	// Local GroupPolicy: Machine + User subtrees.
	c.harvestRoot(c.localRoot, "", &out)

	// Per-user GroupPolicyUsers: each immediate subdirectory is a
	// SID-named GPO root.
	if dirs, err := c.readDir(c.perUserRoot); err == nil {
		sort.Slice(dirs, func(i, j int) bool {
			return dirs[i].Name() < dirs[j].Name()
		})
		for _, d := range dirs {
			if !d.IsDir() {
				continue
			}
			sid := d.Name()
			if strings.HasPrefix(sid, ".") {
				continue
			}
			c.harvestRoot(filepath.Join(c.perUserRoot, sid), sid, &out)
		}
	}

	if len(out) > MaxArtifacts {
		out = out[:MaxArtifacts]
	}
	SortArtifacts(out)
	return out, nil
}

// harvestRoot processes one GPO root directory. When `targetSID`
// is non-empty we treat the root as a per-user GPO; otherwise the
// Machine / User subdir scope is inferred from each artifact's
// path.
func (c *fileCollector) harvestRoot(root, targetSID string, out *[]Artifact) {
	// gpt.ini sits at the root.
	if gpt := c.readArtifact(filepath.Join(root, "gpt.ini"), KindGPTIni); gpt != nil {
		gpt.GPOScope = scopeForRoot(targetSID, "")
		gpt.TargetSID = targetSID
		if body, err := c.readFile(gpt.FilePath); err == nil {
			gpt.GPOVersion, gpt.ExtensionNames = ParseGPTIni(body)
		}
		AnnotateSecurity(gpt)
		*out = append(*out, *gpt)
	}

	for _, sub := range []struct {
		Rel   string
		Scope GPOScope
	}{
		{"Machine", ScopeMachine},
		{"User", ScopeUser},
	} {
		scope := sub.Scope
		if targetSID != "" {
			scope = ScopePerUser
		}
		// Registry.pol
		if pol := c.readArtifact(filepath.Join(root, sub.Rel, "Registry.pol"), KindRegistryPol); pol != nil {
			pol.GPOScope = scope
			pol.TargetSID = targetSID
			if body, err := c.readFile(pol.FilePath); err == nil {
				pol.HasPolSignature = IsValidRegistryPol(body)
				pol.IsPolSignatureInvalid = !pol.HasPolSignature
			}
			AnnotateSecurity(pol)
			*out = append(*out, *pol)
		}
		// Scripts\{Startup,Shutdown,Logon,Logoff}\*
		scriptsRoot := filepath.Join(root, sub.Rel, "Scripts")
		c.harvestScripts(scriptsRoot, scope, targetSID, out)
	}
}

// harvestScripts enumerates files inside each canonical script
// subdirectory and emits one Artifact per file.
func (c *fileCollector) harvestScripts(scriptsRoot string, scope GPOScope, targetSID string, out *[]Artifact) {
	subs, err := c.readDir(scriptsRoot)
	if err != nil {
		return
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name() < subs[j].Name() })
	for _, sub := range subs {
		if !sub.IsDir() {
			continue
		}
		kind := ScriptSubdirToKind(sub.Name())
		if kind == KindUnknown {
			continue
		}
		subDir := filepath.Join(scriptsRoot, sub.Name())
		files, err := c.readDir(subDir)
		if err != nil {
			continue
		}
		sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			name := f.Name()
			if strings.HasPrefix(name, ".") || strings.EqualFold(name, "scripts.ini") || strings.EqualFold(name, "psscripts.ini") {
				continue
			}
			art := c.readArtifact(filepath.Join(subDir, name), kind)
			if art == nil {
				continue
			}
			art.GPOScope = scope
			art.TargetSID = targetSID
			AnnotateSecurity(art)
			*out = append(*out, *art)
			if len(*out) >= MaxArtifacts {
				return
			}
		}
	}
}

// readArtifact reads + hashes the given file, returning a
// partially-populated Artifact. Missing files return nil so the
// caller can skip.
func (c *fileCollector) readArtifact(path string, kind ArtifactKind) *Artifact {
	body, err := c.readFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return nil
	}
	art := Artifact{
		FilePath:      path,
		FileHash:      HashContents(body),
		FileSizeBytes: int64(len(body)),
		ArtifactKind:  kind,
	}
	if fi, err := c.statFile(path); err == nil {
		art.FileMtime = fi.ModTime().Unix()
	}
	return &art
}

// scopeForRoot infers the GPOScope for a root-level artifact
// (gpt.ini specifically). When targetSID is non-empty we're
// inside a per-user GPO; otherwise the root gpt.ini belongs to
// the Machine scope.
func scopeForRoot(targetSID, _ string) GPOScope {
	if targetSID != "" {
		return ScopePerUser
	}
	return ScopeMachine
}
