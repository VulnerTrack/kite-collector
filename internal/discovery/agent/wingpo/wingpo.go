// Package wingpo inventories the on-disk Local Group Policy
// cache under %windir%\System32\GroupPolicy\ and the per-user
// counterpart at %windir%\System32\GroupPolicyUsers\<SID>\. Every
// Group Policy that lands on a Windows host materialises into a
// gpt.ini descriptor, a binary Registry.pol blob, and an optional
// Scripts\{Startup,Shutdown,Logon,Logoff} directory.
//
// File-based discovery is the deliberate design choice — the
// audit pipeline hashes each artifact for drift detection without
// invoking `gpresult` or the Group Policy Service. The headline
// finding is **T1037.001 (Logon Script: Windows)**: any file
// inside a Machine\Scripts\Startup\ folder runs at boot with
// SYSTEM privileges; any file inside Shutdown runs at shutdown.
//
// Read-only by intent — we walk the GroupPolicy trees only,
// never invoke gpupdate. (Project guideline 4.2.)
package wingpo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strings"
)

// MaxArtifacts bounds per-scan output. A typical host has 5-20
// GPO artifacts; the 4096 ceiling covers enterprise-policy
// payloads with hundreds of scripts.
const MaxArtifacts = 4096

// GPOScope tags the discovery tree the artifact came from.
// Pinned to the host_local_gpo.gpo_scope CHECK enum.
type GPOScope string

const (
	ScopeMachine GPOScope = "machine"
	ScopeUser    GPOScope = "user"
	ScopePerUser GPOScope = "per-user"
	ScopeUnknown GPOScope = "unknown"
)

// ArtifactKind tags which Group Policy artifact a row represents.
// Pinned to the host_local_gpo.artifact_kind CHECK enum.
type ArtifactKind string

const (
	KindGPTIni         ArtifactKind = "gpt-ini"
	KindRegistryPol    ArtifactKind = "registry-pol"
	KindScriptStartup  ArtifactKind = "script-startup"
	KindScriptShutdown ArtifactKind = "script-shutdown"
	KindScriptLogon    ArtifactKind = "script-logon"
	KindScriptLogoff   ArtifactKind = "script-logoff"
	KindUnknown        ArtifactKind = "unknown"
)

// Artifact mirrors host_local_gpo's column shape exactly.
type Artifact struct {
	ExtensionNames         string       `json:"extension_names,omitempty"`
	GPOScope               GPOScope     `json:"gpo_scope"`
	ArtifactKind           ArtifactKind `json:"artifact_kind"`
	FileHash               string       `json:"file_hash"`
	TargetSID              string       `json:"target_sid,omitempty"`
	FilePath               string       `json:"file_path"`
	GPOVersion             int          `json:"gpo_version,omitempty"`
	FileSizeBytes          int64        `json:"file_size_bytes"`
	FileMtime              int64        `json:"file_mtime,omitempty"`
	HasPolSignature        bool         `json:"has_pol_signature"`
	IsPolSignatureInvalid  bool         `json:"is_pol_signature_invalid"`
	IsMachineScope         bool         `json:"is_machine_scope"`
	IsUserScope            bool         `json:"is_user_scope"`
	IsPerUserGPO           bool         `json:"is_per_user_gpo"`
	IsScriptArtifact       bool         `json:"is_script_artifact"`
	IsPersistenceCandidate bool         `json:"is_persistence_candidate"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Artifact, error)
}

// HashContents returns the SHA-256 hex of an artifact body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// RegistryPolSignature is the 8-byte "PReg\x01\x00\x00\x00" header
// every valid Group Policy Registry.pol file begins with.
var RegistryPolSignature = []byte{
	'P', 'R', 'e', 'g',
	0x01, 0x00, 0x00, 0x00,
}

// IsValidRegistryPol reports whether `body` begins with the
// canonical Registry.pol signature.
func IsValidRegistryPol(body []byte) bool {
	if len(body) < len(RegistryPolSignature) {
		return false
	}
	for i, b := range RegistryPolSignature {
		if body[i] != b {
			return false
		}
	}
	return true
}

// ScriptSubdirToKind maps the canonical Scripts subdirectory
// names to our ArtifactKind. Returns KindUnknown for anything
// else (including the parent `Scripts` dir itself).
func ScriptSubdirToKind(name string) ArtifactKind {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "startup":
		return KindScriptStartup
	case "shutdown":
		return KindScriptShutdown
	case "logon":
		return KindScriptLogon
	case "logoff":
		return KindScriptLogoff
	}
	return KindUnknown
}

// AnnotateSecurity sets the derived booleans on an Artifact that
// has its raw fields populated.
func AnnotateSecurity(a *Artifact) {
	a.IsMachineScope = a.GPOScope == ScopeMachine
	a.IsUserScope = a.GPOScope == ScopeUser
	a.IsPerUserGPO = a.GPOScope == ScopePerUser
	a.IsScriptArtifact = a.ArtifactKind == KindScriptStartup ||
		a.ArtifactKind == KindScriptShutdown ||
		a.ArtifactKind == KindScriptLogon ||
		a.ArtifactKind == KindScriptLogoff
	a.IsPersistenceCandidate = a.IsScriptArtifact || a.IsPerUserGPO
}

// SortArtifacts returns a deterministic ordering by file path.
func SortArtifacts(as []Artifact) {
	sort.Slice(as, func(i, j int) bool {
		return as[i].FilePath < as[j].FilePath
	})
}

// FileBaseLower returns filepath.Base(p) lowercased. Used so
// callers don't pull in extra imports.
func FileBaseLower(p string) string {
	return strings.ToLower(filepath.Base(p))
}
