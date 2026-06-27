// Package smbshares inventories Samba share definitions from
// /etc/samba/smb.conf and every drop-in under /etc/samba/smb.conf.d/.
//
// Samba's `smb.conf` is the SMB-side equivalent of NFS exports: each
// `[section]` declares a share with file-system semantics (path,
// read-only, masks) and access controls (valid users, hosts allow/
// deny, guest_ok). The classic finding shapes:
//
//   - `guest ok = yes` + `writable = yes` on a non-loopback host →
//     anonymous SMB write (CWE-732 + T1135 entry point).
//   - Missing `hosts allow` line on a share = world-exposed once
//     port 445 is reachable.
//   - `force user = root` makes every write land as local root
//     regardless of the SMB client's identity (CWE-269).
//   - Wide `create mask` (≥0666) ignores Unix permission discipline
//     and creates world-writable files (CWE-732).
//
// Every collector is **read-only by intent** — it parses smb.conf,
// never invokes smbcontrol / smbcacls. Read-only is enforced by
// guideline 4.2 of the kite-collector project.
package smbshares

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// MaxShares bounds per-scan output. A small office Samba install has
// 5-15 shares; the 1024 ceiling covers heavyweight team-file-server
// installs without bloating SQLite writes.
const MaxShares = 1024

// SectionKind classifies a smb.conf section. Pinned to the
// host_smb_shares.section_kind CHECK enum.
type SectionKind string

const (
	SectionGlobal   SectionKind = "global"
	SectionShare    SectionKind = "share"
	SectionHomes    SectionKind = "homes"
	SectionPrinters SectionKind = "printers"
	SectionPrintDS  SectionKind = "print$"
	SectionUnknown  SectionKind = "unknown"
)

// Share mirrors host_smb_shares' column shape exactly.
type Share struct {
	HostsDeny        string      `json:"hosts_deny,omitempty"`
	InvalidUsers     string      `json:"invalid_users,omitempty"`
	ForceGroup       string      `json:"force_group,omitempty"`
	RawLine          string      `json:"raw_line,omitempty"`
	FilePath         string      `json:"file_path"`
	SectionKind      SectionKind `json:"section_kind"`
	Path             string      `json:"path,omitempty"`
	Comment          string      `json:"comment,omitempty"`
	ValidUsers       string      `json:"valid_users,omitempty"`
	HostsAllow       string      `json:"hosts_allow,omitempty"`
	AdminUsers       string      `json:"admin_users,omitempty"`
	ReadList         string      `json:"read_list,omitempty"`
	FileHash         string      `json:"file_hash"`
	WriteList        string      `json:"write_list,omitempty"`
	SectionName      string      `json:"section_name"`
	CreateMask       string      `json:"create_mask,omitempty"`
	DirectoryMask    string      `json:"directory_mask,omitempty"`
	ForceUser        string      `json:"force_user,omitempty"`
	LineNo           int         `json:"line_no"`
	IsPublic         bool        `json:"is_public"`
	IsGuestOK        bool        `json:"is_guest_ok"`
	IsWritable       bool        `json:"is_writable"`
	IsReadOnly       bool        `json:"is_read_only"`
	IsBrowseable     bool        `json:"is_browseable"`
	IsGuestWritable  bool        `json:"is_guest_writable"`
	IsWorldExposed   bool        `json:"is_world_exposed"`
	IsWideCreateMask bool        `json:"is_wide_create_mask"`
	IsForceUserRoot  bool        `json:"is_force_user_root"`
}

// Collector is the read-only contract every implementation satisfies.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]Share, error)
}

// HashContents returns the SHA-256 hex of a smb.conf body.
func HashContents(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// NormalizeSectionKind maps a section header to our enum.
// Special-cased reserved sections: [global], [homes], [printers],
// [print$]. Everything else is treated as a user share.
func NormalizeSectionKind(s string) SectionKind {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "global":
		return SectionGlobal
	case "homes":
		return SectionHomes
	case "printers":
		return SectionPrinters
	case "print$":
		return SectionPrintDS
	case "":
		return SectionUnknown
	}
	return SectionShare
}

// ParseBool implements Samba's permissive boolean grammar: yes/true/
// on/1 → true; no/false/off/0/"" → false.
func ParseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "yes", "true", "on", "1":
		return true
	}
	return false
}

// CanonicalKey collapses Samba's whitespace-tolerant keys into a
// single canonical form: lowercase, spaces stripped. "Read Only" /
// "READ ONLY" / "readonly" all normalise to "readonly".
func CanonicalKey(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

// IsWideCreateMask reports whether a Samba file-mode mask grants
// **other-write** on created files — the canonical CWE-732 shape on a
// multi-tenant filesystem. Group-only writes (0660, 0664, 0775) are
// not flagged: those rely on POSIX group membership and are routine
// in closed-team setups; the danger is when "everyone" can write.
//
// Empty / unparseable masks return false — we don't infer Samba's
// default, the audit pipeline gets to decide.
func IsWideCreateMask(mask string) bool {
	v := strings.TrimSpace(mask)
	if v == "" {
		return false
	}
	v = strings.TrimPrefix(v, "0o")
	v = strings.TrimPrefix(v, "0")
	if v == "" {
		return false
	}
	n, err := strconv.ParseInt(v, 8, 32)
	if err != nil {
		return false
	}
	return n&0o002 != 0
}

// IsForceUserRoot reports whether the `force user` value resolves
// to local root. Accepts both `root` and uid `0`.
func IsForceUserRoot(s string) bool {
	v := strings.ToLower(strings.TrimSpace(s))
	return v == "root" || v == "0"
}

// HasHostsAllowRestriction reports whether the share has any
// `hosts allow` restriction. Empty/missing means "any host".
func HasHostsAllowRestriction(s string) bool {
	return strings.TrimSpace(s) != ""
}

// AnnotateSecurity sets the indexed booleans on a Share from its
// already-populated string fields.
//
// Defaults (per smb.conf(5)):
//   - browseable     = yes
//   - guest ok       = no
//   - writable / read only — the default is `read only = yes`. We
//     track explicit settings; the parser pre-populates IsReadOnly /
//     IsWritable from explicit `writable`/`read only`/`writeable`
//     directives (Samba treats `writable=yes` and `read only=no` as
//     equivalent — same for the inverse pair).
func AnnotateSecurity(s *Share) {
	s.IsWideCreateMask = IsWideCreateMask(s.CreateMask) ||
		IsWideCreateMask(s.DirectoryMask)
	s.IsForceUserRoot = IsForceUserRoot(s.ForceUser)
	s.IsWorldExposed = s.SectionKind == SectionShare &&
		!HasHostsAllowRestriction(s.HostsAllow)
	// `is_guest_writable` only makes sense on real share sections.
	// [global] guest_ok=yes alone is a default, not a finding.
	if s.SectionKind == SectionShare {
		s.IsGuestWritable = (s.IsGuestOK || s.IsPublic) && s.IsWritable
	}
}

// SortShares returns a deterministic ordering: file path, section.
func SortShares(ss []Share) {
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].FilePath != ss[j].FilePath {
			return ss[i].FilePath < ss[j].FilePath
		}
		return ss[i].SectionName < ss[j].SectionName
	})
}
