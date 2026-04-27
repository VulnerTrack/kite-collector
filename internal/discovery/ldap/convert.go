package ldap

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

// Active Directory userAccountControl flag bits we care about.
//
// MSDN: https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_user_flag_enum
// Only the subset relevant to RFC-0121 findings/asset classification is decoded.
const (
	uacAccountDisable  uint32 = 0x00000002
	uacWorkstation     uint32 = 0x00001000
	uacServerTrust     uint32 = 0x00002000
	uacDontExpirePwd   uint32 = 0x00010000
	uacTrustedForDeleg uint32 = 0x00080000
)

// windowsEpochOffset is the number of seconds between
// 1601-01-01 (Windows FILETIME epoch) and 1970-01-01 (Unix epoch).
const windowsEpochOffset int64 = 11644473600

// windowsTicksPerSecond is the number of 100-ns ticks in one second.
const windowsTicksPerSecond int64 = 10_000_000

// computerEntry is the typed view of a single Active Directory computer
// object after extraction from an *ldap.Entry. Field names mirror RFC-0121
// §5.6.1 so the conversion to model.Asset and contract.AttrAD* tags is
// straightforward.
type computerEntry struct {
	dn                 string
	domainDNSName      string
	samAccountName     string
	objectSID          string
	dnsHostName        string
	operatingSystem    string
	osVersion          string
	ouPath             string
	servicePrincipals  []string
	memberOf           []string
	uacFlags           uint32
	enabled            bool
	lastLogonTimestamp int64 // Unix seconds (0 == never)
	passwordLastSet    int64 // Unix seconds (0 == never)
}

// extractComputer translates a raw *ldap.Entry into a computerEntry. Missing
// or malformed attributes degrade gracefully — the entry's DN is the only
// hard requirement.
func extractComputer(e *ldapv3.Entry, baseDN string) (*computerEntry, error) {
	if e == nil || e.DN == "" {
		return nil, fmt.Errorf("entry has no DN")
	}

	c := &computerEntry{
		dn:               e.DN,
		samAccountName:   strings.TrimSuffix(e.GetAttributeValue("sAMAccountName"), "$"),
		dnsHostName:      e.GetAttributeValue("dnsHostName"),
		operatingSystem:  e.GetAttributeValue("operatingSystem"),
		osVersion:        e.GetAttributeValue("operatingSystemVersion"),
		domainDNSName:    domainFromBaseDN(baseDN),
		ouPath:           parentOU(e.DN),
		servicePrincipals: e.GetAttributeValues("servicePrincipalName"),
		memberOf:          e.GetAttributeValues("memberOf"),
	}

	if sid := e.GetRawAttributeValue("objectSid"); len(sid) > 0 {
		c.objectSID = parseObjectSID(sid)
	}

	if uac := e.GetAttributeValue("userAccountControl"); uac != "" {
		c.uacFlags = parseUint32(uac)
	}
	c.enabled = c.uacFlags&uacAccountDisable == 0

	if v := e.GetAttributeValue("lastLogonTimestamp"); v != "" {
		c.lastLogonTimestamp = windowsTimeToUnix(parseInt64(v))
	}
	if v := e.GetAttributeValue("pwdLastSet"); v != "" {
		c.passwordLastSet = windowsTimeToUnix(parseInt64(v))
	}

	return c, nil
}

// toAsset materialises the discovery-time view of the computer as a
// model.Asset. The asset's Tags JSON carries the closed AD attribute set
// declared in contract.AttrAD*.
func (c *computerEntry) toAsset(now time.Time) model.Asset {
	hostname := c.dnsHostName
	if hostname == "" {
		hostname = c.samAccountName
	}

	tags := map[string]any{
		contract.AttrADDomainDNSName:     c.domainDNSName,
		contract.AttrADSAMAccountName:    c.samAccountName,
		contract.AttrADObjectSID:         c.objectSID,
		contract.AttrADOUPath:            c.ouPath,
		contract.AttrADEnabled:           c.enabled,
		contract.AttrADUACFlags:          c.uacFlags,
		contract.AttrADDistinguishedName: c.dn,
	}
	if c.lastLogonTimestamp > 0 {
		tags[contract.AttrADLastLogonTimestamp] = c.lastLogonTimestamp
	}
	if c.passwordLastSet > 0 {
		tags[contract.AttrADPasswordLastSet] = c.passwordLastSet
	}
	if len(c.servicePrincipals) > 0 {
		tags[contract.AttrADSPNs] = c.servicePrincipals
	}
	if len(c.memberOf) > 0 {
		tags[contract.AttrADGroups] = c.memberOf
	}

	tagsJSON, _ := json.Marshal(tags)

	asset := model.Asset{
		ID:              uuid.Must(uuid.NewV7()),
		Hostname:        hostname,
		AssetType:       classifyAsset(c.uacFlags, c.operatingSystem),
		OSFamily:        osFamilyFrom(c.operatingSystem),
		OSVersion:       c.osVersion,
		DiscoverySource: SourceName,
		IsAuthorized:    model.AuthorizationAuthorized,
		IsManaged:       model.ManagedManaged,
		Tags:            string(tagsJSON),
		FirstSeenAt:     now,
		LastSeenAt:      now,
	}
	asset.ComputeNaturalKey()
	return asset
}

// classifyAsset maps the userAccountControl trust bits + operatingSystem
// label to the kite asset taxonomy. Domain controllers and member servers
// are surfaced as servers; workstation-trust accounts as workstations;
// everything else falls back to server because AD computer accounts are
// almost always servers/clients (vs. printers, etc.).
func classifyAsset(uacFlags uint32, os string) model.AssetType {
	if uacFlags&uacWorkstation != 0 {
		return model.AssetTypeWorkstation
	}
	if uacFlags&uacServerTrust != 0 {
		return model.AssetTypeServer
	}
	lower := strings.ToLower(os)
	if strings.Contains(lower, "server") {
		return model.AssetTypeServer
	}
	if strings.Contains(lower, "windows") {
		return model.AssetTypeWorkstation
	}
	return model.AssetTypeServer
}

// osFamilyFrom returns the lowercase OS family for the operatingSystem
// label seen in AD ("Windows Server 2022 Standard" → "windows").
func osFamilyFrom(os string) string {
	lower := strings.ToLower(os)
	switch {
	case strings.Contains(lower, "windows"):
		return "windows"
	case strings.Contains(lower, "linux"):
		return "linux"
	default:
		return ""
	}
}

// domainFromBaseDN converts an LDAP base DN (e.g. "DC=corp,DC=acme,DC=com")
// into a dotted DNS name ("corp.acme.com"). Returns the empty string when
// the DN contains no DC components.
func domainFromBaseDN(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToLower(p), "dc=") {
			out = append(out, p[3:])
		}
	}
	return strings.Join(out, ".")
}

// parentOU extracts the parent OU path from a computer DN. Given
// "CN=WS01,OU=Workstations,OU=NA,DC=corp,DC=acme,DC=com" it returns
// "OU=Workstations,OU=NA,DC=corp,DC=acme,DC=com".
func parentOU(dn string) string {
	idx := strings.Index(dn, ",")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(dn[idx+1:])
}

// parseObjectSID decodes a binary SID into the canonical
// "S-R-A-S1-S2-...-Sn" textual form per [MS-DTYP] §2.4.2.2. Returns the
// empty string on malformed input rather than failing the whole search.
//
// Layout (little-endian for sub-authorities, big-endian for IdentifierAuthority):
//
//	byte 0      : revision
//	byte 1      : SubAuthorityCount (n)
//	bytes 2..7  : IdentifierAuthority (6 bytes, big-endian)
//	bytes 8..   : n × 4-byte SubAuthority (little-endian uint32)
func parseObjectSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	revision := b[0]
	subCount := int(b[1])
	if len(b) < 8+subCount*4 {
		return ""
	}
	// 6-byte big-endian identifier authority.
	var auth uint64
	for i := 2; i < 8; i++ {
		auth = (auth << 8) | uint64(b[i])
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", revision, auth)
	for i := 0; i < subCount; i++ {
		off := 8 + i*4
		sub := binary.LittleEndian.Uint32(b[off : off+4])
		fmt.Fprintf(&sb, "-%d", sub)
	}
	return sb.String()
}

// windowsTimeToUnix converts a 64-bit Windows FILETIME (100-ns ticks since
// 1601-01-01 UTC) into Unix seconds. Returns 0 for the sentinel values 0
// and 0x7FFFFFFFFFFFFFFF (== "never logged on" / "password never set").
func windowsTimeToUnix(filetime int64) int64 {
	if filetime <= 0 || filetime == 0x7FFFFFFFFFFFFFFF {
		return 0
	}
	return filetime/windowsTicksPerSecond - windowsEpochOffset
}

// parseInt64 safely parses a string into an int64, returning 0 on error
// or empty input. AD numeric attributes can be very large (FILETIMEs go
// up to ~10^18) so we cannot fall back to strconv.Atoi.
func parseInt64(s string) int64 {
	if s == "" {
		return 0
	}
	var v int64
	negative := false
	i := 0
	if s[0] == '-' {
		negative = true
		i = 1
	}
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0
		}
		v = v*10 + int64(c-'0')
	}
	if negative {
		return -v
	}
	return v
}

// parseUint32 parses a decimal uint32, returning 0 on parse error.
// userAccountControl is an int32 in AD but the bit-mask interpretation
// is unsigned, so we mask any sign bit on the way in.
func parseUint32(s string) uint32 {
	v := parseInt64(s)
	return uint32(v) //nolint:gosec // userAccountControl is bit-mask interpreted as uint32
}
