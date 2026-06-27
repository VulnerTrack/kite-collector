package winfilezilla

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"strconv"
	"strings"
)

// sitemanagerDoc mirrors the top-level shape of FileZilla's
// sitemanager.xml. The full schema is much wider, but we only
// inventory the columns the audit pipeline alerts on.
type sitemanagerDoc struct {
	XMLName xml.Name     `xml:"FileZilla3"`
	Servers serversBlock `xml:"Servers"`
}

type serversBlock struct {
	Servers []serverEntry `xml:"Server"`
	Folders []folderBlock `xml:"Folder"`
}

type folderBlock struct {
	Servers []serverEntry `xml:"Server"`
	Folders []folderBlock `xml:"Folder"`
}

type serverEntry struct {
	Host      string    `xml:"Host"`
	Port      string    `xml:"Port"`
	Protocol  string    `xml:"Protocol"`
	User      string    `xml:"User"`
	Pass      passField `xml:"Pass"`
	Logontype string    `xml:"Logontype"`
	Name      string    `xml:"Name"`
}

// passField captures Pass element with optional encoding="base64".
type passField struct {
	Encoding string `xml:"encoding,attr"`
	Value    string `xml:",chardata"`
}

// ParseSitemanager walks one FileZilla sitemanager.xml body and
// emits one Site per <Server> stanza (including nested ones
// inside <Folder>s). Passwords are NEVER kept verbatim — only
// the decoded length is recorded.
func ParseSitemanager(body []byte) []Site {
	out := make([]Site, 0, 4)
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var doc sitemanagerDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return out
	}
	walkServers(doc.Servers.Servers, &out)
	walkFolders(doc.Servers.Folders, &out)
	return out
}

func walkFolders(folders []folderBlock, out *[]Site) {
	for _, f := range folders {
		walkServers(f.Servers, out)
		walkFolders(f.Folders, out)
		if len(*out) >= MaxSites {
			return
		}
	}
}

func walkServers(servers []serverEntry, out *[]Site) {
	for _, s := range servers {
		port, _ := strconv.Atoi(strings.TrimSpace(s.Port))
		proto, _ := strconv.Atoi(strings.TrimSpace(s.Protocol))
		logon, err := strconv.Atoi(strings.TrimSpace(s.Logontype))
		if err != nil {
			logon = -1
		}
		site := Site{
			SiteName:       strings.TrimSpace(s.Name),
			SiteHost:       strings.TrimSpace(s.Host),
			SitePort:       port,
			SiteProtocol:   ProtocolName(proto),
			SiteUser:       strings.TrimSpace(s.User),
			LogonType:      logon,
			PasswordLength: passwordLength(s.Pass),
		}
		*out = append(*out, site)
		if len(*out) >= MaxSites {
			return
		}
	}
}

func passwordLength(p passField) int {
	v := strings.TrimSpace(p.Value)
	if v == "" {
		return 0
	}
	if strings.EqualFold(p.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return len(v)
		}
		return len(decoded)
	}
	return len(v)
}
