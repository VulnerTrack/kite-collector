package timesync

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ParseChrony walks a chrony.conf body (and any conf-d drop-in).
// Grammar per chrony.conf(5) — only the lines we care about are
// recognised; everything else is ignored:
//
//	server <addr> [iburst] [prefer] [nts] [key N] [minpoll N] [maxpoll N]
//	pool <addr> [...]
//	peer <addr> [...]
//	keyfile /etc/chrony/chrony.keys  (parsed indirectly via key <N>)
func ParseChrony(raw []byte, filePath string) []Peer {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Peer, 0, 8)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		fields := strings.Fields(clean)
		if len(fields) < 2 {
			continue
		}
		directive := chronyDirective(fields[0])
		if directive == DirectiveUnknown {
			continue
		}
		p := Peer{
			Source:    SourceChrony,
			Directive: directive,
			Server:    fields[1],
			Port:      123,
			Protocol:  ProtocolNTP,
			FilePath:  filePath,
			FileHash:  hash,
			LineNo:    i + 1,
			RawLine:   clean,
		}
		applyChronyOptions(&p, fields[2:])
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxPeers {
			break
		}
	}
	return out
}

func chronyDirective(s string) Directive {
	switch strings.ToLower(s) {
	case "server":
		return DirectiveServer
	case "peer":
		return DirectivePeer
	case "pool":
		return DirectivePool
	}
	return DirectiveUnknown
}

// applyChronyOptions walks the post-server options. Each token is
// either a standalone flag (iburst, prefer, nts) or a key/value pair
// in `name value` form.
func applyChronyOptions(p *Peer, opts []string) {
	for i := 0; i < len(opts); i++ {
		switch strings.ToLower(opts[i]) {
		case "iburst":
			p.Iburst = true
		case "prefer":
			p.PreferFlag = true
		case "nts":
			p.Protocol = ProtocolNTS
			p.IsAuthenticated = true
			p.Port = 4460 // NTS-KE default
		case "key":
			if i+1 < len(opts) {
				if n, err := strconv.Atoi(opts[i+1]); err == nil {
					p.KeyID = n
					p.IsAuthenticated = true
				}
				i++
			}
		case "minpoll":
			if i+1 < len(opts) {
				if n, err := strconv.Atoi(opts[i+1]); err == nil {
					p.MinPoll = n
				}
				i++
			}
		case "maxpoll":
			if i+1 < len(opts) {
				if n, err := strconv.Atoi(opts[i+1]); err == nil {
					p.MaxPoll = n
				}
				i++
			}
		case "port":
			if i+1 < len(opts) {
				if n, err := strconv.Atoi(opts[i+1]); err == nil {
					p.Port = n
				}
				i++
			}
		}
	}
}

// ParseNTPd walks an ntp.conf body (ISC ntpd 4.x, also used by sntp).
// Grammar per ntp.conf(5):
//
//	server <addr> [iburst] [prefer] [key N] [autokey] [minpoll N]
//	pool <addr> [...]
//	peer <addr> [...]
func ParseNTPd(raw []byte, filePath string) []Peer {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Peer, 0, 8)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		fields := strings.Fields(clean)
		if len(fields) < 2 {
			continue
		}
		directive := chronyDirective(fields[0])
		if directive == DirectiveUnknown {
			continue
		}
		p := Peer{
			Source:    SourceNTPd,
			Directive: directive,
			Server:    fields[1],
			Port:      123,
			Protocol:  ProtocolNTP,
			FilePath:  filePath,
			FileHash:  hash,
			LineNo:    i + 1,
			RawLine:   clean,
		}
		applyNTPdOptions(&p, fields[2:])
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxPeers {
			break
		}
	}
	return out
}

func applyNTPdOptions(p *Peer, opts []string) {
	for i := 0; i < len(opts); i++ {
		switch strings.ToLower(opts[i]) {
		case "iburst":
			p.Iburst = true
		case "prefer":
			p.PreferFlag = true
		case "autokey":
			p.Protocol = ProtocolAutokey
			p.IsAuthenticated = true
		case "key":
			if i+1 < len(opts) {
				if n, err := strconv.Atoi(opts[i+1]); err == nil {
					p.KeyID = n
					p.IsAuthenticated = true
				}
				i++
			}
		case "minpoll":
			if i+1 < len(opts) {
				if n, err := strconv.Atoi(opts[i+1]); err == nil {
					p.MinPoll = n
				}
				i++
			}
		case "maxpoll":
			if i+1 < len(opts) {
				if n, err := strconv.Atoi(opts[i+1]); err == nil {
					p.MaxPoll = n
				}
				i++
			}
		}
	}
}

// ParseTimesyncd walks /etc/systemd/timesyncd.conf. Grammar per
// timesyncd.conf(5):
//
//	[Time]
//	NTP=server1 server2
//	FallbackNTP=...
//
// Each whitespace-separated token in NTP=/FallbackNTP= is one peer.
// systemd-timesyncd speaks SNTP (no auth) — IsAuthenticated stays
// false; Protocol is ProtocolSNTP.
func ParseTimesyncd(raw []byte, filePath string) []Peer {
	hash := HashContents(raw)
	lines := splitLines(raw)

	var (
		section  string
		servers  []string
		fallback []string
	)
	for _, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "[") && strings.HasSuffix(clean, "]") {
			section = strings.ToLower(strings.Trim(clean, "[]"))
			continue
		}
		if section != "time" {
			continue
		}
		k, v, ok := splitKV(clean)
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "ntp":
			servers = append(servers, strings.Fields(v)...)
		case "fallbackntp":
			fallback = append(fallback, strings.Fields(v)...)
		}
	}

	out := make([]Peer, 0, len(servers)+len(fallback))
	for _, s := range servers {
		p := mkTimesyncd(s, DirectiveServer, filePath, hash)
		out = append(out, p)
	}
	for _, s := range fallback {
		p := mkTimesyncd(s, DirectiveFallback, filePath, hash)
		out = append(out, p)
	}
	return out
}

func mkTimesyncd(server string, directive Directive, filePath, hash string) Peer {
	p := Peer{
		Source:    SourceSystemdTimesyncd,
		Directive: directive,
		Server:    server,
		Port:      123,
		Protocol:  ProtocolSNTP,
		FilePath:  filePath,
		FileHash:  hash,
	}
	AnnotateSecurity(&p)
	return p
}

// ParseOpenNTPd walks an OpenNTPD /etc/ntpd.conf body. Grammar per
// ntpd.conf(5):
//
//	server <addr> [weight N]
//	servers <addr>        (DNS round-robin, treated as pool)
//	listen on *
//
// OpenNTPD has no authentication primitive.
func ParseOpenNTPd(raw []byte, filePath string) []Peer {
	hash := HashContents(raw)
	lines := splitLines(raw)

	out := make([]Peer, 0, 4)
	for i, line := range lines {
		clean := stripComment(line)
		clean = strings.TrimSpace(clean)
		if clean == "" {
			continue
		}
		fields := strings.Fields(clean)
		if len(fields) < 2 {
			continue
		}
		var directive Directive
		switch strings.ToLower(fields[0]) {
		case "server":
			directive = DirectiveServer
		case "servers":
			directive = DirectivePool // round-robin DNS = pool semantics
		default:
			continue
		}
		p := Peer{
			Source:    SourceOpenNTPd,
			Directive: directive,
			Server:    fields[1],
			Port:      123,
			Protocol:  ProtocolNTP,
			FilePath:  filePath,
			FileHash:  hash,
			LineNo:    i + 1,
			RawLine:   clean,
		}
		AnnotateSecurity(&p)
		out = append(out, p)
		if len(out) >= MaxPeers {
			break
		}
	}
	return out
}

// -- shared helpers -----------------------------------------------------

func splitLines(raw []byte) []string {
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	var out []string
	for scan.Scan() {
		out = append(out, scan.Text())
	}
	return out
}

func stripComment(line string) string {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i]
	}
	return line
}

func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
	}
	return "", "", false
}
