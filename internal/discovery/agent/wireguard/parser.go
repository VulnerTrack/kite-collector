package wireguard

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
)

// Parse walks one WireGuard .conf body and returns a populated
// Tunnel slice — one [Interface] row followed by zero or more [Peer]
// rows in source-file order. `filePath` is recorded verbatim and
// also drives the tunnel-name field.
func Parse(raw []byte, filePath string) []Tunnel {
	hash := HashContents(raw)
	name := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))

	out := make([]Tunnel, 0, 4)
	var current *Tunnel
	peerCount := 0

	finalize := func() {
		if current == nil {
			return
		}
		AnnotateSecurity(current)
		out = append(out, *current)
		current = nil
	}

	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || isComment(line) {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			finalize()
			if len(out) >= MaxRows {
				return out
			}
			sectionName := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			kind := SectionUnknown
			idx := 0
			switch sectionName {
			case "interface":
				kind = SectionInterface
			case "peer":
				kind = SectionPeer
				peerCount++
				idx = peerCount
			}
			current = &Tunnel{
				FilePath:     filePath,
				FileHash:     hash,
				SectionKind:  kind,
				SectionIndex: idx,
				TunnelName:   name,
			}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		applyDirective(current, key, value)
	}
	finalize()
	return out
}

// applyDirective routes one `key = value` pair into the active
// section's fields. WireGuard keys are case-sensitive in the wg-quick
// reference; we normalise to lowercase for switch-table simplicity.
func applyDirective(t *Tunnel, key, value string) {
	canonical := strings.ToLower(strings.TrimSpace(key))

	switch t.SectionKind {
	case SectionInterface:
		applyInterface(t, canonical, value)
	case SectionPeer:
		applyPeer(t, canonical, value)
	case SectionUnknown:
		// no-op — skip stray content under unknown sections.
	}
}

func applyInterface(t *Tunnel, key, value string) {
	switch key {
	case "privatekey":
		// Mark only — we never persist the secret. Just enough info
		// for the audit pipeline to drive findings.
		t.HasPrivateKey = strings.TrimSpace(value) != ""
	case "address":
		t.Address = value
	case "listenport":
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			t.ListenPort = n
		}
	case "dns":
		t.DNS = value
	case "mtu":
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			t.MTU = n
		}
	case "table":
		t.TableRouting = value
	case "preup", "postup", "predown", "postdown":
		body := strings.TrimSpace(value)
		if body != "" {
			t.ShellHooks = append(t.ShellHooks, key+": "+body)
		}
	case "publickey":
		// Some configs annotate the [Interface] section with the
		// derived public key as a comment-style line. We capture the
		// fingerprint without storing the key.
		t.PublicKeyFingerprint = PublicKeyFingerprint(value)
	}
}

func applyPeer(t *Tunnel, key, value string) {
	switch key {
	case "publickey":
		t.PeerPublicKeyFingerprint = PublicKeyFingerprint(value)
	case "presharedkey":
		t.HasPresharedKey = strings.TrimSpace(value) != ""
	case "endpoint":
		t.Endpoint = value
	case "allowedips":
		t.AllowedIPs = value
	case "persistentkeepalive":
		if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			t.PersistentKeepaliveSeconds = n
		}
	}
}

// splitKV separates `key = value` (with arbitrary whitespace around
// the `=`). Bare lines without `=` are not part of wg-quick's
// grammar; we return ok=false there.
func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:]), true
	}
	return "", "", false
}

// isComment reports whether a trimmed line is purely a `#` comment.
// wg-quick does NOT accept `;` comments — they trip the parser when
// it sees them, so we don't treat them as comments either.
func isComment(line string) bool {
	return strings.HasPrefix(line, "#")
}
