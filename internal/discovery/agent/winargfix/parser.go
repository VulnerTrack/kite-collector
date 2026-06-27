package winargfix

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
	"time"
)

// FIXSummary captures aggregate stats + leaked-tag flags from
// a FIX session log body.
type FIXSummary struct {
	SenderCompID   string
	TargetCompID   string
	AccountRaw     string
	FirstSeen      string
	LastSeen       string
	MessageCount   int64
	OrderCount     int64
	CancelCount    int64
	ExecCount      int64
	IsAfterHours   bool
	HasPasswordTag bool
}

// tagRE matches a FIX `tag=value` segment. SOH (\x01) is the
// canonical separator; logs sometimes substitute `|`.
var (
	tagSender   = []byte{0x01, '4', '9', '='}
	tagTarget   = []byte{0x01, '5', '6', '='}
	tagAccount  = []byte{0x01, '1', '='}
	tagPassword = []byte{0x01, '5', '5', '4', '='}
	tagMsgType  = []byte{0x01, '3', '5', '='}

	// Pipe-separated alt (some QuickFIX logs use ASCII | sep).
	pipeSender   = []byte("|49=")
	pipeTarget   = []byte("|56=")
	pipeAccount  = []byte("|1=")
	pipePassword = []byte("|554=")
	pipeMsgType  = []byte("|35=")

	// Bracket-quoted alt (event-log style).
	bracketSender   = []byte("(49)")
	bracketTarget   = []byte("(56)")
	bracketPassword = []byte("(554)")
)

// timestampRE matches QuickFIX log timestamps:
// "20260616-13:45:01.123".
var timestampRE = regexp.MustCompile(`(20\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-([01]\d|2[0-3]):([0-5]\d):([0-5]\d)`)

// ParseFIXLog scans a FIX session log body and returns
// aggregate stats. Returns ok=false on empty input.
func ParseFIXLog(body []byte) (FIXSummary, bool) {
	var out FIXSummary
	if len(body) == 0 {
		return out, false
	}
	if bytes.Contains(body, tagPassword) ||
		bytes.Contains(body, pipePassword) ||
		bytes.Contains(body, bracketPassword) ||
		bytes.Contains(bytes.ToLower(body), []byte("password=")) {
		out.HasPasswordTag = true
	}

	// Extract SenderCompID / TargetCompID from first occurrence.
	out.SenderCompID = extractAfter(body, tagSender, pipeSender, bracketSender)
	out.TargetCompID = extractAfter(body, tagTarget, pipeTarget, bracketTarget)
	out.AccountRaw = extractAfter(body, tagAccount, pipeAccount, nil)

	// Scan line-by-line for MsgType counts + timestamps.
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		msgType := extractMsgType(line)
		if msgType != "" {
			out.MessageCount++
			switch msgType {
			case "D":
				out.OrderCount++
			case "F":
				out.CancelCount++
			case "8":
				out.ExecCount++
			}
		}
		if ts := timestampRE.Find(line); ts != nil {
			s := string(ts)
			if out.FirstSeen == "" || s < out.FirstSeen {
				out.FirstSeen = s
			}
			if s > out.LastSeen {
				out.LastSeen = s
			}
			if isAfterVenueHours(s) {
				out.IsAfterHours = true
			}
		}
	}

	if !hasAny(out) {
		return out, false
	}
	return out, true
}

func hasAny(s FIXSummary) bool {
	return s.MessageCount > 0 || s.SenderCompID != "" ||
		s.TargetCompID != "" || s.AccountRaw != "" ||
		s.FirstSeen != "" || s.HasPasswordTag
}

func extractAfter(body []byte, sohSep, pipeSep, bracketSep []byte) string {
	for _, sep := range [][]byte{sohSep, pipeSep, bracketSep} {
		if sep == nil {
			continue
		}
		idx := bytes.Index(body, sep)
		if idx < 0 {
			continue
		}
		rest := body[idx+len(sep):]
		end := bytes.IndexAny(rest, "\x01|\r\n ")
		if end < 0 {
			end = len(rest)
		}
		v := strings.TrimSpace(string(rest[:end]))
		if v != "" {
			return v
		}
	}
	return ""
}

func extractMsgType(line []byte) string {
	for _, sep := range [][]byte{tagMsgType, pipeMsgType} {
		idx := bytes.Index(line, sep)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(sep):]
		end := bytes.IndexAny(rest, "\x01|\r\n ")
		if end < 0 {
			end = len(rest)
		}
		return strings.TrimSpace(string(rest[:end]))
	}
	return ""
}

// isAfterVenueHours reports whether the timestamp falls outside
// the union of Argentine venue trading windows (BYMA + MATba
// roughly 09:00–17:00 ART, Mon–Fri).
func isAfterVenueHours(ts string) bool {
	t, err := time.Parse("20060102-15:04:05", ts)
	if err != nil {
		return false
	}
	wd := t.Weekday()
	if wd == time.Saturday || wd == time.Sunday {
		return true
	}
	h := t.Hour()
	if h < 9 || h >= 17 {
		return true
	}
	return false
}
