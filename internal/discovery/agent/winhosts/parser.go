package winhosts

import (
	"bufio"
	"bytes"
	"strings"
)

// Parse walks one hosts(5) body and returns one Entry per (line,
// hostname) tuple. Lines look like:
//
//	# comment-only line
//	127.0.0.1   localhost   loopback         # trailing comment
//	0.0.0.0     ads.example.com
//	10.0.0.5    backend.corp.local backend
//
// The first whitespace-delimited token is the IP; the rest (up to
// the first `#`) are hostnames. Each hostname after the first is
// emitted as IsAlias=true so the audit pipeline can prefer the
// canonical name in its joins.
func Parse(raw []byte, filePath string) []Entry {
	hash := HashContents(raw)
	out := make([]Entry, 0, 16)

	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	lineNo := 0
	for scan.Scan() {
		lineNo++
		line := scan.Text()
		body, comment := splitComment(line)
		body = strings.TrimSpace(body)
		if body == "" {
			continue
		}
		fields := strings.Fields(body)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		hosts := fields[1:]
		for i, h := range hosts {
			e := Entry{
				FilePath:  filePath,
				FileHash:  hash,
				LineNo:    lineNo,
				RawLine:   strings.TrimRight(line, " \t"),
				IPAddress: ip,
				Hostname:  h,
				IsAlias:   i > 0,
				Comment:   strings.TrimSpace(comment),
			}
			AnnotateSecurity(&e)
			out = append(out, e)
			if len(out) >= MaxEntries {
				return out
			}
		}
	}
	return out
}

// splitComment splits a hosts(5) line into (body, comment). The `#`
// can appear mid-line; everything from there is the comment.
func splitComment(line string) (string, string) {
	if i := strings.IndexByte(line, '#'); i >= 0 {
		return line[:i], line[i+1:]
	}
	return line, ""
}
