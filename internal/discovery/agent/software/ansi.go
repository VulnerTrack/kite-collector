package software

import "regexp"

// ansiCSI matches ANSI CSI escape sequences — parameter bytes then a
// final byte, which covers the SGR color codes CLIs emit when they
// believe stdout is a TTY (pod/CLAide always colorises errors, and
// some tools mis-detect pipes). Parsers must see plain text: a color
// code glued to "-> Name (version)" fails the prefix check and the
// inventory silently parses to zero packages.
var ansiCSI = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

// stripANSI removes ANSI escape sequences, leaving the printable text.
func stripANSI(s string) string {
	return ansiCSI.ReplaceAllString(s, "")
}
