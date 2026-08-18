package software

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// BuildCPE23
// ---------------------------------------------------------------------------

func TestBuildCPE23_AllFieldsPresent(t *testing.T) {
	got := BuildCPE23("apache", "httpd", "2.4.57")
	assert.Equal(t, "cpe:2.3:a:apache:httpd:2.4.57:*:*:*:*:*:*:*", got)
}

func TestBuildCPE23_EmptyVendor_UsesWildcard(t *testing.T) {
	got := BuildCPE23("", "curl", "7.88.1")
	assert.Equal(t, "cpe:2.3:a:*:curl:7.88.1:*:*:*:*:*:*:*", got)
}

func TestBuildCPE23_EmptyVersion_UsesWildcard(t *testing.T) {
	got := BuildCPE23("gnu", "wget", "")
	assert.Equal(t, "cpe:2.3:a:gnu:wget:*:*:*:*:*:*:*:*", got)
}

func TestBuildCPE23_AllEmpty_ReturnsEmpty(t *testing.T) {
	got := BuildCPE23("", "", "")
	assert.Equal(t, "", got)
}

func TestBuildCPE23_NormalizesSpacesAndCase(t *testing.T) {
	got := BuildCPE23("The Apache Foundation", "HTTP Server", "2.4")
	assert.Equal(t, "cpe:2.3:a:the_apache_foundation:http_server:2.4:*:*:*:*:*:*:*", got)
}

func TestBuildCPE23_StripsSpecialCharacters(t *testing.T) {
	// "!" and "@" are removed; "+" and "~" are escaped per the CPE 2.3
	// formatted-string binding, not deleted.
	got := BuildCPE23("vendor!", "pkg@name", "1.0+dfsg~1")
	assert.Equal(t, `cpe:2.3:a:vendor:pkgname:1.0\+dfsg\~1:*:*:*:*:*:*:*`, got)
}

func TestBuildCPE23_EscapesPlusInProduct(t *testing.T) {
	// NVD stores notepad++ as notepad\+\+; deleting the pluses would
	// collapse g++ into g and libsigc++ into libsigc.
	got := BuildCPE23("don ho", "Notepad++", "8.6")
	assert.Equal(t, `cpe:2.3:a:don_ho:notepad\+\+:8.6:*:*:*:*:*:*:*`, got)
}

func TestBuildCPE23_SplitsEpochFromVersion(t *testing.T) {
	// pacman/dpkg epoch: deleting the colon would report docker 29.7.1
	// as version 129.7.1. NVD versions never carry epochs.
	got := BuildCPE23("", "docker", "1:29.7.1-1")
	assert.Equal(t, "cpe:2.3:a:*:docker:29.7.1-1:*:*:*:*:*:*:*", got)
}

func TestBuildCPE23_TransliteratesToASCII(t *testing.T) {
	// The formatted-string grammar is ASCII-only: café must fold to cafe,
	// not pass through and never match the NVD dictionary.
	got := BuildCPE23("", "café", "1.0")
	assert.Equal(t, "cpe:2.3:a:*:cafe:1.0:*:*:*:*:*:*:*", got)
}

func TestBuildCPE23_EscapedVersionWithVCSSuffix(t *testing.T) {
	// Arch gcc-style versions keep their structure instead of fusing
	// into an unrecognizable blob.
	got := BuildCPE23("", "gcc", "16.1.1+r595+g171d15ac6959-1")
	assert.Equal(t, `cpe:2.3:a:*:gcc:16.1.1\+r595\+g171d15ac6959-1:*:*:*:*:*:*:*`, got)
}

// ---------------------------------------------------------------------------
// BuildCPE23WithTargetSW
// ---------------------------------------------------------------------------

func TestBuildCPE23WithTargetSW_Python(t *testing.T) {
	got := BuildCPE23WithTargetSW("", "requests", "2.31.0", "python")
	assert.Equal(t, "cpe:2.3:a:*:requests:2.31.0:*:*:*:*:python:*:*", got)
}

func TestBuildCPE23WithTargetSW_NodeJS(t *testing.T) {
	got := BuildCPE23WithTargetSW("", "typescript", "5.5.0", "node.js")
	assert.Equal(t, "cpe:2.3:a:*:typescript:5.5.0:*:*:*:*:node.js:*:*", got)
}

// ---------------------------------------------------------------------------
// BuildCPE23Full
// ---------------------------------------------------------------------------

func TestBuildCPE23Full_AllFields(t *testing.T) {
	got := BuildCPE23Full("vendor", "product", "1.0", "python", "x86_64")
	assert.Equal(t, "cpe:2.3:a:vendor:product:1.0:*:*:*:*:python:x86_64:*", got)
}

func TestBuildCPE23Full_EmptyOptionals(t *testing.T) {
	got := BuildCPE23Full("v", "p", "1.0", "", "")
	assert.Equal(t, "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*", got)
}

// ---------------------------------------------------------------------------
// normalizeComponent
// ---------------------------------------------------------------------------

func TestNormalizeComponent_Lowercases(t *testing.T) {
	assert.Equal(t, "hello", normalizeComponent("HELLO"))
}

func TestNormalizeComponent_ReplacesSpaces(t *testing.T) {
	assert.Equal(t, "foo_bar", normalizeComponent("foo bar"))
}

func TestNormalizeComponent_EmptyString(t *testing.T) {
	assert.Equal(t, "", normalizeComponent(""))
}

func TestNormalizeComponent_PreservesHyphensAndDots(t *testing.T) {
	assert.Equal(t, "lib-x.2", normalizeComponent("lib-x.2"))
}

func TestNormalizeComponent_TrimsWhitespace(t *testing.T) {
	assert.Equal(t, "trimmed", normalizeComponent("  trimmed  "))
}
