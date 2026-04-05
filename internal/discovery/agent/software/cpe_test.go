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
	got := BuildCPE23("vendor!", "pkg@name", "1.0+dfsg~1")
	assert.Equal(t, "cpe:2.3:a:vendor:pkgname:1.0dfsg1:*:*:*:*:*:*:*", got)
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
