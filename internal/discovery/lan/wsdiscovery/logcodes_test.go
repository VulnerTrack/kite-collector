package wsdiscovery

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogCodes_FollowConvention(t *testing.T) {
	codes := []LogCode{
		LogCodeWSDNoInterfaces, LogCodeWSDIPv4ListenFail, LogCodeWSDIPv6ListenFail,
		LogCodeWSDOpenSenderFail, LogCodeWSDSendFail,
	}
	for _, c := range codes {
		s := string(c)
		t.Run(s, func(t *testing.T) {
			parts := strings.Split(s, ".")
			assert.GreaterOrEqual(t, len(parts), 3,
				"code %q must have ≥3 dot-separated segments", s)
			assert.Equal(t, "lan_wsdiscovery", parts[0],
				"code %q must lead with the lan_wsdiscovery namespace prefix", s)
			assert.Equal(t, strings.ToLower(s), s,
				"code %q must be all lowercase", s)
			assert.NotContains(t, s, " ", "code %q must not contain spaces", s)
		})
	}
}

func TestLogCodes_AreUnique(t *testing.T) {
	seen := map[LogCode]bool{}
	for _, c := range []LogCode{
		LogCodeWSDNoInterfaces, LogCodeWSDIPv4ListenFail, LogCodeWSDIPv6ListenFail,
		LogCodeWSDOpenSenderFail, LogCodeWSDSendFail,
	} {
		assert.False(t, seen[c], "duplicate log code constant %q", string(c))
		seen[c] = true
	}
}
