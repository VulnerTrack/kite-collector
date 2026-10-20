package ldap

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

// The AD account attributes the source tags onto a machine must survive
// FromMachine, the only path from Machine to the OTLP emitter.
func TestComputerToMachine_ADAttributesReachEvent(t *testing.T) {
	c := &computerEntry{
		dn:                 "CN=DC01,OU=Domain Controllers,DC=corp,DC=example",
		domainDNSName:      "corp.example",
		samAccountName:     "DC01",
		objectSID:          "S-1-5-21-1004336348-1177238915-682003330-1000",
		dnsHostName:        "dc01.corp.example",
		ouPath:             "OU=Domain Controllers,DC=corp,DC=example",
		servicePrincipals:  []string{"ldap/dc01.corp.example"},
		memberOf:           []string{"CN=Domain Controllers,CN=Users,DC=corp,DC=example"},
		uacFlags:           uacServerTrust | uacTrustedForDeleg,
		enabled:            true,
		lastLogonTimestamp: 1776672191,
		passwordLastSet:    1775008800,
	}

	var evt model.MachineEvent
	evt.FromMachine(c.toMachine(time.Now()))

	assert.Equal(t, map[string]string{
		contract.AttrADDomainDNSName:      "corp.example",
		contract.AttrADSAMAccountName:     "DC01",
		contract.AttrADObjectSID:          "S-1-5-21-1004336348-1177238915-682003330-1000",
		contract.AttrADDistinguishedName:  "CN=DC01,OU=Domain Controllers,DC=corp,DC=example",
		contract.AttrADOUPath:             "OU=Domain Controllers,DC=corp,DC=example",
		contract.AttrADEnabled:            "true",
		contract.AttrADUACFlags:           "532480",
		contract.AttrADLastLogonTimestamp: "2026-04-20T08:03:11Z",
		contract.AttrADPasswordLastSet:    "2026-04-01T02:00:00Z",
		contract.AttrADSPNs:               `["ldap/dc01.corp.example"]`,
		contract.AttrADGroups:             `["CN=Domain Controllers,CN=Users,DC=corp,DC=example"]`,
	}, evt.AD)
}
