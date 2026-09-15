package ldap

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestDirectoryServices_DomainController(t *testing.T) {
	services := directoryServices(uacServerTrust, []string{
		"ldap/dc01.corp.example",
		"GC/dc01.corp.example/corp.example",
		"HOST/dc01",
		"DNS/dc01.corp.example",
		"MSSQLSvc/dc01.corp.example:1433",
		"TERMSRV/dc01",
		"bogus-no-slash",
	})
	byName := map[string]model.MachineService{}
	for _, s := range services {
		byName[s.Name] = s
	}
	assert.Len(t, byName, 6)
	assert.Equal(t, model.ServiceCategoryDirectory, byName["active_directory"].Category)
	assert.Equal(t, "directory+spn", byName["active_directory"].Source, "DC role and the GC SPN both attest it")
	assert.Equal(t, model.ServiceCategoryDirectory, byName["kerberos"].Category)
	assert.Equal(t, "directory+spn", byName["ldap"].Source)
	assert.Equal(t, model.ServiceCategoryDNS, byName["dns"].Category)
	assert.Equal(t, 1433, byName["mssql"].Port)
	assert.Equal(t, "tcp", byName["mssql"].Protocol)
	assert.Equal(t, "spn", byName["mssql"].Source)
	assert.Equal(t, model.ServiceCategoryRemoteAccess, byName["rdp"].Category)
	_, hasHost := byName["host"]
	assert.False(t, hasHost, "HOST/ is Windows plumbing, not a service")
}

func TestDirectoryServices_MemberServerWithoutSPNs(t *testing.T) {
	assert.Nil(t, directoryServices(uacWorkstation, nil))
	assert.Nil(t, directoryServices(uacWorkstation, []string{"HOST/ws01", "RestrictedKrbHost/ws01"}))
}

func TestComputerToMachine_CarriesServicesTag(t *testing.T) {
	c := &computerEntry{
		dnsHostName:       "sql01.corp.example",
		samAccountName:    "SQL01$",
		uacFlags:          0x1000, // WORKSTATION_TRUST_ACCOUNT
		servicePrincipals: []string{"MSSQLSvc/sql01.corp.example:1433"},
	}
	m := c.toMachine(time.Now())
	var tags map[string]any
	require.NoError(t, json.Unmarshal([]byte(m.Tags), &tags))
	require.Contains(t, tags, model.TagServices)
	services := model.ServicesFromTags(m.Tags)
	require.Len(t, services, 1)
	assert.Equal(t, "mssql", services[0].Name)
	assert.Equal(t, model.ServiceCategoryDatabase, services[0].Category)

	var evt model.MachineEvent
	evt.FromMachine(m)
	assert.Equal(t, []string{model.ServiceCategoryDatabase}, model.ServiceCategories(evt.Services))
}
