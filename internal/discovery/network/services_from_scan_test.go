package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery/network/servicefp"
	"github.com/vulnertrack/kite-collector/internal/model"
)

func TestServicesFromScan(t *testing.T) {
	services := servicesFromScan([]int{22, 443, 5432, 8080, 40000}, map[int]servicefp.Result{
		22:   {Protocol: "ssh", Version: "OpenSSH_9.6p1"},
		443:  {Protocol: "http", TLS: true},
		5432: {Protocol: "postgresql", Version: "16.3"},
	})
	byPort := map[int]model.MachineService{}
	for _, s := range services {
		byPort[s.Port] = s
	}
	require.Len(t, byPort, 4)
	assert.Equal(t, "ssh", byPort[22].Name)
	assert.Equal(t, "banner", byPort[22].Source)
	assert.Equal(t, "https", byPort[443].Name, "TLS-wrapped http reports as https")
	assert.Equal(t, "postgresql", byPort[5432].Name)
	assert.Equal(t, "16.3", byPort[5432].Version)
	assert.Equal(t, model.ServiceCategoryDatabase, byPort[5432].Category)
	assert.Equal(t, "http", byPort[8080].Name, "unfingerprinted well-known port falls back to the port table")
	assert.Equal(t, "port", byPort[8080].Source)
	_, unknown := byPort[40000]
	assert.False(t, unknown, "unknown ports without a banner are not services")

	assert.Nil(t, servicesFromScan(nil, nil))

	tags := model.WithServicesInTags(withServicesTag("", []string{"22/ssh OpenSSH_9.6p1"}), services)
	assert.Len(t, model.ServicesFromTags(tags), 4)
	assert.Contains(t, tags, "network_scan_services", "legacy label list is kept alongside")
}
