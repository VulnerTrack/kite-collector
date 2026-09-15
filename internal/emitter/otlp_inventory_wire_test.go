package emitter

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/telemetry/contract"
)

// The container hashes and the service inventory are emitted on both the
// legacy snake_case keys and the contract v1.2 security.machine.* keys, and
// omitted entirely when the machine carries none.
func TestOTLP_WireShape_InventoryAttributes(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	evt := makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)
	evt.ContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	evt.ImageID = "sha256:cafe"
	evt.ImageDigest = "sha256:feed"
	evt.Services = []model.MachineService{
		{Name: "postgresql", Category: model.ServiceCategoryDatabase, Port: 5432, Protocol: "tcp", Version: "16"},
		{Name: "ldap", Category: model.ServiceCategoryDirectory, Port: 389, Protocol: "tcp"},
	}
	require.NoError(t, em.Emit(context.Background(), evt))

	require.Len(t, *reqs, 1)
	payload := decodeOTLPPayload(t, (*reqs)[0].Body)
	attrs := attrMap(payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes)

	assert.Equal(t, evt.ContainerID, attrs["container_id"])
	assert.Equal(t, "sha256:cafe", attrs["image_id"])
	assert.Equal(t, "sha256:feed", attrs["image_digest"])
	assert.Equal(t, "database,directory", attrs["service_categories"])
	assert.Contains(t, attrs["services"], `"name":"postgresql"`)

	assert.Equal(t, evt.ContainerID, attrs[contract.AttrMachineContainerID])
	assert.Equal(t, "sha256:cafe", attrs[contract.AttrMachineImageID])
	assert.Equal(t, "sha256:feed", attrs[contract.AttrMachineImageDigest])
	assert.Equal(t, "database,directory", attrs[contract.AttrMachineServiceCategories])
	assert.Equal(t, model.EncodeServices(evt.Services), attrs[contract.AttrMachineServices])
	for _, key := range []string{contract.AttrMachineContainerID, contract.AttrMachineImageID, contract.AttrMachineImageDigest, contract.AttrMachineServices, contract.AttrMachineServiceCategories} {
		assert.Truef(t, contract.IsAllowedEventAttribute(contract.EventMachineDiscovered, key), "%s must be declared in the contract", key)
		assert.Truef(t, contract.IsAllowedEventAttribute(contract.EventMachineChanged, key), "%s must be declared in the contract", key)
	}
	for _, c := range model.ServiceCategories(evt.Services) {
		_, ok := contract.AllowedServiceCategories[c]
		assert.Truef(t, ok, "category %q must be in the closed set", c)
	}
}

func TestOTLP_WireShape_InventoryAttributesOmittedWhenEmpty(t *testing.T) {
	endpoint, reqs := startCaptureServer(t, http.StatusOK)
	em := newWireTestEmitter(t, endpoint)
	t.Cleanup(func() { _ = em.Shutdown(context.Background()) })

	require.NoError(t, em.Emit(context.Background(), makeEvent(t, model.EventMachineDiscovered, model.SeverityLow)))
	require.Len(t, *reqs, 1)
	payload := decodeOTLPPayload(t, (*reqs)[0].Body)
	attrs := attrMap(payload.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes)
	for _, key := range []string{
		"container_id", "image_id", "image_digest", "services", "service_categories",
		contract.AttrMachineContainerID, contract.AttrMachineImageID, contract.AttrMachineImageDigest,
		contract.AttrMachineServices, contract.AttrMachineServiceCategories,
	} {
		_, present := attrs[key]
		assert.Falsef(t, present, "attribute %q must be omitted when empty", key)
	}
}
