package engine

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/model"
)

// listenerMockStore adds the optional HostListenerStore capability to the
// engine's mock store.
type listenerMockStore struct {
	*mockStore
	listeners map[uuid.UUID][]model.HostListener
}

func (m *listenerMockStore) ReplaceHostListeners(_ context.Context, id uuid.UUID, l []model.HostListener) error {
	m.listeners[id] = l
	return nil
}

func (m *listenerMockStore) ListHostListeners(_ context.Context, id uuid.UUID) ([]model.HostListener, error) {
	return m.listeners[id], nil
}

func TestAttachLocalListenerServices(t *testing.T) {
	ms := &listenerMockStore{mockStore: newMockStore(), listeners: map[uuid.UUID][]model.HostListener{}}
	agentID := uuid.Must(uuid.NewV7())
	otherID := uuid.Must(uuid.NewV7())
	ms.listeners[agentID] = []model.HostListener{
		{Port: 5432, Protocol: "tcp", Exposure: "lan", Service: "postgresql", ServiceVersion: "16.3"},
		{Port: 389, Protocol: "tcp", Exposure: "lan"},
	}

	eng := &Engine{store: ms}
	machines := []model.Machine{
		{ID: otherID, Hostname: "peer", DiscoverySource: "network", Tags: `{"x":"y"}`},
		{ID: agentID, Hostname: "me", DiscoverySource: "agent", Tags: model.WithServicesInTags("", []model.MachineService{
			{Name: "docker", Category: model.ServiceCategoryContainerPlatform, Source: "socket"},
		})},
	}
	eng.attachLocalListenerServices(context.Background(), machines)

	assert.Equal(t, `{"x":"y"}`, machines[0].Tags, "non-agent machines are untouched")
	services := model.ServicesFromTags(machines[1].Tags)
	require.Len(t, services, 3)
	assert.Equal(t, []string{model.ServiceCategoryContainerPlatform, model.ServiceCategoryDatabase, model.ServiceCategoryDirectory}, model.ServiceCategories(services))

	// Services are material: a changed listener set flips the fingerprint.
	before := machines[1].MaterialFingerprint()
	ms.listeners[agentID] = ms.listeners[agentID][:1]
	machines[1].Tags = model.WithServicesInTags(machines[1].Tags, nil)
	eng.attachLocalListenerServices(context.Background(), machines)
	assert.NotEqual(t, before, machines[1].MaterialFingerprint())
}

func TestAttachLocalListenerServices_NoOps(t *testing.T) {
	// Store without host listeners.
	plain := &Engine{store: newMockStore()}
	machines := []model.Machine{{ID: uuid.Must(uuid.NewV7()), DiscoverySource: "agent", Tags: ""}}
	plain.attachLocalListenerServices(context.Background(), machines)
	assert.Equal(t, "", machines[0].Tags)

	// No agent machine in the batch / no listeners yet.
	ms := &listenerMockStore{mockStore: newMockStore(), listeners: map[uuid.UUID][]model.HostListener{}}
	eng := &Engine{store: ms}
	machines = []model.Machine{{ID: uuid.Must(uuid.NewV7()), DiscoverySource: "network"}}
	eng.attachLocalListenerServices(context.Background(), machines)
	assert.Equal(t, "", machines[0].Tags)
	machines = []model.Machine{{ID: uuid.Must(uuid.NewV7()), DiscoverySource: "agent"}}
	eng.attachLocalListenerServices(context.Background(), machines)
	assert.Equal(t, "", machines[0].Tags)
}

func TestEngine_EmitsServicesAndImageHashes(t *testing.T) {
	ms := newMockStore()
	reg := discovery.NewRegistry()
	tags := model.WithServicesInTags(`{"container_id_full":"`+
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"+
		`","image_id":"sha256:cafe","image_digest":"sha256:feed"}`,
		[]model.MachineService{{Name: "postgresql", Category: model.ServiceCategoryDatabase, Port: 5432, Version: "16"}})
	reg.Register(&mockSource{
		name: "test",
		machines: []model.Machine{{
			Hostname:        "pg",
			MachineType:     model.MachineTypeContainer,
			OSFamily:        "linux",
			DiscoverySource: "test",
			Tags:            tags,
		}},
	})
	em := &recordingEmitter{}
	eng := newTestEngine(ms, reg, em)
	_, err := eng.Run(context.Background(), newTestConfig())
	require.NoError(t, err)

	em.mu.Lock()
	defer em.mu.Unlock()
	require.NotEmpty(t, em.events)
	evt := em.events[0]
	assert.Equal(t, model.EventMachineDiscovered, evt.EventType)
	assert.Equal(t, "sha256:feed", evt.ImageDigest)
	assert.Equal(t, "sha256:cafe", evt.ImageID)
	assert.Len(t, evt.ContainerID, 64)
	require.Len(t, evt.Services, 1)
	assert.Equal(t, "postgresql", evt.Services[0].Name)
	assert.Contains(t, evt.Details, `"image_digest":"sha256:feed"`)
	assert.Contains(t, evt.Details, `"service_categories":"database"`)
}
