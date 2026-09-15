package model

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitImageRef(t *testing.T) {
	cases := []struct {
		ref, repo, tag string
	}{
		{"postgres:16", "postgres", "16"},
		{"postgres", "postgres", ""},
		{"docker.io/bitnami/postgresql:16.3.0", "docker.io/bitnami/postgresql", "16.3.0"},
		{"registry.local:5000/team/app", "registry.local:5000/team/app", ""},
		{"registry.local:5000/team/app:1.2", "registry.local:5000/team/app", "1.2"},
		{"nginx@sha256:abc", "nginx", ""},
		{"nginx:1.25@sha256:abc", "nginx", "1.25"},
		{"", "", ""},
	}
	for _, c := range cases {
		repo, tag := SplitImageRef(c.ref)
		assert.Equal(t, c.repo, repo, c.ref)
		assert.Equal(t, c.tag, tag, c.ref)
	}
}

func TestServiceFromImage(t *testing.T) {
	cases := []struct {
		ref, name, category, version string
	}{
		{"postgres:16", "postgresql", ServiceCategoryDatabase, "16"},
		{"docker.io/bitnami/postgresql:16.3.0", "postgresql", ServiceCategoryDatabase, "16.3.0"},
		{"timescale/timescaledb:2.15-pg16", "postgresql", ServiceCategoryDatabase, "2.15-pg16"},
		{"mcr.microsoft.com/mssql/server:2022-latest", "mssql", ServiceCategoryDatabase, "2022-latest"},
		{"redis:7-alpine", "redis", ServiceCategoryCache, "7-alpine"},
		{"redis:latest", "redis", ServiceCategoryCache, ""},
		{"nowsci/samba-domain", "active_directory", ServiceCategoryDirectory, ""},
		{"osixia/openldap:1.5.0", "ldap", ServiceCategoryDirectory, "1.5.0"},
		{"dpage/pgadmin4", "pgadmin", ServiceCategoryOther, ""},
		{"prom/mysqld-exporter", "exporter", ServiceCategoryMonitoring, ""},
		{"confluentinc/cp-kafka:7.6.0", "kafka", ServiceCategoryMessageQueue, "7.6.0"},
		{"hashicorp/vault:1.15", "vault", ServiceCategorySecrets, "1.15"},
		{"nginx:1.25", "nginx", ServiceCategoryWeb, "1.25"},
		{"ghcr.io/acme/api:v2.1.0", "", "", ""},
	}
	for _, c := range cases {
		svc, ok := ServiceFromImage(c.ref)
		if c.name == "" {
			assert.False(t, ok, c.ref)
			continue
		}
		require.True(t, ok, c.ref)
		assert.Equal(t, c.name, svc.Name, c.ref)
		assert.Equal(t, c.category, svc.Category, c.ref)
		assert.Equal(t, c.version, svc.Version, c.ref)
		assert.Equal(t, "image", svc.Source)
	}
}

func TestServiceFromProtocolAndPort(t *testing.T) {
	svc, ok := ServiceFromProtocol("PostgreSQL")
	require.True(t, ok)
	assert.Equal(t, "postgresql", svc.Name)
	assert.Equal(t, ServiceCategoryDatabase, svc.Category)

	svc, ok = ServiceFromProtocol("amqp")
	require.True(t, ok)
	assert.Equal(t, "rabbitmq", svc.Name)

	svc, ok = ServiceFromProtocol("jdwp")
	require.True(t, ok, "unknown protocols are still recorded")
	assert.Equal(t, "jdwp", svc.Name)
	assert.Equal(t, ServiceCategoryOther, svc.Category)

	_, ok = ServiceFromProtocol("  ")
	assert.False(t, ok)

	svc, ok = ServiceFromPort(3268)
	require.True(t, ok)
	assert.Equal(t, "active_directory", svc.Name)
	assert.Equal(t, ServiceCategoryDirectory, svc.Category)
	assert.Equal(t, 3268, svc.Port)

	_, ok = ServiceFromPort(9000)
	assert.False(t, ok, "ambiguous ports must not classify")
}

func TestMergeServices_FoldsBareIntoPorted(t *testing.T) {
	merged := MergeServices(
		[]MachineService{{Name: "postgresql", Category: ServiceCategoryDatabase, Version: "16", Source: "image"}},
		[]MachineService{
			{Name: "postgresql", Category: ServiceCategoryDatabase, Port: 5432, Protocol: "tcp", Source: "port"},
			{Name: "ssh", Category: ServiceCategoryRemoteAccess, Port: 22},
			{Name: "ssh", Category: ServiceCategoryRemoteAccess, Port: 22, Version: "OpenSSH_9.6"},
			{Name: "", Category: "x"},
		},
	)
	require.Len(t, merged, 2)
	assert.Equal(t, "postgresql", merged[0].Name)
	assert.Equal(t, 5432, merged[0].Port)
	assert.Equal(t, "16", merged[0].Version, "bare image row's version folds into the ported row")
	assert.Equal(t, "image+port", merged[0].Source)
	assert.Equal(t, "ssh", merged[1].Name)
	assert.Equal(t, "OpenSSH_9.6", merged[1].Version)

	// Deterministic order regardless of input order.
	again := MergeServices(merged[1:], merged[:1])
	assert.Equal(t, merged, again)
}

func TestMergeServices_Cap(t *testing.T) {
	var many []MachineService
	for i := 0; i < maxServicesPerMachine+10; i++ {
		many = append(many, MachineService{Name: "svc", Category: ServiceCategoryOther, Port: 1000 + i})
	}
	assert.Len(t, MergeServices(many), maxServicesPerMachine)
}

func TestServicesTagsRoundTrip(t *testing.T) {
	services := []MachineService{
		{Name: "redis", Category: ServiceCategoryCache, Port: 6379, Protocol: "tcp"},
		{Name: "ldap", Category: ServiceCategoryDirectory, Port: 389, Protocol: "tcp"},
	}
	tags := WithServicesInTags(`{"image":"redis:7"}`, services)

	var obj map[string]any
	require.NoError(t, json.Unmarshal([]byte(tags), &obj))
	assert.Equal(t, "redis:7", obj["image"], "existing tags are preserved")
	_, isArray := obj[TagServices].([]any)
	assert.True(t, isArray, "services are stored as a native JSON array")

	got := ServicesFromTags(tags)
	require.Len(t, got, 2)
	assert.Equal(t, "redis", got[0].Name, "sorted by category: cache < directory")
	assert.Equal(t, ServiceCategoryDirectory, got[1].Category)

	// String-encoded array (as a store or pair-form tag would carry it).
	encoded := `{"services":"` + strings.ReplaceAll(EncodeServices(services), `"`, `\"`) + `"}`
	assert.Len(t, ServicesFromTags(encoded), 2)

	// Pair-form tags.
	pair := MarshalTags(map[string]string{TagServices: EncodeServices(services)})
	assert.Len(t, ServicesFromTags(pair), 2)

	// Removing the last service drops the key; an empty object collapses to "".
	assert.Equal(t, `{"image":"redis:7"}`, WithServicesInTags(tags, nil))
	assert.Equal(t, "", WithServicesInTags("", nil))

	assert.Nil(t, ServicesFromTags(""))
	assert.Nil(t, ServicesFromTags("not json"))
	assert.Nil(t, ServicesFromTags(`{"services":"garbage"}`))
}

func TestServiceCategories(t *testing.T) {
	cats := ServiceCategories([]MachineService{
		{Name: "a", Category: ServiceCategoryWeb},
		{Name: "b", Category: ServiceCategoryDatabase},
		{Name: "c", Category: ServiceCategoryWeb},
		{Name: "d"},
	})
	assert.Equal(t, []string{ServiceCategoryDatabase, ServiceCategoryWeb}, cats)
}

func TestServicesFromListeners(t *testing.T) {
	services := ServicesFromListeners([]HostListener{
		{Port: 5432, Protocol: "tcp6", Exposure: "lan", Service: "postgresql", ServiceVersion: "16.3"},
		{Port: 22, Protocol: "tcp", Exposure: "internet", Service: "ssh", ServiceVersion: "OpenSSH_9.6"},
		{Port: 389, Protocol: "tcp", Exposure: "lan"},   // unfingerprinted, well-known
		{Port: 41234, Protocol: "tcp", Exposure: "lan"}, // unfingerprinted, unknown
		{Port: 53, Protocol: "udp", Exposure: "lan"},
	})
	require.Len(t, services, 4)
	byName := map[string]MachineService{}
	for _, s := range services {
		byName[s.Name] = s
	}
	assert.Equal(t, "16.3", byName["postgresql"].Version)
	assert.Equal(t, "tcp", byName["postgresql"].Protocol, "tcp6 folds onto tcp")
	assert.Equal(t, "lan", byName["postgresql"].Exposure)
	assert.Equal(t, "listener", byName["postgresql"].Source)
	assert.Equal(t, "internet", byName["ssh"].Exposure)
	assert.Equal(t, ServiceCategoryDirectory, byName["ldap"].Category)
	assert.Equal(t, "udp", byName["dns"].Protocol)
}

func TestMachineEvent_LiftsContainerHashesAndServices(t *testing.T) {
	tags := map[string]any{
		"container_id":      "abc123def456",
		TagContainerID:      "abc123def4567890abc123def4567890abc123def4567890abc123def4567890",
		TagImageID:          "sha256:cafe",
		TagImageDigest:      "sha256:feed",
		TagImageRepoDigests: []string{"redis@sha256:feed"},
		TagServices: []MachineService{
			{Name: "redis", Category: ServiceCategoryCache, Port: 6379, Protocol: "tcp", Version: "7"},
		},
	}
	encoded, err := json.Marshal(tags)
	require.NoError(t, err)
	m := Machine{ID: uuid.Must(uuid.NewV7()), Hostname: "redis-cache", MachineType: MachineTypeContainer, Tags: string(encoded)}

	var evt MachineEvent
	evt.FromMachine(m)
	assert.Equal(t, tags[TagContainerID], evt.ContainerID)
	assert.Equal(t, "sha256:cafe", evt.ImageID)
	assert.Equal(t, "sha256:feed", evt.ImageDigest)
	require.Len(t, evt.Services, 1)
	assert.Equal(t, "redis", evt.Services[0].Name)
	assert.Equal(t, 6379, evt.Services[0].Port)

	var details map[string]string
	require.NoError(t, json.Unmarshal([]byte(BuildEventDetails(m, EventMachineDiscovered)), &details))
	assert.Equal(t, "sha256:feed", details["image_digest"])
	assert.Equal(t, "sha256:cafe", details["image_id"])
	assert.Equal(t, tags[TagContainerID], details["container_id"])
	assert.Equal(t, "cache", details["service_categories"])
	assert.Contains(t, details["services"], `"name":"redis"`)

	// A plain host carries none of it.
	var plain MachineEvent
	plain.FromMachine(Machine{Hostname: "h", Tags: `{"foo":"bar"}`})
	assert.Empty(t, plain.ContainerID)
	assert.Empty(t, plain.ImageDigest)
	assert.Nil(t, plain.Services)
	var plainDetails map[string]string
	require.NoError(t, json.Unmarshal([]byte(BuildEventDetails(Machine{Hostname: "h"}, EventMachineDiscovered)), &plainDetails))
	_, has := plainDetails["services"]
	assert.False(t, has)
}
