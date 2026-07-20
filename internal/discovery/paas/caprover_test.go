package paas

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

func newMockCapRoverAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v2/user/apps/appDefinitions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-captain-auth") != "test-caprover-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
  "status": 100,
  "description": "success",
  "data": {
    "appDefinitions": [
      {
        "appName": "my-app",
        "hasPersistentData": false,
        "instanceCount": 2,
        "isAppBuilding": false
      },
      {
        "appName": "db-app",
        "hasPersistentData": true,
        "instanceCount": 1,
        "isAppBuilding": true
      }
    ]
  }
}`))
	})

	return httptest.NewServer(mux)
}

func TestCapRover_Name(t *testing.T) {
	assert.Equal(t, "caprover", NewCapRover().Name())
}

func TestCapRover_Discover_Success(t *testing.T) {
	srv := newMockCapRoverAPI(t)
	defer srv.Close()

	t.Setenv("KITE_CAPROVER_TOKEN", "test-caprover-token")

	cr := NewCapRover()
	cr.baseURL = srv.URL
	machines, err := cr.Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Len(t, machines, 2)

	myApp := findMachineByHostname(machines, "my-app")
	require.NotNil(t, myApp)
	assert.Equal(t, model.MachineTypeContainer, myApp.MachineType)
	assert.Equal(t, "caprover", myApp.DiscoverySource)
	assert.NotEmpty(t, myApp.NaturalKey)

	var myTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(myApp.Tags), &myTags))
	assert.Equal(t, "caprover", myTags["platform"])
	assert.Equal(t, float64(2), myTags["instance_count"])
	assert.Equal(t, false, myTags["persistent_data"])
	assert.NotContains(t, myTags, "building")

	// Building app gets building tag.
	dbApp := findMachineByHostname(machines, "db-app")
	require.NotNil(t, dbApp)
	var dbTags map[string]any
	require.NoError(t, json.Unmarshal([]byte(dbApp.Tags), &dbTags))
	assert.Equal(t, true, dbTags["building"])
	assert.Equal(t, true, dbTags["persistent_data"])
}

func TestCapRover_Discover_MissingCredentials(t *testing.T) {
	t.Setenv("KITE_CAPROVER_TOKEN", "")
	t.Setenv("KITE_CAPROVER_ENDPOINT", "")

	cr := NewCapRover()

	_, err := cr.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KITE_CAPROVER_TOKEN")

	machines, err := cr.Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, machines)
}

func TestCapRover_Discover_AuthFailure(t *testing.T) {
	srv := newMockCapRoverAPI(t)
	defer srv.Close()

	t.Setenv("KITE_CAPROVER_TOKEN", "wrong-token")

	cr := NewCapRover()
	cr.baseURL = srv.URL
	_, err := cr.Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication error")
}
