package cloud

// azure_more_test.go: coverage for the Azure VM source paths whose endpoints
// are hardcoded (Microsoft identity token endpoint, ARM subscriptions and
// virtualMachines APIs) via the interceptHosts test transport.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	azureLoginHost = "login.microsoftonline.com"
	azureARMHost   = "management.azure.com"
)

// setAzureEnvCreds sets the standard Azure service-principal environment
// variables for the duration of the test.
func setAzureEnvCreds(t *testing.T, subscriptionID string) {
	t.Helper()
	t.Setenv("AZURE_TENANT_ID", "tenant-1")
	t.Setenv("AZURE_CLIENT_ID", "client-1")
	t.Setenv("AZURE_CLIENT_SECRET", "secret-1")
	t.Setenv("AZURE_SUBSCRIPTION_ID", subscriptionID)
}

// azureTokenHandler mimics the Microsoft identity platform token endpoint and
// records the submitted form for assertions.
func azureTokenHandler(token string, gotForm *map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if gotForm != nil {
			_ = req.ParseForm()
			*gotForm = map[string]string{
				"path":          req.URL.Path,
				"grant_type":    req.PostForm.Get("grant_type"),
				"client_id":     req.PostForm.Get("client_id"),
				"client_secret": req.PostForm.Get("client_secret"),
				"scope":         req.PostForm.Get("scope"),
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + token + `","token_type":"Bearer","expires_in":3599}`))
	})
}

func TestAzureName(t *testing.T) {
	assert.Equal(t, "azure_vm", NewAzure().Name())
}

func TestAzureAcquireToken_Success(t *testing.T) {
	var gotForm map[string]string
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("az-tok-1", &gotForm),
	})

	creds := azureCredentials{tenantID: "tenant-1", clientID: "client-1", clientSecret: "secret-1"}
	token, err := (&Azure{}).acquireToken(context.Background(), creds)
	require.NoError(t, err)
	assert.Equal(t, "az-tok-1", token)
	assert.Equal(t, map[string]string{
		"path":          "/tenant-1/oauth2/v2.0/token",
		"grant_type":    "client_credentials",
		"client_id":     "client-1",
		"client_secret": "secret-1",
		"scope":         "https://management.azure.com/.default",
	}, gotForm)
}

func TestAzureAcquireToken_EmptyAccessToken(t *testing.T) {
	interceptHosts(t, hostRoutes{
		azureLoginHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
		}),
	})

	_, err := (&Azure{}).acquireToken(context.Background(), azureCredentials{tenantID: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty access_token")
}

func TestAzureAcquireToken_MalformedJSON(t *testing.T) {
	interceptHosts(t, hostRoutes{
		azureLoginHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`<html>oops</html>`))
		}),
	})

	_, err := (&Azure{}).acquireToken(context.Background(), azureCredentials{tenantID: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding token response")
}

func TestAzureAcquireToken_BadStatus(t *testing.T) {
	interceptHosts(t, hostRoutes{
		azureLoginHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
		}),
	})

	_, err := (&Azure{}).acquireToken(context.Background(), azureCredentials{tenantID: "t"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange")
	assert.Contains(t, err.Error(), "unexpected status 400")
}

func TestAzureListSubscriptions_PaginatesAndFiltersEnabled(t *testing.T) {
	page1 := `{
	  "value": [
	    {"subscriptionId": "sub-1", "state": "Enabled"},
	    {"subscriptionId": "sub-2", "state": "Disabled"}
	  ],
	  "nextLink": "https://management.azure.com/subscriptions?api-version=2022-12-01&page=2"
	}`
	page2 := `{
	  "value": [
	    {"subscriptionId": "sub-3", "state": "enabled"}
	  ]
	}`
	interceptHosts(t, hostRoutes{
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			assert.Equal(t, "Bearer tok-1", req.Header.Get("Authorization"))
			if req.URL.Query().Get("page") == "2" {
				_, _ = w.Write([]byte(page2))
				return
			}
			_, _ = w.Write([]byte(page1))
		}),
	})

	ids, err := (&Azure{}).listSubscriptions(context.Background(), "tok-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1", "sub-3"}, ids,
		"disabled subscriptions must be dropped, state match is case-insensitive")
}

func TestAzureListSubscriptions_AuthError(t *testing.T) {
	interceptHosts(t, hostRoutes{
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("no"))
		}),
	})

	_, err := (&Azure{}).listSubscriptions(context.Background(), "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing subscriptions")

	var ae *authError
	require.ErrorAs(t, err, &ae)
	assert.Equal(t, 401, ae.statusCode)
}

func TestAzureListSubscriptions_MalformedJSON(t *testing.T) {
	interceptHosts(t, hostRoutes{
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`[`))
		}),
	})

	_, err := (&Azure{}).listSubscriptions(context.Background(), "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing subscriptions response")
}

// azureVMListHandler serves the ARM virtualMachines list with one nextLink
// round trip.
func azureVMListHandler() http.Handler {
	page1 := `{
	  "value": [
	    {
	      "name": "vm-east",
	      "location": "eastus",
	      "properties": {
	        "vmId": "id-east",
	        "storageProfile": {"osDisk": {"osType": "Linux"}, "imageReference": {"offer": "UbuntuServer"}}
	      }
	    }
	  ],
	  "nextLink": "https://management.azure.com/vmpage2"
	}`
	page2 := `{
	  "value": [
	    {
	      "name": "vm-west",
	      "location": "westeurope",
	      "properties": {
	        "vmId": "id-west",
	        "storageProfile": {"osDisk": {"osType": "Windows"}, "imageReference": {"offer": "WindowsServer"}}
	      }
	    }
	  ]
	}`
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(req.URL.Path, "/vmpage2") {
			_, _ = w.Write([]byte(page2))
			return
		}
		_, _ = w.Write([]byte(page1))
	})
}

func TestAzureListVirtualMachines_Paginates(t *testing.T) {
	interceptHosts(t, hostRoutes{azureARMHost: azureVMListHandler()})

	vms, err := (&Azure{}).listVirtualMachines(context.Background(), "sub-9", "tok")
	require.NoError(t, err)
	require.Len(t, vms, 2, "nextLink must drive the second page fetch")
	assert.Equal(t, "vm-east", vms[0].name)
	assert.Equal(t, "id-east", vms[0].vmID)
	assert.Equal(t, "vm-west", vms[1].name)
	assert.Equal(t, "Windows", vms[1].osType)
}

func TestAzureFetchVMPage_MalformedJSON(t *testing.T) {
	interceptHosts(t, hostRoutes{
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{{`))
		}),
	})

	_, _, err := (&Azure{}).fetchVMPage(context.Background(),
		"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines", "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing response")
}

func TestAzureFetchVMPage_SkipsUnparseableEntry(t *testing.T) {
	interceptHosts(t, hostRoutes{
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"value": [42, {"name": "vm-ok", "location": "eastus", "properties": {}}]}`))
		}),
	})

	vms, nextLink, err := (&Azure{}).fetchVMPage(context.Background(),
		"https://management.azure.com/subscriptions/s/providers/Microsoft.Compute/virtualMachines", "tok")
	require.NoError(t, err)
	assert.Empty(t, nextLink)
	require.Len(t, vms, 1, "unparseable entry must be skipped, valid entry kept")
	assert.Equal(t, "vm-ok", vms[0].name)
}

func TestParseAzureVM_MalformedJSON(t *testing.T) {
	_, err := parseAzureVM(json.RawMessage(`[1,2`))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unmarshal azure VM")
}

func TestAzureDiscover_FullFlow_RegionFiltered(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("disc-tok", nil),
		azureARMHost:   azureVMListHandler(),
	})

	machines, err := NewAzure().Discover(context.Background(), map[string]any{
		"subscription_id": "sub-9",
		"regions":         []any{"EastUS"},
	})
	require.NoError(t, err)
	require.Len(t, machines, 1, "region filter must be case-insensitive and drop westeurope")

	m := machines[0]
	assert.Equal(t, "vm-east", m.Hostname)
	assert.Equal(t, "linux", m.OSFamily)
	assert.Equal(t, model.MachineTypeCloudInstance, m.MachineType)
	assert.Equal(t, "azure_vm", m.DiscoverySource)
	assert.Equal(t, "eastus", m.Environment)
	assert.Equal(t, model.AuthorizationUnknown, m.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, m.IsManaged)
}

func TestAzureDiscover_EnumeratesSubscriptions(t *testing.T) {
	setAzureEnvCreds(t, "")
	subsJSON := `{"value": [{"subscriptionId": "sub-e1", "state": "Enabled"}]}`
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("disc-tok", nil),
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case strings.Contains(req.URL.Path, "/virtualMachines"):
				assert.Contains(t, req.URL.Path, "/subscriptions/sub-e1/")
				azureVMListHandler().ServeHTTP(w, req)
			case strings.HasSuffix(req.URL.Path, "/vmpage2"):
				azureVMListHandler().ServeHTTP(w, req)
			default:
				_, _ = w.Write([]byte(subsJSON))
			}
		}),
	})

	machines, err := NewAzure().Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	require.Len(t, machines, 2)
	assert.Equal(t, "vm-east", machines[0].Hostname)
	assert.Equal(t, "vm-west", machines[1].Hostname)
	assert.Equal(t, "windows", machines[1].OSFamily)
}

func TestAzureDiscover_NoAccessibleSubscriptions(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("disc-tok", nil),
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"value": []}`))
		}),
	})

	machines, err := NewAzure().Discover(context.Background(), map[string]any{})
	require.NoError(t, err)
	assert.Nil(t, machines, "no accessible subscriptions must skip discovery without error")
}

func TestAzureDiscover_EnumerateSubscriptionsFailure(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("disc-tok", nil),
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}),
	})

	machines, err := NewAzure().Discover(context.Background(), map[string]any{})
	require.NoError(t, err, "enumerate failure degrades gracefully")
	assert.Nil(t, machines)
}

func TestAzureDiscover_TokenFailureErrorsWhenConfigured(t *testing.T) {
	setAzureEnvCreds(t, "sub-9")
	interceptHosts(t, hostRoutes{
		azureLoginHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("bad client"))
		}),
	})

	_, err := NewAzure().Discover(context.Background(), map[string]any{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to acquire OAuth2 token")
}

func TestAzureDiscover_TokenFailureSkipsWhenUnconfigured(t *testing.T) {
	setAzureEnvCreds(t, "sub-9")
	interceptHosts(t, hostRoutes{
		azureLoginHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}),
	})

	machines, err := NewAzure().Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, machines)
}

func TestAzureDiscover_ListVMsFailureReturnsPartial(t *testing.T) {
	setAzureEnvCreds(t, "")
	interceptHosts(t, hostRoutes{
		azureLoginHost: azureTokenHandler("disc-tok", nil),
		azureARMHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("denied"))
		}),
	})

	machines, err := NewAzure().Discover(context.Background(), map[string]any{
		"subscription_id": "sub-9",
	})
	require.NoError(t, err, "per-subscription VM list failure must not abort discovery")
	assert.Empty(t, machines)
}

func TestAzureDiscover_NilConfigNoCredsSkips(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_CLIENT_SECRET", "")
	t.Setenv("AZURE_SUBSCRIPTION_ID", "")

	machines, err := NewAzure().Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, machines)
}
