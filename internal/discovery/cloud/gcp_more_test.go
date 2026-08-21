package cloud

// gcp_more_test.go: coverage for the GCP Compute source paths whose endpoints
// are hardcoded (metadata server, OAuth2 token exchange, aggregatedList) via
// the interceptHosts test transport, plus pure-helper edge cases.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	gcpMetadataHost = "metadata.google.internal"
	gcpOAuthHost    = "oauth2.googleapis.com"
	gcpComputeHost  = "compute.googleapis.com"
)

// gcpMetadataTokenHandler mimics the GCE metadata token endpoint, recording
// whether the mandatory Metadata-Flavor header was sent.
func gcpMetadataTokenHandler(token string, sawFlavor *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if sawFlavor != nil {
			*sawFlavor = req.Header.Get("Metadata-Flavor") == "Google"
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + token + `","token_type":"Bearer"}`))
	})
}

func TestGCPName(t *testing.T) {
	assert.Equal(t, "gcp_compute", NewGCP().Name())
}

func TestTruncateBytes(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		maxLen   int
		expected string
	}{
		{"under limit", "abc", 5, "abc"},
		{"exactly at limit", "abcde", 5, "abcde"},
		{"one over limit", "abcdef", 5, "abcde..."},
		{"empty", "", 5, ""},
		{"zero limit", "abc", 0, "..."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, truncateBytes([]byte(tc.data), tc.maxLen))
		})
	}
}

func TestTokenFromMetadata_Success(t *testing.T) {
	var sawFlavor bool
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("meta-tok-123", &sawFlavor),
	})

	token, err := tokenFromMetadata(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "meta-tok-123", token)
	assert.True(t, sawFlavor, "request must carry Metadata-Flavor: Google")
}

func TestTokenFromMetadata_Non200(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}),
	})

	_, err := tokenFromMetadata(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata server returned 404")
}

func TestTokenFromMetadata_MalformedJSON(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`not-json`))
		}),
	})

	_, err := tokenFromMetadata(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding metadata token")
}

func TestTokenFromMetadata_Unreachable(t *testing.T) {
	interceptHosts(t, hostRoutes{}) // no route: connection refused equivalent

	_, err := tokenFromMetadata(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata request")
}

// writeGCPCredFile writes a credentials JSON file into a temp dir and returns
// its path.
func writeGCPCredFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adc.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestTokenFromCredentialsFile_Success(t *testing.T) {
	var gotForm map[string]string
	interceptHosts(t, hostRoutes{
		gcpOAuthHost: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			require.NoError(t, req.ParseForm())
			gotForm = map[string]string{
				"grant_type":    req.PostForm.Get("grant_type"),
				"refresh_token": req.PostForm.Get("refresh_token"),
				"client_id":     req.PostForm.Get("client_id"),
				"client_secret": req.PostForm.Get("client_secret"),
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"file-tok-456"}`))
		}),
	})

	path := writeGCPCredFile(t, `{
		"type": "authorized_user",
		"client_id": "cid-1",
		"client_secret": "csec-1",
		"refresh_token": "rtok-1"
	}`)

	token, err := tokenFromCredentialsFile(context.Background(), path)
	require.NoError(t, err)
	assert.Equal(t, "file-tok-456", token)
	assert.Equal(t, map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "rtok-1",
		"client_id":     "cid-1",
		"client_secret": "csec-1",
	}, gotForm)
}

func TestTokenFromCredentialsFile_MissingFile(t *testing.T) {
	_, err := tokenFromCredentialsFile(context.Background(), filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading credentials file")
}

func TestTokenFromCredentialsFile_MalformedJSON(t *testing.T) {
	path := writeGCPCredFile(t, `{not json`)
	_, err := tokenFromCredentialsFile(context.Background(), path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing credentials file")
}

func TestTokenFromCredentialsFile_UnsupportedType(t *testing.T) {
	path := writeGCPCredFile(t, `{"type":"service_account"}`)
	_, err := tokenFromCredentialsFile(context.Background(), path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported credential type "service_account"`)
}

func TestTokenFromCredentialsFile_IncompleteCredentials(t *testing.T) {
	path := writeGCPCredFile(t, `{"type":"authorized_user","client_id":"cid"}`)
	_, err := tokenFromCredentialsFile(context.Background(), path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "incomplete authorized_user credentials")
}

func TestTokenFromCredentialsFile_TokenExchangeNon200(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpOAuthHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		}),
	})

	path := writeGCPCredFile(t, `{
		"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"
	}`)
	_, err := tokenFromCredentialsFile(context.Background(), path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token exchange returned 400")
	assert.Contains(t, err.Error(), "invalid_grant")
}

func TestTokenFromCredentialsFile_TokenExchangeMalformedJSON(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpOAuthHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`}{`))
		}),
	})

	path := writeGCPCredFile(t, `{
		"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"
	}`)
	_, err := tokenFromCredentialsFile(context.Background(), path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decoding token response")
}

func TestObtainGCPToken_FromMetadata(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("meta-first", nil),
	})

	token, err := obtainGCPToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "meta-first", token)
}

func TestObtainGCPToken_FallsBackToCredentialsFile(t *testing.T) {
	interceptHosts(t, hostRoutes{
		// metadata.google.internal deliberately unrouted -> attempt 1 fails.
		gcpOAuthHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"access_token":"from-file"}`))
		}),
	})

	path := writeGCPCredFile(t, `{
		"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"
	}`)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)

	token, err := obtainGCPToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "from-file", token)
}

func TestObtainGCPToken_NoCredentialsAnywhere(t *testing.T) {
	interceptHosts(t, hostRoutes{}) // metadata unreachable
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))

	_, err := obtainGCPToken(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no GCP credentials available")
}

// gcpComputeHandler serves the aggregatedList (with one pageToken round trip)
// and per-disk resources used by the Discover flow tests.
func gcpComputeHandler(t *testing.T) http.Handler {
	t.Helper()
	page1 := `{
	  "items": {
	    "zones/us-central1-a": {
	      "instances": [
	        {
	          "name": "web-1",
	          "zone": "projects/proj-x/zones/us-central1-a",
	          "disks": [
	            {"source": "projects/proj-x/zones/us-central1-a/disks/web-1-boot", "boot": true}
	          ]
	        }
	      ]
	    }
	  },
	  "nextPageToken": "tok-2"
	}`
	page2 := `{
	  "items": {
	    "zones/europe-west1-b": {
	      "instances": [
	        {
	          "name": "db-1",
	          "zone": "projects/proj-x/zones/europe-west1-b",
	          "disks": [
	            {"source": "projects/proj-x/zones/europe-west1-b/disks/db-1-boot", "boot": true}
	          ]
	        }
	      ]
	    }
	  }
	}`
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(req.URL.Path, "/aggregated/instances"):
			if req.URL.Query().Get("pageToken") == "tok-2" {
				_, _ = w.Write([]byte(page2))
				return
			}
			assert.Equal(t, "status=RUNNING", req.URL.Query().Get("filter"))
			_, _ = w.Write([]byte(page1))
		case strings.Contains(req.URL.Path, "/disks/web-1-boot"):
			_, _ = w.Write([]byte(`{"sourceImage":"projects/debian-cloud/global/images/debian-12-v20260101"}`))
		case strings.Contains(req.URL.Path, "/disks/db-1-boot"):
			_, _ = w.Write([]byte(`{"sourceImage":"projects/windows-cloud/global/images/windows-server-2022-dc"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestListAggregatedInstances_Paginates(t *testing.T) {
	interceptHosts(t, hostRoutes{gcpComputeHost: gcpComputeHandler(t)})

	instances, err := NewGCP().listAggregatedInstances(context.Background(), "proj-x", "tok")
	require.NoError(t, err)
	require.Len(t, instances, 2, "both pages must be fetched via pageToken")
	assert.Equal(t, "web-1", instances[0].name)
	assert.Equal(t, "db-1", instances[1].name)
}

func TestListAggregatedInstances_ErrorOnBadStatus(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpComputeHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad request"))
		}),
	})

	_, err := NewGCP().listAggregatedInstances(context.Background(), "proj-x", "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 400")
}

func TestFetchInstancePage_MalformedJSON(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpComputeHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{{{`))
		}),
	})

	_, _, err := NewGCP().fetchInstancePage(context.Background(),
		"https://compute.googleapis.com/compute/v1/projects/p/aggregated/instances", "tok")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing response")
}

func TestFetchInstancePage_SkipsUnparseableZoneEntry(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpComputeHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// One zone entry is a bare number (unmarshal fails and is skipped);
			// the other is valid and must survive.
			_, _ = w.Write([]byte(`{
			  "items": {
			    "zones/bad": 42,
			    "zones/ok": {"instances": [{"name": "vm-ok", "zone": "projects/p/zones/us-east1-b"}]}
			  }
			}`))
		}),
	})

	instances, nextURL, err := NewGCP().fetchInstancePage(context.Background(),
		"https://compute.googleapis.com/compute/v1/projects/p/aggregated/instances", "tok")
	require.NoError(t, err)
	assert.Empty(t, nextURL)
	require.Len(t, instances, 1)
	assert.Equal(t, "vm-ok", instances[0].name)
}

func TestEnrichOSFromDisk(t *testing.T) {
	interceptHosts(t, hostRoutes{gcpComputeHost: gcpComputeHandler(t)})
	gcp := NewGCP()
	ctx := context.Background()

	t.Run("no disks defaults to linux", func(t *testing.T) {
		assert.Equal(t, "linux", gcp.enrichOSFromDisk(ctx, gcpInstance{}, "tok"))
	})

	t.Run("boot disk source image wins", func(t *testing.T) {
		inst := gcpInstance{disks: []gcpDisk{
			{source: "projects/proj-x/zones/europe-west1-b/disks/db-1-boot", boot: true},
		}}
		assert.Equal(t, "windows", gcp.enrichOSFromDisk(ctx, inst, "tok"))
	})

	t.Run("non-boot first disk used when no boot disk", func(t *testing.T) {
		inst := gcpInstance{disks: []gcpDisk{
			{source: "projects/proj-x/zones/us-central1-a/disks/web-1-boot", boot: false},
		}}
		assert.Equal(t, "linux", gcp.enrichOSFromDisk(ctx, inst, "tok"))
	})

	t.Run("fetch failure falls back to URL heuristic", func(t *testing.T) {
		inst := gcpInstance{disks: []gcpDisk{
			{source: "projects/proj-x/zones/z/disks/windows-server-2022", boot: true},
		}}
		// The disk path is unknown to the handler (404) so the sourceImage is
		// empty and the disk-URL heuristic must classify it as windows.
		assert.Equal(t, "windows", gcp.enrichOSFromDisk(ctx, inst, "tok"))
	})
}

func TestGuessOSFromDisks_AllHeuristics(t *testing.T) {
	linuxSources := []string{
		"disks/rhel-9", "disks/red-hat-8", "disks/centos-7", "disks/debian-12",
		"disks/ubuntu-2404", "disks/suse-x", "disks/sles-15", "disks/cos-109",
		"disks/container-optimized-1", "disks/fedora-40", "disks/rocky-9", "disks/alma-9",
	}
	for _, src := range linuxSources {
		t.Run(src, func(t *testing.T) {
			assert.Equal(t, "linux", guessOSFromDisks([]gcpDisk{{source: src}}))
		})
	}
	t.Run("unmatched source defaults to linux", func(t *testing.T) {
		assert.Equal(t, "linux", guessOSFromDisks([]gcpDisk{{source: "disks/mystery-os"}}))
	})
}

func TestGCPDiscover_FullFlow_RegionFiltered(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("disc-tok", nil),
		gcpComputeHost:  gcpComputeHandler(t),
	})

	machines, err := NewGCP().Discover(context.Background(), map[string]any{
		"project": "proj-x",
		"regions": []any{"us-central1"},
	})
	require.NoError(t, err)
	require.Len(t, machines, 1, "europe-west1 instance must be filtered out")

	m := machines[0]
	assert.Equal(t, "web-1", m.Hostname)
	assert.Equal(t, "linux", m.OSFamily)
	assert.Equal(t, model.MachineTypeCloudInstance, m.MachineType)
	assert.Equal(t, "gcp_compute", m.DiscoverySource)
	assert.Equal(t, "projects/proj-x/zones/us-central1-a", m.Environment)
	assert.Equal(t, model.AuthorizationUnknown, m.IsAuthorized)
	assert.Equal(t, model.ManagedUnknown, m.IsManaged)
}

func TestGCPDiscover_FullFlow_AllRegions(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("disc-tok", nil),
		gcpComputeHost:  gcpComputeHandler(t),
	})

	machines, err := NewGCP().Discover(context.Background(), map[string]any{
		"project": "proj-x",
	})
	require.NoError(t, err)
	require.Len(t, machines, 2)
	assert.Equal(t, "web-1", machines[0].Hostname)
	assert.Equal(t, "linux", machines[0].OSFamily)
	assert.Equal(t, "db-1", machines[1].Hostname)
	assert.Equal(t, "windows", machines[1].OSFamily, "windows source image must map to windows")
}

func TestGCPDiscover_NilConfigSkips(t *testing.T) {
	machines, err := NewGCP().Discover(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, machines)
}

func TestGCPDiscover_TokenFailureErrorsWhenConfigured(t *testing.T) {
	interceptHosts(t, hostRoutes{}) // metadata unreachable
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))

	_, err := NewGCP().Discover(context.Background(), map[string]any{"project": "proj-x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not obtain access token")
}

func TestGCPDiscover_ListInstancesFailure(t *testing.T) {
	interceptHosts(t, hostRoutes{
		gcpMetadataHost: gcpMetadataTokenHandler("disc-tok", nil),
		gcpComputeHost: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("denied"))
		}),
	})

	_, err := NewGCP().Discover(context.Background(), map[string]any{"project": "proj-x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listing instances")
}
