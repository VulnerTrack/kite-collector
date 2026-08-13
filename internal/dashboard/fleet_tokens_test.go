package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFleetHTTPTokenIssuer_MintsScopedBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/pki/tokens/batch", r.URL.Path)
		assert.Equal(t, "Bearer operator-jwt", r.Header.Get("Authorization"))
		var request struct {
			AgentCodes []string `json:"agent_codes"`
			TTLHours   int      `json:"ttl_hours"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		assert.Equal(t, []string{"kite-a", "kite-b"}, request.AgentCodes)
		assert.Equal(t, 2, request.TTLHours)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"tokens":[` +
			`{"agent_code":"kite-a","token":"pki_enroll_v1_token-a-secret","token_id":"id-a"},` +
			`{"agent_code":"kite-b","token":"pki_enroll_v1_token-b-secret","token_id":"id-b"}]}`))
	}))
	defer server.Close()

	issuer := newFleetHTTPTokenIssuer()
	issued, err := issuer.MintBatch(
		context.Background(), server.URL, "operator-jwt", []string{"kite-a", "kite-b"},
	)
	require.NoError(t, err)
	assert.Equal(t, "pki_enroll_v1_token-a-secret", issued["kite-a"].Token)
	assert.Equal(t, "id-b", issued["kite-b"].TokenID)
}

func TestFleetPackageService_MapsCredentialsToHostnames(t *testing.T) {
	service := &fleetPackageService{
		issuer: fakeFleetTokenIssuer{},
		operatorToken: func(context.Context) (string, error) {
			return "operator-jwt", nil
		},
	}
	targets := []fleetTarget{
		{Hostname: "pc-a.example.test", OS: "windows", Arch: "amd64"},
		{Hostname: "srv-b.example.test", OS: "linux", Arch: "amd64"},
	}
	tokens, err := service.issueTokens(context.Background(), "https://pki.example.test", targets)
	require.NoError(t, err)
	assert.Contains(t, tokens["pc-a.example.test"], fleetAgentCode("pc-a.example.test"))
	assert.Contains(t, tokens["srv-b.example.test"], fleetAgentCode("srv-b.example.test"))
}
