package enrollment

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func deviceResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(body))}
}

func TestDeviceEnrollmentPollsThenIssuesCertificate(t *testing.T) {
	t.Setenv("KITE_PKI_ENDPOINT", "https://pki.example")
	client := NewClient(nil)
	polls := 0
	shown := false
	var waits []time.Duration
	client.http = &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/oauth/device/code":
			require.NoError(t, req.ParseForm())
			require.Equal(t, "kite-server", req.Form.Get("agent_code"))
			return deviceResponse(200, `{"device_code":"private-device-code","user_code":"KITE-ABCD-EFGH","verification_uri":"https://app.example/device","expires_in":600,"interval":5}`), nil
		case "/oauth/token":
			require.True(t, shown)
			require.NoError(t, req.ParseForm())
			require.Equal(t, "private-device-code", req.Form.Get("device_code"))
			require.Equal(t, "urn:ietf:params:oauth:grant-type:device_code", req.Form.Get("grant_type"))
			polls++
			if polls == 1 {
				return deviceResponse(400, `{"error":"authorization_pending"}`), nil
			}
			if polls == 2 {
				return deviceResponse(400, `{"error":"slow_down"}`), nil
			}
			return deviceResponse(200, `{"access_token":"private-token","token_type":"Bearer"}`), nil
		case "/pki/enroll/device":
			require.Equal(t, "Bearer private-token", req.Header.Get("Authorization"))
			var body map[string]string
			require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
			require.Equal(t, "kite-server", body["agent_code"])
			return issueEnrollmentResponse(t, body["csr_pem"], nil), nil
		default:
			t.Fatalf("unexpected request: %s", req.URL.Path)
			return nil, nil
		}
	}}
	result, err := client.enrollDevice(context.Background(), "kite-server", func(auth DeviceAuthorization) error {
		shown = true
		require.Equal(t, "KITE-ABCD-EFGH", auth.UserCode)
		encoded, err := json.Marshal(auth)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "private-device-code")
		return nil
	}, func(_ context.Context, delay time.Duration) error { waits = append(waits, delay); return nil })
	require.NoError(t, err)
	require.NotEmpty(t, result.ClientCertificate)
	require.NotEmpty(t, result.ClientKey)
	require.Equal(t, []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second}, waits)
}

func TestDeviceEnrollmentStopsOnDenialExpiryAndInvalidResponses(t *testing.T) {
	for _, oauthError := range []string{"access_denied", "expired_token", "invalid_grant"} {
		t.Run(oauthError, func(t *testing.T) {
			client := NewClient(nil)
			calls := 0
			client.http = &callbackDoer{do: func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return deviceResponse(200, `{"device_code":"secret","user_code":"KITE-ABCD-EFGH","verification_uri":"https://app.example/device","expires_in":600}`), nil
				}
				return deviceResponse(400, `{"error":"`+oauthError+`","error_description":"secret"}`), nil
			}}
			_, err := client.enrollDevice(context.Background(), "kite-server", func(DeviceAuthorization) error { return nil }, func(context.Context, time.Duration) error { return nil })
			require.Error(t, err)
			require.NotContains(t, err.Error(), "secret")
			require.Equal(t, 2, calls)
		})
	}
}

func TestDeviceEnrollmentCancellationAndHTTPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, deviceWait(ctx, time.Hour), context.Canceled)
	t.Setenv("KITE_PKI_ENDPOINT", "http://pki.example")
	_, err := NewClient(nil).EnrollDevice(ctx, "kite-server", func(DeviceAuthorization) error { t.Fatal("must not display a request"); return nil })
	require.ErrorContains(t, err, "HTTPS")
}
