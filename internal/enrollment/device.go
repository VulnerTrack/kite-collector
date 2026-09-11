package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DeviceAuthorization contains only the values shown to the operator.
// The secret device code and access token stay in memory inside EnrollDevice.
type DeviceAuthorization struct {
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// deviceVerificationURI is the public browser route shown to SSH operators.
// Keep this client-side value stable so enrollment does not depend on a stale
// or misconfigured URI returned by a PKI deployment.
const deviceVerificationURI = "https://app.vulnertrack.com/auth/device/"

var (
	deviceUserCodePattern            = regexp.MustCompile(`^KITE-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$`)
	deviceAuthorizationTicketPattern = regexp.MustCompile(`^v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{32,512}$`)
)

func deviceWait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("polling canceled: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// EnrollDevice implements RFC 8628 using outbound HTTPS only.
func (c *Client) EnrollDevice(ctx context.Context, agentCode string, display func(DeviceAuthorization) error) (*Result, error) {
	return c.enrollDevice(ctx, agentCode, display, deviceWait)
}

func (c *Client) enrollDevice(ctx context.Context, agentCode string, display func(DeviceAuthorization) error, wait func(context.Context, time.Duration) error) (*Result, error) {
	base := pkiBaseURL()
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("device enrollment requires an HTTPS KITE_PKI_ENDPOINT")
	}
	// Do not forward a grant or JWT through an HTTP redirect.
	client := *c
	if c.http == nil || c.http == http.DefaultClient {
		client.http = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	var authorization struct {
		DeviceAuthorization
		DeviceCode string `json:"device_code"`
	}
	status, err := client.devicePost(ctx, base+"/oauth/device/code", url.Values{
		"client_id": {"kite-collector"}, "agent_code": {agentCode}, "scope": {"openid enrollment"},
	}, &authorization)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("device authorization returned HTTP %d", status)
	}
	verify, err := url.Parse(authorization.VerificationURI)
	completeResponse, completeErr := url.Parse(authorization.VerificationURIComplete)
	ticket := ""
	if completeErr == nil && completeResponse != nil {
		ticket = completeResponse.Query().Get("authorization")
	}
	if err != nil || completeErr != nil || verify.Scheme != "https" || verify.Host == "" || verify.User != nil || completeResponse.Scheme != "https" || completeResponse.Host != verify.Host || completeResponse.Path != verify.Path || completeResponse.User != nil || len(ticket) < 32 || len(ticket) > 1024 || !deviceAuthorizationTicketPattern.MatchString(ticket) || !deviceUserCodePattern.MatchString(authorization.UserCode) || authorization.DeviceCode == "" || authorization.ExpiresIn <= 0 || authorization.ExpiresIn > 3600 || authorization.Interval < 0 || authorization.Interval > 3600 {
		return nil, fmt.Errorf("invalid device authorization response")
	}
	authorization.VerificationURI = deviceVerificationURI
	complete, err := url.Parse(deviceVerificationURI)
	if err != nil {
		return nil, fmt.Errorf("invalid device verification URL")
	}
	query := complete.Query()
	query.Set("authorization", ticket)
	complete.RawQuery = query.Encode()
	authorization.VerificationURIComplete = complete.String()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(authorization.ExpiresIn)*time.Second)
	defer cancel()
	if displayErr := display(authorization.DeviceAuthorization); displayErr != nil {
		return nil, displayErr
	}
	interval := time.Duration(authorization.Interval) * time.Second
	if interval == 0 {
		interval = 5 * time.Second
	}
	for {
		if waitErr := wait(ctx, interval); waitErr != nil {
			return nil, fmt.Errorf("device authorization stopped: %w", waitErr)
		}
		var response struct {
			Token
			Error string `json:"error"`
		}
		status, err = client.devicePost(ctx, base+"/oauth/token", url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":  {"kite-collector"}, "device_code": {authorization.DeviceCode},
		}, &response)
		if err != nil {
			var timeout net.Error
			if ctx.Err() == nil && errors.As(err, &timeout) && timeout.Timeout() {
				interval *= 2
				continue
			}
			return nil, err
		}
		if status == http.StatusOK {
			if response.AccessToken == "" || !strings.EqualFold(response.TokenType, "Bearer") {
				return nil, fmt.Errorf("invalid device access token response")
			}
			result, err := client.enrollAt(ctx, agentCode, response.AccessToken, base+"/pki/enroll/device")
			if err != nil {
				return nil, err
			}
			if result.Status != "enrolled" {
				return nil, fmt.Errorf("device certificate was not issued")
			}
			return result, nil
		}
		if status != http.StatusBadRequest {
			return nil, fmt.Errorf("device token endpoint returned HTTP %d", status)
		}
		switch response.Error {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return nil, fmt.Errorf("device authorization was denied")
		case "expired_token":
			return nil, fmt.Errorf("device authorization expired; run enroll again")
		default:
			return nil, fmt.Errorf("device authorization failed (HTTP %d)", status)
		}
	}
}

func (c *Client) devicePost(ctx context.Context, endpoint string, form url.Values, result any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, fmt.Errorf("device authorization request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("device authorization request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(result); err != nil {
		return resp.StatusCode, fmt.Errorf("invalid device authorization response (HTTP %d)", resp.StatusCode)
	}
	return resp.StatusCode, nil
}
