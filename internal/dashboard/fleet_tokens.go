package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var errFleetSignInRequired = errors.New("VulnerTrack sign-in required")

// FleetEnrollmentToken is a one-time PKI credential scoped to one collector.
// The plaintext Token exists only long enough to write the confidential ZIP.
type FleetEnrollmentToken struct {
	Token     string
	TokenID   string
	ExpiresAt string
}

// FleetEnrollmentTokenIssuer allows the dashboard to mint and roll back
// short-lived, per-computer enrollment credentials.
type FleetEnrollmentTokenIssuer interface {
	MintBatch(ctx context.Context, endpoint, operatorToken string, agentCodes []string) (map[string]FleetEnrollmentToken, error)
}

type fleetHTTPTokenIssuer struct {
	client *http.Client
}

type fleetPackageService struct {
	issuer        FleetEnrollmentTokenIssuer
	operatorToken func(context.Context) (string, error)
}

func (s *fleetPackageService) issueTokens(
	ctx context.Context,
	endpoint string,
	targets []fleetTarget,
) (map[string]string, error) {
	if s == nil || s.operatorToken == nil {
		return nil, errFleetSignInRequired
	}
	operatorToken, err := s.operatorToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errFleetSignInRequired, err)
	}
	issuer := s.issuer
	if issuer == nil {
		issuer = newFleetHTTPTokenIssuer()
	}
	agentCodes := make([]string, 0, len(targets))
	hostByAgentCode := make(map[string]string, len(targets))
	for _, target := range targets {
		agentCode := fleetAgentCode(target.Hostname)
		agentCodes = append(agentCodes, agentCode)
		hostByAgentCode[agentCode] = target.Hostname
	}
	issued, err := issuer.MintBatch(ctx, endpoint, operatorToken, agentCodes)
	if err != nil {
		return nil, fmt.Errorf("create short-lived fleet credentials: %w", err)
	}
	tokens := make(map[string]string, len(targets))
	for agentCode, hostname := range hostByAgentCode {
		credential, ok := issued[agentCode]
		if !ok || credential.Token == "" {
			return nil, fmt.Errorf("PKI did not issue a credential for %s", hostname)
		}
		tokens[hostname] = credential.Token
	}
	return tokens, nil
}

func newFleetHTTPTokenIssuer() *fleetHTTPTokenIssuer {
	return &fleetHTTPTokenIssuer{client: &http.Client{Timeout: 15 * time.Second}}
}

func (i *fleetHTTPTokenIssuer) MintBatch(
	ctx context.Context,
	endpoint, operatorToken string,
	agentCodes []string,
) (map[string]FleetEnrollmentToken, error) {
	body, err := json.Marshal(map[string]any{
		"agent_codes": agentCodes,
		"ttl_hours":   2,
	})
	if err != nil {
		return nil, fmt.Errorf("encode PKI token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(endpoint, "/")+"/pki/tokens/batch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create PKI token request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := i.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request enrollment tokens: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if readErr != nil {
		return nil, fmt.Errorf("read PKI token response: %w", readErr)
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PKI rejected token creation (%s)", resp.Status)
	}
	var result struct {
		Tokens []struct {
			Token     string `json:"token"`
			TokenID   string `json:"token_id"`
			AgentCode string `json:"agent_code"`
			ExpiresAt string `json:"expires_at"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("decode PKI token response: %w", err)
	}
	issued := make(map[string]FleetEnrollmentToken, len(result.Tokens))
	for _, token := range result.Tokens {
		if len(strings.TrimSpace(token.Token)) < 20 || strings.TrimSpace(token.TokenID) == "" || token.AgentCode == "" {
			return nil, fmt.Errorf("PKI returned an incomplete enrollment token")
		}
		issued[token.AgentCode] = FleetEnrollmentToken{
			Token: strings.TrimSpace(token.Token), TokenID: token.TokenID, ExpiresAt: token.ExpiresAt,
		}
	}
	if len(issued) != len(agentCodes) {
		return nil, fmt.Errorf("PKI returned %d tokens for %d computers", len(issued), len(agentCodes))
	}
	return issued, nil
}
