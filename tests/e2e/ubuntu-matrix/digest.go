package ubuntumatrix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Manifest media types the registry must consider. Listing the index types
// first matters: without them a registry answers with the platform-specific
// manifest, whose digest is *not* the digest `ubuntu:22.04` resolves to, and
// the drift check would report a difference on every single run.
const manifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

const (
	defaultRegistryHost = "docker.io"
	dockerRegistryBase  = "https://registry-1.docker.io"
	registryTimeout     = 30 * time.Second
)

// RegistryClient resolves the digest a floating tag currently points at.
// Deliberately built on net/http rather than a registry SDK: RFC-0149 §6.5
// introduces no new third-party Go dependency, and the anonymous pull-token
// flow is a dozen lines.
type RegistryClient struct {
	HTTP *http.Client
	// BaseURL overrides the derived registry endpoint. Set by tests.
	BaseURL string
}

// NewRegistryClient returns a client with a bounded timeout.
func NewRegistryClient() *RegistryClient {
	return &RegistryClient{HTTP: &http.Client{Timeout: registryTimeout}}
}

// SplitRepository splits "docker.io/library/ubuntu" into its registry host
// and repository path, defaulting to Docker Hub when no host is present.
func SplitRepository(repository string) (host, path string) {
	parts := strings.SplitN(repository, "/", 2)
	if len(parts) == 2 && strings.ContainsAny(parts[0], ".:") {
		return parts[0], parts[1]
	}
	if !strings.Contains(repository, "/") {
		return defaultRegistryHost, "library/" + repository
	}
	return defaultRegistryHost, repository
}

func (c *RegistryClient) baseURL(host string) string {
	if c.BaseURL != "" {
		return strings.TrimSuffix(c.BaseURL, "/")
	}
	if host == defaultRegistryHost {
		return dockerRegistryBase
	}
	return "https://" + host
}

func (c *RegistryClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: registryTimeout}
}

// ResolveTagDigest returns the current `sha256:...` digest for a tag.
//
// Used only by the weekly scheduled drift-check, never on the PR path: a
// per-PR registry round trip would add Docker Hub rate-limit exposure to
// every push for a signal that changes at most a few times a month.
func (c *RegistryClient) ResolveTagDigest(ctx context.Context, repository, tag string) (string, error) {
	host, path := SplitRepository(repository)
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", c.baseURL(host), path, tag)

	digest, challenge, err := c.headManifest(ctx, url, "")
	if err != nil {
		return "", err
	}
	if digest != "" {
		return digest, nil
	}
	if challenge == "" {
		return "", fmt.Errorf("registry %s: no Docker-Content-Digest and no auth challenge", url)
	}

	token, err := c.fetchToken(ctx, challenge)
	if err != nil {
		return "", err
	}
	digest, _, err = c.headManifest(ctx, url, token)
	if err != nil {
		return "", err
	}
	if digest == "" {
		return "", fmt.Errorf("registry %s: authenticated request returned no digest", url)
	}
	return digest, nil
}

// headManifest issues a HEAD and returns either the digest or, on a 401, the
// Www-Authenticate challenge to satisfy.
func (c *RegistryClient) headManifest(
	ctx context.Context, url, token string,
) (digest, challenge string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", "", fmt.Errorf("build manifest request: %w", err)
	}
	req.Header.Set("Accept", manifestAccept)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", "", fmt.Errorf("head manifest %s: %w", url, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", resp.Header.Get("Www-Authenticate"), nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("head manifest %s: unexpected status %d", url, resp.StatusCode)
	}
	return resp.Header.Get("Docker-Content-Digest"), "", nil
}

// fetchToken satisfies a `Bearer realm=...,service=...,scope=...` challenge
// with an anonymous pull token. No credentials are involved: the matrix only
// ever pulls public official images (§6.3).
func (c *RegistryClient) fetchToken(ctx context.Context, challenge string) (string, error) {
	params := parseChallenge(challenge)
	realm := params["realm"]
	if realm == "" {
		return "", fmt.Errorf("auth challenge %q has no realm", challenge)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm, nil)
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	q := req.URL.Query()
	for _, key := range []string{"service", "scope"} {
		if v := params[key]; v != "" {
			q.Set(key, v)
		}
	}
	req.URL.RawQuery = q.Encode()

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch registry token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch registry token: unexpected status %d", resp.StatusCode)
	}

	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("decode registry token: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("registry token response carried no token")
}

// parseChallenge turns `Bearer realm="https://…",service="…"` into a map.
func parseChallenge(challenge string) map[string]string {
	out := map[string]string{}
	rest := strings.TrimSpace(challenge)
	if scheme, params, ok := strings.Cut(rest, " "); ok && strings.EqualFold(scheme, "Bearer") {
		rest = params
	}
	for _, part := range strings.Split(rest, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(key)] = strings.Trim(strings.TrimSpace(value), `"`)
	}
	return out
}
