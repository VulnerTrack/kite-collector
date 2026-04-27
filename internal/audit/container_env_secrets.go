package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	dockerdisc "github.com/vulnertrack/kite-collector/internal/discovery/docker"
	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	containerEnvSecretsAuditorName = "container_env_secrets"

	// CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
	containerEnvSecretsCWEID   = "CWE-526"
	containerEnvSecretsCWEName = "Cleartext Storage of Sensitive Information in an Environment Variable"

	// containerEnvSecretsExpected is the security baseline message included
	// in every finding's Expected field.
	containerEnvSecretsExpected = "No credentials in container environment variables"

	// CIS Controls 3.11 (Encrypt Sensitive Data at Rest) and 14.8 (Use of
	// Secure Authentication Mechanism) cover this finding category.
	containerEnvSecretsCISControl = "CIS 3.11, CIS 14.8"

	// maxContainersScanned caps the number of containers a single Audit
	// invocation will inspect to bound execution time on hosts running
	// thousands of short-lived containers.
	maxContainersScanned = 500
)

// defaultEnvDenyPrefixes lists environment variable name prefixes that are
// almost always safe to skip. They are noisy (every shell sets them) and
// never contain credentials.
var defaultEnvDenyPrefixes = []string{
	"TERM", "LANG", "LC_", "PATH", "HOME", "PWD", "SHELL",
	"HOSTNAME", "DEBIAN_FRONTEND", "OLDPWD",
}

// ContainerEnvLister is the read-only Docker API surface the
// ContainerEnvSecrets auditor depends on. The interface lets tests inject a
// fake without spinning up a real Docker socket.
type ContainerEnvLister interface {
	ListContainerEnvs(ctx context.Context, cfg map[string]any) ([]dockerdisc.ContainerEnv, error)
}

// ContainerEnvSecrets scans Docker container environment variables for
// hard-coded credentials matching the shared secretPatterns ruleset. It
// implements Auditor; it is a no-op for any asset whose AssetType is not
// AssetTypeContainer.
//
// The auditor reads container envs from a ContainerEnvLister at construction
// time so the same Audit method can run per-asset without re-issuing Docker
// API calls. The lister is a thin wrapper around docker.Docker.
type ContainerEnvSecrets struct {
	lister       ContainerEnvLister
	dockerCfg    map[string]any
	denyPrefixes []string
	maxScan      int

	// envByID caches the result of one ListContainerEnvs call so the
	// engine's per-asset audit loop does not re-fetch container env data
	// for every container asset. The cache is populated lazily on first
	// Audit call and bounded to a single scan.
	cache       map[string]dockerdisc.ContainerEnv
	cacheLoaded bool
}

// NewContainerEnvSecrets constructs a ContainerEnvSecrets auditor.
//
// extraDeny is appended to the default deny list of high-noise env var
// name prefixes (TERM, LANG, PATH, etc.) and matched case-insensitively.
// Pass nil for the default behaviour. dockerCfg is the same map[string]any
// passed to docker.Docker.Discover; pass nil to use environment-variable
// based defaults.
func NewContainerEnvSecrets(lister ContainerEnvLister, dockerCfg map[string]any, extraDeny []string) *ContainerEnvSecrets {
	deny := make([]string, 0, len(defaultEnvDenyPrefixes)+len(extraDeny))
	deny = append(deny, defaultEnvDenyPrefixes...)
	for _, e := range extraDeny {
		if e == "" {
			continue
		}
		deny = append(deny, e)
	}
	return &ContainerEnvSecrets{
		lister:       lister,
		dockerCfg:    dockerCfg,
		denyPrefixes: deny,
		maxScan:      maxContainersScanned,
	}
}

// Name returns the auditor identifier.
func (c *ContainerEnvSecrets) Name() string { return containerEnvSecretsAuditorName }

// Audit scans the env vars of the container identified by the asset's
// container_id tag. Returns nil findings for non-container assets.
func (c *ContainerEnvSecrets) Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	if asset.AssetType != model.AssetTypeContainer {
		return nil, nil
	}
	if c.lister == nil {
		return nil, nil
	}

	containerID := extractContainerIDTag(asset.Tags)
	if containerID == "" {
		slog.Warn("container_env_secrets: asset has no container_id tag, skipping", "asset_id", asset.ID)
		return nil, nil
	}

	env, ok := c.envFor(ctx, containerID)
	if !ok {
		return nil, nil
	}

	now := time.Now().UTC()
	return scanContainerEnv(asset, env, c.denyPrefixes, now), nil
}

// envFor returns the cached ContainerEnv whose 12-char prefix matches the
// asset's container_id tag. The cache is populated lazily on the first
// successful call to ListContainerEnvs.
func (c *ContainerEnvSecrets) envFor(ctx context.Context, shortID string) (dockerdisc.ContainerEnv, bool) {
	if !c.cacheLoaded {
		envs, err := c.lister.ListContainerEnvs(ctx, c.dockerCfg)
		if err != nil {
			slog.Warn("container_env_secrets: list failed, scan skipped", "error", err)
			c.cache = map[string]dockerdisc.ContainerEnv{}
			c.cacheLoaded = true
			return dockerdisc.ContainerEnv{}, false
		}
		c.cache = make(map[string]dockerdisc.ContainerEnv, len(envs))
		count := 0
		for _, e := range envs {
			if count >= c.maxScan {
				slog.Warn("container_env_secrets: reached max containers cap; remainder skipped",
					"max", c.maxScan)
				break
			}
			short := truncateID(e.ID, 12)
			c.cache[short] = e
			count++
		}
		c.cacheLoaded = true
	}
	e, ok := c.cache[shortID]
	return e, ok
}

// scanContainerEnv applies the secretPatterns to every env var in env and
// returns one ConfigFinding per (pattern, env_var_name) pair. Findings are
// deduplicated within the same scan. Secret values are never stored — only
// the env var name and a 16-hex-char SHA-256 prefix of the matched value
// are recorded so cross-asset correlation is possible without exposure.
func scanContainerEnv(asset model.Asset, env dockerdisc.ContainerEnv, denyPrefixes []string, now time.Time) []model.ConfigFinding {
	if len(env.Env) == 0 {
		return nil
	}

	var findings []model.ConfigFinding
	seen := make(map[string]bool, len(env.Env)*len(secretPatterns))

	shortID := truncateID(env.ID, 12)
	for _, kv := range env.Env {
		name, value, ok := splitEnvKV(kv)
		if !ok || value == "" {
			continue
		}
		if matchesAnyPrefix(name, denyPrefixes) {
			continue
		}

		for _, pat := range secretPatterns {
			if !pat.Re.MatchString(value) {
				continue
			}

			dedupeKey := pat.ID + ":" + name
			if seen[dedupeKey] {
				continue
			}
			seen[dedupeKey] = true

			valueHash := fmt.Sprintf("%x", sha256.Sum256([]byte(value)))[:16]
			seed := fmt.Sprintf("container_env_secrets:%s:%s:%s", asset.ID, pat.ID, name)
			findingID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(seed))

			evidence := fmt.Sprintf("ENV[%s]=<redacted> detected in container:%s (%s) hash:%s",
				name, shortID, env.Name, valueHash)

			findings = append(findings, model.ConfigFinding{
				ID:          findingID,
				AssetID:     asset.ID,
				Auditor:     containerEnvSecretsAuditorName,
				CheckID:     pat.ID,
				Title:       fmt.Sprintf("Container env secret: %s", pat.Name),
				Severity:    pat.Severity,
				CWEID:       containerEnvSecretsCWEID,
				CWEName:     containerEnvSecretsCWEName,
				Evidence:    evidence,
				Expected:    containerEnvSecretsExpected,
				Remediation: pat.Remediation,
				CISControl:  containerEnvSecretsCISControl,
				Timestamp:   now,
			})
		}
	}

	if len(findings) > 0 {
		slog.Info("container_env_secrets: findings detected",
			"asset_id", asset.ID,
			"container_id", shortID,
			"container_name", env.Name,
			"count", len(findings),
		)
	}

	return findings
}

// splitEnvKV splits a Docker env entry like "AWS_ACCESS_KEY_ID=AKIA..."
// into its name and value components. Returns ok=false for entries that
// have no '=' separator (Docker accepts these but they carry no value).
func splitEnvKV(kv string) (name, value string, ok bool) {
	idx := strings.IndexByte(kv, '=')
	if idx <= 0 {
		return "", "", false
	}
	return kv[:idx], kv[idx+1:], true
}

// matchesAnyPrefix returns true when name starts with any prefix in
// prefixes (case-insensitive). An empty prefix is ignored.
func matchesAnyPrefix(name string, prefixes []string) bool {
	upper := strings.ToUpper(name)
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(upper, strings.ToUpper(p)) {
			return true
		}
	}
	return false
}

// truncateID returns the first n characters of id, or id itself if shorter.
func truncateID(id string, n int) string {
	if len(id) <= n {
		return id
	}
	return id[:n]
}

// Compile-time interface check.
var _ Auditor = (*ContainerEnvSecrets)(nil)
