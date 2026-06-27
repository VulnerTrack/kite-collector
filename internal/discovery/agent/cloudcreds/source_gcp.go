package cloudcreds

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// gcpCollector reads two GCP credential surfaces:
//
//	~/.config/gcloud/application_default_credentials.json
//	   — gcloud auth application-default login; OAuth user creds.
//	~/.config/gcloud/credentials.db (SQLite, skip)
//	~/.config/gcloud/legacy_credentials/<account>/adc.json
//	   — per-account OAuth caches.
//	<service-account>.json
//	   — when GOOGLE_APPLICATION_CREDENTIALS points at one (not
//	     scanned by default; operator must configure).
//
// The JSON shape we recognise:
//
//	{"type":"authorized_user","client_id":"...","refresh_token":"...",
//	 "client_secret":"..."}   ← user-OAuth ADC
//
//	{"type":"service_account","project_id":"...","client_email":"...",
//	 "private_key_id":"...","private_key":"-----BEGIN ..."}
//	                                        ← downloaded SA JSON key
//
// We extract project_id, client_email, and private_key_id (the LATTER
// is non-secret per Google docs — it identifies which SA key is in use
// without revealing the secret). private_key field is never read.
type gcpCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	homeRoots []string
}

// NewGCPCollector returns the default GCP credentials walker.
func NewGCPCollector() Collector {
	return &gcpCollector{
		homeRoots: defaultHomeRoots(),
		readFile:  func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- $HOME path
		readDir:   func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *gcpCollector) Name() string { return "gcp-files" }

func (c *gcpCollector) Collect(ctx context.Context) ([]Credential, error) {
	var out []Credential
	for _, home := range walkHomes(c.readDir, c.homeRoots) {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		user := filepath.Base(home)
		adcPath := filepath.Join(home, ".config", "gcloud",
			"application_default_credentials.json")
		out = append(out, c.parseADC(adcPath, user)...)
		out = append(out, c.parseLegacyDir(home, user)...)
		if len(out) >= MaxCredentials {
			SortCredentials(out)
			return out[:MaxCredentials], nil
		}
	}
	SortCredentials(out)
	return out, nil
}

// gcpADC is the projection we decode from any GCP credentials JSON.
type gcpADC struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientEmail  string `json:"client_email,omitempty"`
	PrivateKeyID string `json:"private_key_id,omitempty"`
	// We intentionally do NOT add fields for `private_key`,
	// `refresh_token`, or `client_secret`. Even though we'd then have
	// them in memory only, leaving them undeclared in the struct means
	// json.Unmarshal won't allocate them.
}

func (c *gcpCollector) parseADC(path, owner string) []Credential {
	data, err := c.readFile(path)
	if err != nil {
		return nil
	}
	defer wipe(data)
	cred, ok := decodeGCPCredential(data, "default")
	if !ok {
		slog.Debug("cloudcreds: gcp ADC unparseable", "path", path)
		return nil
	}
	cred.OwnerUser = owner
	cred.SourcePath = path
	return []Credential{cred}
}

// parseLegacyDir walks ~/.config/gcloud/legacy_credentials/<account>/adc.json.
func (c *gcpCollector) parseLegacyDir(home, owner string) []Credential {
	legacy := filepath.Join(home, ".config", "gcloud", "legacy_credentials")
	entries, err := c.readDir(legacy)
	if err != nil {
		return nil
	}
	var out []Credential
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		adc := filepath.Join(legacy, e.Name(), "adc.json")
		data, err := c.readFile(adc)
		if err != nil {
			continue
		}
		defer wipe(data)
		cred, ok := decodeGCPCredential(data, e.Name())
		if !ok {
			continue
		}
		cred.OwnerUser = owner
		cred.SourcePath = adc
		out = append(out, cred)
	}
	return out
}

func decodeGCPCredential(data []byte, profile string) (Credential, bool) {
	var raw gcpADC
	if err := json.Unmarshal(data, &raw); err != nil {
		return Credential{}, false
	}
	cred := Credential{
		Provider:     ProviderGCP,
		Profile:      profile,
		AccountID:    raw.ProjectID,
		KeyID:        raw.PrivateKeyID,
		SourceFormat: FormatJSON,
	}
	switch raw.Type {
	case "service_account":
		cred.CredentialType = CredServiceAccountKey
		// Downloaded SA JSON keys are static long-lived secrets per
		// Google's own anti-patterns documentation.
		cred.IsLongLived = true
		if raw.ClientEmail != "" {
			cred.RoleARN = raw.ClientEmail // overload role_arn for "principal identity"
		}
	case "authorized_user":
		cred.CredentialType = CredOAuthRefresh
		cred.FederatedVia = "oauth"
	case "external_account":
		cred.CredentialType = CredOAuthAccess
		cred.FederatedVia = "workload-identity-federation"
	default:
		cred.CredentialType = CredUnknown
	}
	return cred, true
}
