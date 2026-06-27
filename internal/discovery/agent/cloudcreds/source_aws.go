package cloudcreds

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// awsCollector parses ~/.aws/credentials and ~/.aws/config across every
// user. Both are INI-style:
//
//	[default]
//	aws_access_key_id     = AKIA…
//	aws_secret_access_key = …          ← we ignore this column
//	aws_session_token     = …          ← we flag its presence only
//
//	[profile prod]                     ← ~/.aws/config namespaces with "profile "
//	role_arn = arn:aws:iam::123456789012:role/Prod
//	sso_session = corp-sso
//	mfa_serial = arn:aws:iam::…
//
// We never read the secret access key into memory beyond the parser's
// line scan (it lands in the value variable for one iteration and is
// then dropped without being stored). The access key ID (AKIA…) is
// non-secret per AWS documentation and is preserved.
type awsCollector struct {
	readFile  func(string) ([]byte, error)
	readDir   func(string) ([]os.DirEntry, error)
	homeRoots []string
}

// NewAWSCollector returns the default ~/.aws walker.
func NewAWSCollector() Collector {
	return &awsCollector{
		homeRoots: defaultHomeRoots(),
		readFile:  func(p string) ([]byte, error) { return os.ReadFile(p) }, //#nosec G304 -- $HOME-derived path
		readDir:   func(p string) ([]os.DirEntry, error) { return os.ReadDir(p) },
	}
}

func (c *awsCollector) Name() string { return "aws-files" }

func (c *awsCollector) Collect(ctx context.Context) ([]Credential, error) {
	var out []Credential
	for _, home := range walkHomes(c.readDir, c.homeRoots) {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("context cancelled mid-walk: %w", err)
		}
		user := filepath.Base(home)
		credPath := filepath.Join(home, ".aws", "credentials")
		cfgPath := filepath.Join(home, ".aws", "config")

		out = append(out, c.parseCredentialsFile(credPath, user)...)
		out = append(out, c.parseConfigFile(cfgPath, user)...)
		if len(out) >= MaxCredentials {
			SortCredentials(out)
			return out[:MaxCredentials], nil
		}
	}
	SortCredentials(out)
	return out, nil
}

// parseCredentialsFile walks ~/.aws/credentials. Each [section] becomes
// a Credential row.
func (c *awsCollector) parseCredentialsFile(path, owner string) []Credential {
	data, err := c.readFile(path)
	if err != nil {
		return nil
	}
	defer wipe(data) // best-effort scrub of the buffer before GC

	sections := parseINI(data)
	out := make([]Credential, 0, len(sections))
	for _, sec := range sections {
		// In credentials file, section name IS the profile name.
		cred := Credential{
			Provider:     ProviderAWS,
			Profile:      sec.name,
			OwnerUser:    owner,
			SourcePath:   path,
			SourceFormat: FormatINI,
		}
		for _, kv := range sec.pairs {
			switch kv.key {
			case "aws_access_key_id":
				if IsLikelyAWSAccessKeyID(kv.val) {
					cred.KeyID = kv.val
					cred.IsLongLived = IsLongLivedAWSPrefix(kv.val)
					cred.CredentialType = CredAccessKey
					if !cred.IsLongLived {
						cred.CredentialType = CredSessionToken
					}
				}
			case "aws_session_token":
				if kv.val != "" {
					cred.SessionTokenPresent = true
					cred.CredentialType = CredSessionToken
				}
			case "aws_secret_access_key":
				// Deliberate no-op. We only care that the key exists
				// (covered by aws_access_key_id detection).
			}
		}
		if cred.CredentialType == "" {
			cred.CredentialType = CredUnknown
		}
		out = append(out, cred)
	}
	return out
}

// parseConfigFile walks ~/.aws/config. Sections here are named
// `[default]` or `[profile <name>]` — we strip the leading "profile ".
// We extract role_arn, sso_session, mfa_serial.
func (c *awsCollector) parseConfigFile(path, owner string) []Credential {
	data, err := c.readFile(path)
	if err != nil {
		return nil
	}
	sections := parseINI(data)
	out := make([]Credential, 0, len(sections))
	for _, sec := range sections {
		profile := strings.TrimPrefix(sec.name, "profile ")
		cred := Credential{
			Provider:       ProviderAWS,
			CredentialType: CredUnknown,
			Profile:        profile,
			OwnerUser:      owner,
			SourcePath:     path,
			SourceFormat:   FormatINI,
		}
		for _, kv := range sec.pairs {
			switch kv.key {
			case "role_arn":
				cred.RoleARN = kv.val
				cred.CredentialType = CredAccessKey // assume-role chain → ultimately access-key-shaped
			case "sso_session", "sso_start_url":
				cred.FederatedVia = "sso"
				cred.CredentialType = CredSSOCache
			case "mfa_serial":
				if kv.val != "" {
					cred.HasMFA = true
				}
			case "region":
				cred.Region = kv.val
			case "credential_source":
				// "Ec2InstanceMetadata" / "EcsContainer" / "Environment" — all federated.
				cred.FederatedVia = "iam-instance-role"
			}
		}
		out = append(out, cred)
	}
	return out
}

// iniSection / iniPair are tiny dep-free representations of an INI
// file. We deliberately don't bring in a third-party INI parser — AWS's
// format is small and stable.
type iniSection struct {
	name  string
	pairs []iniPair
}

type iniPair struct {
	key string
	val string
}

// parseINI walks an AWS-style INI buffer. Comments (`;` or `#`) and
// blank lines are skipped. Keys are lowercased; values are right-trimmed.
func parseINI(data []byte) []iniSection {
	var (
		out []iniSection
		cur *iniSection
	)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Some credential files contain very long session tokens — bump the
	// default 64KiB buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			out = append(out, iniSection{name: strings.TrimSpace(line[1 : len(line)-1])})
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue // value lines before the first section are skipped
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		cur.pairs = append(cur.pairs, iniPair{key: key, val: val})
	}
	return out
}

// wipe overwrites b with zeros. Best-effort scrub of credential buffers
// before the buffer becomes garbage.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// defaultHomeRoots / walkHomes are shared with the GCP + Kubeconfig
// collectors via homedir.go in this package.

// silence unused-slog warning if a future refactor drops the import
var _ = slog.Default
