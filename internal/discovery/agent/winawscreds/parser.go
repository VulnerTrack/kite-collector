package winawscreds

import (
	"bufio"
	"bytes"
	"strings"
)

// ParseFile walks an AWS credentials or config file body and
// returns one Profile per `[section]` discovered. The grammar is
// Python ConfigParser-style INI with one wrinkle: in the
// `~/.aws/config` file every non-default profile is prefixed
// with `profile ` (`[profile production]`), but in
// `~/.aws/credentials` the prefix is omitted (`[production]`).
// We strip the prefix when present so profile names match
// across files.
//
// `kind` is stamped onto each profile by the caller; the parser
// doesn't infer it from filename.
func ParseFile(body []byte, kind FileKind) []Profile {
	out := make([]Profile, 0, 4)
	if len(body) == 0 {
		return out
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var current *Profile
	finalize := func() {
		if current == nil {
			return
		}
		out = append(out, *current)
		current = nil
	}

	scan := bufio.NewScanner(bytes.NewReader(body))
	scan.Buffer(make([]byte, 0, 4096), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			finalize()
			name := normalizeProfileName(line[1 : len(line)-1])
			current = &Profile{FileKind: kind, ProfileName: name}
			continue
		}
		if current == nil {
			continue
		}
		key, value, ok := splitKV(line)
		if !ok {
			continue
		}
		applyKey(current, key, value)
	}
	finalize()
	return out
}

// normalizeProfileName drops the `profile ` prefix used in
// `~/.aws/config` so the same profile appears under the same
// name regardless of which file declared it.
func normalizeProfileName(raw string) string {
	t := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(t), "profile ") {
		return strings.TrimSpace(t[len("profile "):])
	}
	return t
}

// splitKV separates `key = value`. The AWS CLI accepts both
// `key=value` and `key = value`.
func splitKV(line string) (string, string, bool) {
	if i := strings.IndexByte(line, '='); i > 0 {
		return strings.TrimSpace(line[:i]),
			strings.TrimSpace(line[i+1:]),
			true
	}
	return "", "", false
}

// applyKey routes one (key, value) into the active Profile.
// Unknown keys flow past — AWS profiles can carry arbitrary
// vendor-specific settings (e.g. `endpoint_url`, `ca_bundle`).
func applyKey(p *Profile, key, value string) {
	switch strings.ToLower(key) {
	case "aws_access_key_id":
		p.HasAccessKey = strings.TrimSpace(value) != ""
		p.AccessKeyIDFingerprint = AccessKeyIDPrefix(value)
	case "aws_secret_access_key":
		p.HasSecretAccessKey = strings.TrimSpace(value) != ""
	case "aws_session_token":
		p.HasSessionToken = strings.TrimSpace(value) != ""
	case "region":
		p.Region = value
	case "output":
		p.Output = value
	case "source_profile":
		p.SourceProfile = value
	case "role_arn":
		p.RoleARN = value
		p.HasRoleARN = strings.TrimSpace(value) != ""
	case "mfa_serial":
		p.MFASerial = value
		p.HasMFASerial = strings.TrimSpace(value) != ""
	case "sso_account_id":
		p.SSOAccountID = value
		p.HasSSO = strings.TrimSpace(value) != "" || p.HasSSO
	case "sso_role_name":
		p.SSORoleName = value
		p.HasSSO = strings.TrimSpace(value) != "" || p.HasSSO
	case "sso_start_url", "sso_region":
		p.HasSSO = p.HasSSO || strings.TrimSpace(value) != ""
	}
}
