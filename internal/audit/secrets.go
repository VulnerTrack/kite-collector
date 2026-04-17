package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/model"
)

const (
	secretsAuditorName = "secrets"

	// CWE-798: Use of Hard-coded Credentials
	secretsCWEID   = "CWE-798"
	secretsCWEName = "Use of Hard-coded Credentials" //#nosec G101 -- CWE label, not a credential

	maxFileSize     = 1 << 20 // 1 MiB — skip larger files
	maxFilesScanned = 10_000  // safety cap per repository
)

// secretPattern describes one type of detectable secret.
type secretPattern struct {
	ID          string
	Name        string
	Re          *regexp.Regexp
	Severity    model.Severity
	Remediation string
}

// secretPatterns is the set of patterns the secrets auditor checks for.
// Evidence logged never includes the matched secret value — only the file
// path, line number, and a hash of the match to allow deduplication.
var secretPatterns = []secretPattern{
	{
		ID:          "sec-001",
		Name:        "AWS Access Key ID",
		Re:          regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		Severity:    model.SeverityCritical,
		Remediation: "Remove AWS key from source, rotate it immediately, and use IAM roles or AWS Secrets Manager.",
	},
	{
		ID:          "sec-002",
		Name:        "Private key header",
		Re:          regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----`),
		Severity:    model.SeverityCritical,
		Remediation: "Remove the private key from source and rotate it. Store keys in a secrets manager or hardware vault.",
	},
	{
		ID:          "sec-003",
		Name:        "Generic API key assignment",
		Re:          regexp.MustCompile(`(?i)(api[_\-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}`),
		Severity:    model.SeverityHigh,
		Remediation: "Move the API key to an environment variable or secrets manager and rotate it.",
	},
	{
		ID:          "sec-004",
		Name:        "Hard-coded password assignment",
		Re:          regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{6,}`),
		Severity:    model.SeverityHigh,
		Remediation: "Remove the hard-coded password and load it from environment variables or a secrets manager.",
	},
	{
		ID:          "sec-005",
		Name:        "Generic secret assignment",
		Re:          regexp.MustCompile(`(?i)(secret[_\-]?key|secret_token|auth[_\-]?token)\s*[:=]\s*["']?[A-Za-z0-9+/]{16,}`),
		Severity:    model.SeverityHigh,
		Remediation: "Remove the hard-coded secret and source it from an environment variable or secrets manager.",
	},
	{
		ID:          "sec-006",
		Name:        "GitHub personal access token",
		Re:          regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{36,}`),
		Severity:    model.SeverityCritical,
		Remediation: "Revoke the GitHub token immediately and replace it with a short-lived token or GitHub Actions secret.",
	},
}

// skippedExtensions lists binary or non-text file types to skip.
var skippedExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true,
	".svg": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".pdf": true, ".zip": true, ".tar": true, ".gz": true, ".tgz": true,
	".exe": true, ".bin": true, ".so": true, ".dylib": true, ".dll": true,
	".pyc": true, ".class": true, ".o": true, ".a": true,
	".db": true, ".sqlite": true, ".lock": true,
}

// Secrets scans repository source files for hard-coded credentials.
// It is a no-op for non-repository assets.
type Secrets struct{}

// NewSecrets creates a Secrets auditor.
func NewSecrets() *Secrets { return &Secrets{} }

// Name returns the auditor identifier.
func (s *Secrets) Name() string { return secretsAuditorName }

// Audit scans all eligible text files in the repository for secret patterns.
func (s *Secrets) Audit(ctx context.Context, asset model.Asset) ([]model.ConfigFinding, error) {
	if asset.AssetType != model.AssetTypeRepository {
		return nil, nil
	}

	repoPath := extractRepoPath(asset.Tags)
	if repoPath == "" {
		slog.Warn("secrets: repository asset has no path tag, skipping", "asset_id", asset.ID)
		return nil, nil
	}

	now := time.Now().UTC()
	var findings []model.ConfigFinding
	filesScanned := 0

	err := filepath.WalkDir(repoPath, func(path string, d os.DirEntry, werr error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if werr != nil {
			return nil //nolint:nilerr // WalkDir: skip unreadable entries
		}

		if d.IsDir() {
			name := d.Name()
			if name == ".git" || isHiddenOrSystem(name) {
				return filepath.SkipDir
			}
			return nil
		}

		if filesScanned >= maxFilesScanned {
			return filepath.SkipAll
		}

		// Skip binary and large files.
		ext := strings.ToLower(filepath.Ext(path))
		if skippedExtensions[ext] {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil //nolint:nilerr // skip files whose metadata is unreadable
		}
		if info.Size() > maxFileSize {
			return nil
		}

		filesScanned++
		fileFindings := s.scanFile(asset, path, now)
		findings = append(findings, fileFindings...)
		return nil
	})

	if err != nil && err != filepath.SkipAll {
		slog.Warn("secrets: walk error", "asset_id", asset.ID, "error", err)
	}

	if len(findings) > 0 {
		slog.Info("secrets: findings detected",
			"asset_id", asset.ID,
			"path", repoPath,
			"count", len(findings),
			"files_scanned", filesScanned,
		)
	}

	return findings, nil
}

// scanFile checks a single file for all secret patterns and returns findings.
// The evidence field contains file path + line number but NOT the matched text,
// to avoid secrets appearing in the database.
func (s *Secrets) scanFile(asset model.Asset, filePath string, now time.Time) []model.ConfigFinding {
	f, err := os.Open(filePath) //#nosec G304 -- path is from trusted repo walk
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var findings []model.ConfigFinding
	lineNum := 0
	seen := make(map[string]bool) // deduplicate (pattern, file) pairs within this file

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, pat := range secretPatterns {
			if !pat.Re.MatchString(line) {
				continue
			}

			dedupeKey := pat.ID + ":" + filePath
			if seen[dedupeKey] {
				continue // only one finding per pattern per file
			}
			seen[dedupeKey] = true

			// Build a stable finding ID so first_seen_at is preserved across scans.
			matchHash := fmt.Sprintf("%x", sha256.Sum256([]byte(pat.ID+filePath)))[:16]
			seed := fmt.Sprintf("secrets:%s:%s:%s", asset.ID, pat.ID, matchHash)
			findingID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(seed))

			// Evidence: path+line only — no matched text.
			relPath, _ := filepath.Rel(extractRepoPath(asset.Tags), filePath)
			evidence := fmt.Sprintf("%s (line %d) — %s detected", relPath, lineNum, pat.Name)

			findings = append(findings, model.ConfigFinding{
				ID:          findingID,
				AssetID:     asset.ID,
				Auditor:     secretsAuditorName,
				CheckID:     pat.ID,
				Title:       fmt.Sprintf("Hard-coded secret: %s", pat.Name),
				Severity:    pat.Severity,
				CWEID:       secretsCWEID,
				CWEName:     secretsCWEName,
				Evidence:    evidence,
				Expected:    "No credentials in source code",
				Remediation: pat.Remediation,
				Timestamp:   now,
			})
		}
	}

	return findings
}

// isHiddenOrSystem returns true for directory names that should be skipped
// during file-tree walks (hidden dirs, vendored deps, build artefacts).
func isHiddenOrSystem(name string) bool {
	if len(name) > 0 && name[0] == '.' {
		return true
	}
	switch name {
	case "node_modules", "vendor", "__pycache__", ".git",
		"target", "dist", "build", ".cache":
		return true
	}
	return false
}

// Compile-time interface check.
var _ Auditor = (*Secrets)(nil)
