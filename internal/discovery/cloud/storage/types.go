// Package storage analyses JavaScript bundles and observed network artefacts
// for evidence of S3-compatible object-storage providers (AWS S3, Supabase
// Storage, Google Cloud Storage, Azure Blob, Backblaze B2, Cloudflare R2,
// DigitalOcean Spaces, MinIO, Wasabi, Tigris).
//
// The package exposes three building blocks:
//
//   - A signature catalogue (signatures.go) that classifies known SDK URLs,
//     API host suffixes, TLS SAN patterns, JA4/JA4S/JA4H/JA5 hashes, public
//     network ranges, and bucket-URL templates.
//   - A detector (detector.go) that runs an Evidence record against the
//     catalogue and returns Match values.
//   - A filter (filter.go) that narrows matches by provider, signal type,
//     or confidence band.
//
// The intended consumer is a JS-asset crawler that feeds discovered files,
// TLS metadata, and request fingerprints into Detect and persists the
// resulting matches as discovery artefacts.
package storage

import (
	"net/http"
	"regexp"
)

// Provider identifies an S3-compatible object-storage backend.
type Provider string

const (
	ProviderAWSS3              Provider = "aws_s3"
	ProviderSupabaseStorage    Provider = "supabase_storage"
	ProviderGCS                Provider = "gcs"
	ProviderAzureBlob          Provider = "azure_blob"
	ProviderBackblazeB2        Provider = "backblaze_b2"
	ProviderCloudflareR2       Provider = "cloudflare_r2"
	ProviderDigitalOceanSpaces Provider = "do_spaces"
	ProviderMinIO              Provider = "minio"
	ProviderWasabi             Provider = "wasabi"
	ProviderTigris             Provider = "tigris"
	ProviderLinodeObject       Provider = "linode_object"
	ProviderScalewayObject     Provider = "scaleway_object"
	ProviderIBMCOS             Provider = "ibm_cos"
	ProviderVercelBlob         Provider = "vercel_blob"
	ProviderFilebase           Provider = "filebase"
	ProviderBunnyStorage       Provider = "bunny_storage"
)

// AllProviders is the canonical list of providers this package can detect.
// Callers can iterate it to build allowlists or filter sets without hard-
// coding individual constants.
var AllProviders = []Provider{
	ProviderAWSS3,
	ProviderSupabaseStorage,
	ProviderGCS,
	ProviderAzureBlob,
	ProviderBackblazeB2,
	ProviderCloudflareR2,
	ProviderDigitalOceanSpaces,
	ProviderMinIO,
	ProviderWasabi,
	ProviderTigris,
	ProviderLinodeObject,
	ProviderScalewayObject,
	ProviderIBMCOS,
	ProviderVercelBlob,
	ProviderFilebase,
	ProviderBunnyStorage,
}

// SignalType labels the category of evidence that produced a match. The set
// matches the discovery dimensions called out by the surrounding collector:
// file (JS asset), TLS, JA4 family, JA5, API surface, network, and bucket.
type SignalType string

const (
	SignalFile    SignalType = "file"
	SignalTLS     SignalType = "tls"
	SignalJA4     SignalType = "ja4"
	SignalJA4S    SignalType = "ja4s"
	SignalJA4H    SignalType = "ja4h"
	SignalJA5     SignalType = "ja5"
	SignalAPI     SignalType = "api"
	SignalNetwork SignalType = "network"
	SignalBucket  SignalType = "bucket"
)

// Confidence is a coarse confidence band. We keep three levels rather than a
// 0-100 score so callers don't need to calibrate thresholds across signal
// types; the catalogue assigns the band when a rule is registered.
type Confidence uint8

const (
	ConfidenceLow    Confidence = 1
	ConfidenceMedium Confidence = 2
	ConfidenceHigh   Confidence = 3
)

// Signature is a single matching rule. A signature is keyed by Provider +
// Signal, plus one of several payload kinds: regex (URLs, filenames, headers,
// DNS), literal strings (JA4 hashes, JS source substrings), or CIDR ranges
// (network).
type Signature struct {
	Pattern     *regexp.Regexp
	Description string
	Provider    Provider
	Signal      SignalType
	Literals    []string
	CIDRs       []string
	Confidence  Confidence
}

// Evidence carries one observation about a candidate asset. Every field is
// optional; Detect skips any signal type for which it has no input. This
// lets a caller feed partial data (e.g. just a JS file) without needing to
// stub TLS or JA4 fields.
type Evidence struct {
	APIHeaders    http.Header
	JA4           string
	Filename      string
	JS            string
	TLSServerName string
	URL           string
	JA4S          string
	JA4H          string
	JA5           string
	BucketHost    string
	RemoteIP      string
	TLSSANs       []string
	DNSChain      []string
}

// Match is a single successful signature application. Snippet is a short
// excerpt of the matched evidence (truncated by detector.snippetLimit) so
// downstream logs can include context without echoing entire JS bundles.
type Match struct {
	Provider    Provider   `json:"provider"`
	Signal      SignalType `json:"signal"`
	Reason      string     `json:"reason"`
	Snippet     string     `json:"snippet,omitempty"`
	Confidence  Confidence `json:"confidence"`
	SignatureID int        `json:"signature_id"`
}
