package storage

import (
	"net/http"
	"testing"
)

// hasMatch returns true if matches contains an entry with the given provider
// and signal. The Reason is not checked so callers can change wording without
// breaking these tests.
func hasMatch(matches []Match, p Provider, s SignalType) bool {
	for _, m := range matches {
		if m.Provider == p && m.Signal == s {
			return true
		}
	}
	return false
}

func TestDetect_AWSS3_BucketURL(t *testing.T) {
	ev := Evidence{
		URL:           "https://my-photos.s3.us-east-1.amazonaws.com/avatar.png",
		BucketHost:    "my-photos.s3.us-east-1.amazonaws.com",
		TLSServerName: "my-photos.s3.us-east-1.amazonaws.com",
	}
	matches := Detect(ev)

	if !hasMatch(matches, ProviderAWSS3, SignalBucket) {
		t.Fatalf("expected AWS S3 bucket match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderAWSS3, SignalTLS) {
		t.Errorf("expected AWS S3 TLS match for SNI in URL, got %+v", matches)
	}
}

func TestDetect_AWSS3_PathStyleBucket(t *testing.T) {
	ev := Evidence{URL: "https://s3.amazonaws.com/legacy-bucket/key.txt"}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderAWSS3, SignalBucket) {
		t.Fatalf("expected path-style S3 bucket match, got %+v", matches)
	}
}

func TestDetect_AWSS3_JSSource(t *testing.T) {
	ev := Evidence{
		Filename: "main.bundle.js",
		JS:       `import { S3Client } from "@aws-sdk/client-s3"; new S3Client({region:"eu-west-1"});`,
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderAWSS3, SignalFile) {
		t.Fatalf("expected AWS S3 file (JS) match, got %+v", matches)
	}
}

func TestDetect_AWSS3_APIHeader(t *testing.T) {
	ev := Evidence{
		APIHeaders: http.Header{
			"X-Amz-Request-Id":             []string{"ABC123"},
			"X-Amz-Server-Side-Encryption": []string{"AES256"},
		},
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderAWSS3, SignalAPI) {
		t.Fatalf("expected AWS S3 API header match, got %+v", matches)
	}
}

func TestDetect_AWSS3_Network(t *testing.T) {
	ev := Evidence{RemoteIP: "52.216.10.5"}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderAWSS3, SignalNetwork) {
		t.Fatalf("expected AWS S3 network match for 52.216.10.5, got %+v", matches)
	}

	// IP outside the configured ranges should not match.
	ev = Evidence{RemoteIP: "10.0.0.1"}
	if matches := Detect(ev); hasMatch(matches, ProviderAWSS3, SignalNetwork) {
		t.Errorf("did not expect AWS S3 network match for RFC1918, got %+v", matches)
	}
}

func TestDetect_Supabase(t *testing.T) {
	ev := Evidence{
		JS:            `import { createClient } from "@supabase/supabase-js"; supabase.storage.from("avatars").upload(...)`,
		URL:           "https://abcdefghijklmnopqrst.supabase.co/storage/v1/object/public/avatars/me.png",
		TLSServerName: "abcdefghijklmnopqrst.supabase.co",
		BucketHost:    "abcdefghijklmnopqrst.supabase.co",
	}
	matches := Detect(ev)

	if !hasMatch(matches, ProviderSupabaseStorage, SignalFile) {
		t.Errorf("expected supabase file match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderSupabaseStorage, SignalTLS) {
		t.Errorf("expected supabase TLS match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderSupabaseStorage, SignalAPI) {
		t.Errorf("expected supabase API match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderSupabaseStorage, SignalBucket) {
		t.Errorf("expected supabase bucket match, got %+v", matches)
	}
}

func TestDetect_GCS(t *testing.T) {
	ev := Evidence{
		URL:           "https://storage.googleapis.com/my-public-bucket/file.bin",
		TLSServerName: "storage.googleapis.com",
		APIHeaders:    http.Header{"X-Goog-Generation": []string{"1"}},
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderGCS, SignalBucket) {
		t.Errorf("expected GCS bucket match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderGCS, SignalTLS) {
		t.Errorf("expected GCS TLS match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderGCS, SignalAPI) {
		t.Errorf("expected GCS API match, got %+v", matches)
	}
}

func TestDetect_AzureBlob(t *testing.T) {
	ev := Evidence{
		URL:           "https://mystorage.blob.core.windows.net/images/cat.png",
		TLSServerName: "mystorage.blob.core.windows.net",
		APIHeaders:    http.Header{"X-Ms-Request-Id": []string{"xyz"}},
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderAzureBlob, SignalBucket) {
		t.Errorf("expected Azure Blob bucket match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderAzureBlob, SignalAPI) {
		t.Errorf("expected Azure Blob API match, got %+v", matches)
	}
}

func TestDetect_R2(t *testing.T) {
	ev := Evidence{
		URL:           "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/my-bucket/key",
		TLSServerName: "0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderCloudflareR2, SignalBucket) {
		t.Fatalf("expected R2 bucket match, got %+v", matches)
	}
}

func TestDetect_DOSpaces(t *testing.T) {
	ev := Evidence{
		URL:           "https://my-cdn.nyc3.digitaloceanspaces.com/static/app.js",
		TLSServerName: "my-cdn.nyc3.digitaloceanspaces.com",
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderDigitalOceanSpaces, SignalBucket) {
		t.Fatalf("expected DigitalOcean Spaces bucket match, got %+v", matches)
	}
}

func TestDetect_MinIO_ServerHeader(t *testing.T) {
	ev := Evidence{
		APIHeaders: http.Header{"Server": []string{"MinIO"}},
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderMinIO, SignalAPI) {
		t.Fatalf("expected MinIO API match for Server header, got %+v", matches)
	}
}

func TestDetect_IBMCOS(t *testing.T) {
	ev := Evidence{
		URL: "https://my-bucket.s3.us-south.cloud-object-storage.appdomain.cloud/key",
		JS:  `import * as cos from "ibm-cos-sdk-js";`,
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderIBMCOS, SignalBucket) {
		t.Errorf("expected IBM COS bucket match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderIBMCOS, SignalFile) {
		t.Errorf("expected IBM COS file match, got %+v", matches)
	}
}

func TestDetect_VercelBlob(t *testing.T) {
	ev := Evidence{
		URL: "https://abcdefghijklmnopqrstuvwx.public.blob.vercel-storage.com/avatar.png",
		JS:  `import { put } from "@vercel/blob";`,
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderVercelBlob, SignalFile) {
		t.Errorf("expected Vercel Blob file match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderVercelBlob, SignalBucket) {
		t.Errorf("expected Vercel Blob bucket match, got %+v", matches)
	}
}

func TestDetect_Filebase(t *testing.T) {
	ev := Evidence{
		URL: "https://my-bucket.s3.filebase.com/key",
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderFilebase, SignalBucket) {
		t.Errorf("expected Filebase bucket match, got %+v", matches)
	}
}

func TestDetect_BunnyStorage(t *testing.T) {
	ev := Evidence{
		URL:           "https://my-cdn.b-cdn.net/static/app.js",
		TLSServerName: "my-cdn.b-cdn.net",
		APIHeaders:    map[string][]string{"Server": {"BunnyCDN-DE1-1234"}},
	}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderBunnyStorage, SignalTLS) {
		t.Errorf("expected Bunny TLS match, got %+v", matches)
	}
	if !hasMatch(matches, ProviderBunnyStorage, SignalAPI) {
		t.Errorf("expected Bunny API server header match, got %+v", matches)
	}
}

func TestDetect_Wasabi(t *testing.T) {
	ev := Evidence{URL: "https://s3.eu-central-1.wasabisys.com/my-bucket/key"}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderWasabi, SignalBucket) {
		t.Fatalf("expected Wasabi bucket match, got %+v", matches)
	}
}

func TestDetect_JA4_Literal(t *testing.T) {
	const hash = "ge11nn05enus_<aws-sdk-js>_"
	ev := Evidence{JA4H: hash}
	matches := Detect(ev)
	if !hasMatch(matches, ProviderAWSS3, SignalJA4H) {
		t.Fatalf("expected JA4H literal match, got %+v", matches)
	}

	ev = Evidence{JA4H: "different"}
	if matches := Detect(ev); hasMatch(matches, ProviderAWSS3, SignalJA4H) {
		t.Errorf("did not expect JA4H match for unknown hash, got %+v", matches)
	}
}

func TestDetect_NoDuplicates(t *testing.T) {
	// JS source contains the same substring twice; we still only want one
	// match per (Provider, Signal, Reason).
	ev := Evidence{
		Filename: "main.bundle.js",
		URL:      "https://cdn.example.com/aws-sdk.min.js",
		JS:       "aws-sdk.min.js loaded; window.aws-sdk.min.js loaded again",
	}
	matches := Detect(ev)
	count := 0
	for _, m := range matches {
		if m.Provider == ProviderAWSS3 && m.Signal == SignalFile && m.Reason == "aws-sdk-js bundle filename" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one dedup'd file match, got %d (%+v)", count, matches)
	}
}

func TestDetect_EmptyEvidence(t *testing.T) {
	if matches := Detect(Evidence{}); len(matches) != 0 {
		t.Fatalf("expected zero matches on empty evidence, got %+v", matches)
	}
}

func TestFilter_ByProvider(t *testing.T) {
	matches := []Match{
		{Provider: ProviderAWSS3, Signal: SignalFile, Confidence: ConfidenceHigh},
		{Provider: ProviderGCS, Signal: SignalFile, Confidence: ConfidenceHigh},
		{Provider: ProviderSupabaseStorage, Signal: SignalAPI, Confidence: ConfidenceMedium},
	}

	out := Filter{Providers: []Provider{ProviderAWSS3, ProviderGCS}}.Apply(matches)
	if len(out) != 2 {
		t.Fatalf("expected 2 matches after provider filter, got %d", len(out))
	}
	for _, m := range out {
		if m.Provider == ProviderSupabaseStorage {
			t.Errorf("filter leaked supabase match")
		}
	}
}

func TestFilter_BySignal(t *testing.T) {
	matches := []Match{
		{Provider: ProviderAWSS3, Signal: SignalFile, Confidence: ConfidenceHigh},
		{Provider: ProviderAWSS3, Signal: SignalNetwork, Confidence: ConfidenceMedium},
		{Provider: ProviderAWSS3, Signal: SignalBucket, Confidence: ConfidenceHigh},
	}
	out := Filter{Signals: []SignalType{SignalBucket, SignalFile}}.Apply(matches)
	if len(out) != 2 {
		t.Fatalf("expected 2 matches, got %+v", out)
	}
}

func TestFilter_ExcludeSignal(t *testing.T) {
	matches := []Match{
		{Provider: ProviderAWSS3, Signal: SignalNetwork, Confidence: ConfidenceMedium},
		{Provider: ProviderAWSS3, Signal: SignalBucket, Confidence: ConfidenceHigh},
	}
	out := Filter{ExcludeSignals: []SignalType{SignalNetwork}}.Apply(matches)
	if len(out) != 1 || out[0].Signal != SignalBucket {
		t.Fatalf("expected only bucket match, got %+v", out)
	}
}

func TestFilter_MinConfidence(t *testing.T) {
	matches := []Match{
		{Provider: ProviderAWSS3, Signal: SignalFile, Confidence: ConfidenceLow},
		{Provider: ProviderAWSS3, Signal: SignalFile, Confidence: ConfidenceMedium},
		{Provider: ProviderAWSS3, Signal: SignalFile, Confidence: ConfidenceHigh},
	}
	out := Filter{MinConfidence: ConfidenceMedium}.Apply(matches)
	if len(out) != 2 {
		t.Fatalf("expected 2 matches at >=medium confidence, got %d", len(out))
	}
}

func TestGroupByProvider(t *testing.T) {
	matches := []Match{
		{Provider: ProviderAWSS3, Signal: SignalFile},
		{Provider: ProviderAWSS3, Signal: SignalBucket},
		{Provider: ProviderGCS, Signal: SignalAPI},
	}
	grouped := GroupByProvider(matches)
	if got := len(grouped[ProviderAWSS3]); got != 2 {
		t.Errorf("expected 2 AWS matches, got %d", got)
	}
	if got := len(grouped[ProviderGCS]); got != 1 {
		t.Errorf("expected 1 GCS match, got %d", got)
	}
}

func TestCatalogue_HasEveryProvider(t *testing.T) {
	covered := map[Provider]bool{}
	for _, sig := range Catalogue() {
		covered[sig.Provider] = true
	}
	for _, p := range AllProviders {
		if !covered[p] {
			t.Errorf("catalogue missing provider %s", p)
		}
	}
}

func TestCatalogue_NetworkCIDRsValid(t *testing.T) {
	for i, sig := range Catalogue() {
		if sig.Signal != SignalNetwork {
			continue
		}
		if len(sig.CIDRs) == 0 {
			t.Errorf("signature %d (%s) marked Network but has no CIDRs", i, sig.Provider)
		}
	}
}
