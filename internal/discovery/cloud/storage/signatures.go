package storage

import "regexp"

// reMust is a tiny helper so the catalogue literal stays readable.
func reMust(expr string) *regexp.Regexp { return regexp.MustCompile(expr) }

// catalogue is the master signature list. Entries are ordered roughly by
// provider then signal so reviewers can scan a block per backend. The list
// is intentionally non-exhaustive: each entry is a high-signal fingerprint
// that has been observed in published SDKs, vendor documentation, or
// production bucket URLs.
//
// JA4/JA4S/JA4H/JA5 literal slots are populated with empty entries for
// providers where we have not yet captured a stable hash — the rule shape
// is in place so a later iteration can drop the actual values in without a
// schema change.
var catalogue = []Signature{
	// -----------------------------------------------------------------
	// AWS S3
	// -----------------------------------------------------------------
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)aws-sdk(?:-js)?[^"']*\.(?:min\.)?js`),
		Confidence:  ConfidenceHigh,
		Description: "aws-sdk-js bundle filename",
	},
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalFile,
		Literals:    []string{"@aws-sdk/client-s3", "AWS.S3(", "new S3Client("},
		Confidence:  ConfidenceHigh,
		Description: "aws-sdk-js v2/v3 S3 client identifiers in JS source",
	},
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "S3 endpoint in TLS SAN / SNI",
	},
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalAPI,
		Pattern:     reMust(`(?i)^x-amz-(request-id|id-2|server-side-encryption|version-id|bucket-region)\b`),
		Confidence:  ConfidenceHigh,
		Description: "S3 response header",
	},
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)(?:^|//)([a-z0-9.\-]{3,63})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com(?:/|$)`),
		Confidence:  ConfidenceHigh,
		Description: "Virtual-hosted-style S3 bucket URL",
	},
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/([a-z0-9.\-]{3,63})(?:/|$)`),
		Confidence:  ConfidenceHigh,
		Description: "Path-style S3 bucket URL",
	},
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalNetwork,
		CIDRs:       []string{"52.216.0.0/15", "52.218.0.0/16", "3.5.0.0/19", "16.182.0.0/16"},
		Confidence:  ConfidenceMedium,
		Description: "Sample S3 service prefixes (AWS ip-ranges.json)",
	},
	{
		Provider:    ProviderAWSS3,
		Signal:      SignalJA4H,
		Literals:    []string{"ge11nn05enus_<aws-sdk-js>_"},
		Confidence:  ConfidenceLow,
		Description: "Placeholder JA4H for aws-sdk-js HTTP profile",
	},

	// -----------------------------------------------------------------
	// Supabase Storage
	// -----------------------------------------------------------------
	{
		Provider:    ProviderSupabaseStorage,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)@supabase/(?:storage-js|supabase-js)`),
		Confidence:  ConfidenceHigh,
		Description: "supabase-js / storage-js package import",
	},
	{
		Provider:    ProviderSupabaseStorage,
		Signal:      SignalFile,
		Literals:    []string{".storage.from(", "createClient(", "supabase.storage"},
		Confidence:  ConfidenceMedium,
		Description: "Supabase storage client call sites",
	},
	{
		Provider:    ProviderSupabaseStorage,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.supabase\.co$`),
		Confidence:  ConfidenceHigh,
		Description: "Supabase project hostname in SAN",
	},
	{
		Provider:    ProviderSupabaseStorage,
		Signal:      SignalAPI,
		Pattern:     reMust(`(?i)/storage/v1/object/(public|sign|authenticated)/`),
		Confidence:  ConfidenceHigh,
		Description: "Supabase Storage REST path",
	},
	{
		Provider:    ProviderSupabaseStorage,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9]{20})\.supabase\.co/storage/v1/object/[^/]+/([^/?#]+)`),
		Confidence:  ConfidenceHigh,
		Description: "Supabase bucket URL (project-ref.supabase.co)",
	},

	// -----------------------------------------------------------------
	// Google Cloud Storage
	// -----------------------------------------------------------------
	{
		Provider:    ProviderGCS,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)@google-cloud/storage|firebase/storage|firebase-storage`),
		Confidence:  ConfidenceHigh,
		Description: "GCS / Firebase Storage SDK import",
	},
	{
		Provider:    ProviderGCS,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)(?:^|\.)(storage|firebasestorage)\.googleapis\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "GCS / Firebase Storage SNI",
	},
	{
		Provider:    ProviderGCS,
		Signal:      SignalAPI,
		Pattern:     reMust(`(?i)^x-goog-(generation|metageneration|hash|stored-content-length)\b`),
		Confidence:  ConfidenceHigh,
		Description: "GCS response header",
	},
	{
		Provider:    ProviderGCS,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//(?:storage\.googleapis\.com/([a-z0-9._\-]+)|([a-z0-9._\-]+)\.storage\.googleapis\.com)(?:/|$)`),
		Confidence:  ConfidenceHigh,
		Description: "GCS bucket URL (path or virtual-host)",
	},
	{
		Provider:    ProviderGCS,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//firebasestorage\.googleapis\.com/v0/b/([a-z0-9._\-]+)/o/`),
		Confidence:  ConfidenceHigh,
		Description: "Firebase Storage download URL",
	},

	// -----------------------------------------------------------------
	// Azure Blob
	// -----------------------------------------------------------------
	{
		Provider:    ProviderAzureBlob,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)@azure/storage-blob`),
		Confidence:  ConfidenceHigh,
		Description: "Azure Blob SDK import",
	},
	{
		Provider:    ProviderAzureBlob,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.blob\.core\.windows\.net$`),
		Confidence:  ConfidenceHigh,
		Description: "Azure Blob endpoint",
	},
	{
		Provider:    ProviderAzureBlob,
		Signal:      SignalAPI,
		Pattern:     reMust(`(?i)^x-ms-(request-id|version|blob-type|copy-id|lease-id)\b`),
		Confidence:  ConfidenceHigh,
		Description: "Azure Blob response header",
	},
	{
		Provider:    ProviderAzureBlob,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9\-]{3,63})`),
		Confidence:  ConfidenceHigh,
		Description: "Azure Blob container URL (account.blob.core.windows.net/container)",
	},

	// -----------------------------------------------------------------
	// Backblaze B2
	// -----------------------------------------------------------------
	{
		Provider:    ProviderBackblazeB2,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.(?:backblazeb2|backblaze)\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "Backblaze B2 endpoint",
	},
	{
		Provider:    ProviderBackblazeB2,
		Signal:      SignalAPI,
		Pattern:     reMust(`(?i)/b2api/v[0-9]+/b2_(download_file_by_id|get_upload_url|list_buckets)`),
		Confidence:  ConfidenceHigh,
		Description: "Backblaze B2 native API path",
	},
	{
		Provider:    ProviderBackblazeB2,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//s3\.([a-z0-9\-]+)\.backblazeb2\.com/([a-z0-9.\-]{3,63})`),
		Confidence:  ConfidenceHigh,
		Description: "Backblaze B2 S3-compatible endpoint",
	},

	// -----------------------------------------------------------------
	// Cloudflare R2
	// -----------------------------------------------------------------
	{
		Provider:    ProviderCloudflareR2,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.r2\.cloudflarestorage\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "R2 S3-compatible endpoint",
	},
	{
		Provider:    ProviderCloudflareR2,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.r2\.dev$`),
		Confidence:  ConfidenceHigh,
		Description: "R2 public bucket endpoint",
	},
	{
		Provider:    ProviderCloudflareR2,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-f0-9]{32})\.r2\.cloudflarestorage\.com/([a-z0-9.\-]{3,63})`),
		Confidence:  ConfidenceHigh,
		Description: "R2 bucket URL (accountid.r2.cloudflarestorage.com)",
	},
	{
		Provider:    ProviderCloudflareR2,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)@cloudflare/(?:workers-types|kv-asset-handler).*R2`),
		Confidence:  ConfidenceMedium,
		Description: "Cloudflare R2 type imports",
	},

	// -----------------------------------------------------------------
	// DigitalOcean Spaces
	// -----------------------------------------------------------------
	{
		Provider:    ProviderDigitalOceanSpaces,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.digitaloceanspaces\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "DigitalOcean Spaces endpoint",
	},
	{
		Provider:    ProviderDigitalOceanSpaces,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9.\-]{3,63})\.([a-z]{3})\d?\.digitaloceanspaces\.com(?:/|$)`),
		Confidence:  ConfidenceHigh,
		Description: "DigitalOcean Spaces bucket URL",
	},

	// -----------------------------------------------------------------
	// MinIO
	// -----------------------------------------------------------------
	{
		Provider:    ProviderMinIO,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)minio-js|@minio/`),
		Confidence:  ConfidenceHigh,
		Description: "MinIO JS SDK import",
	},
	{
		Provider:    ProviderMinIO,
		Signal:      SignalAPI,
		Pattern:     reMust(`(?i)^server:\s*minio`),
		Confidence:  ConfidenceHigh,
		Description: "MinIO Server response header",
	},
	{
		Provider:    ProviderMinIO,
		Signal:      SignalAPI,
		Literals:    []string{"x-minio-deployment-id", "x-minio-request-id"},
		Confidence:  ConfidenceHigh,
		Description: "MinIO response header",
	},

	// -----------------------------------------------------------------
	// Wasabi
	// -----------------------------------------------------------------
	{
		Provider:    ProviderWasabi,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.wasabisys\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "Wasabi endpoint",
	},
	{
		Provider:    ProviderWasabi,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//s3\.([a-z0-9\-]+)\.wasabisys\.com/([a-z0-9.\-]{3,63})`),
		Confidence:  ConfidenceHigh,
		Description: "Wasabi S3-compatible bucket URL",
	},

	// -----------------------------------------------------------------
	// Tigris (S3-compatible global object store)
	// -----------------------------------------------------------------
	{
		Provider:    ProviderTigris,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)fly\.storage\.tigris\.dev$`),
		Confidence:  ConfidenceHigh,
		Description: "Tigris fly.storage endpoint",
	},

	// -----------------------------------------------------------------
	// Linode Object Storage
	// -----------------------------------------------------------------
	{
		Provider:    ProviderLinodeObject,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.linodeobjects\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "Linode Object Storage endpoint",
	},
	{
		Provider:    ProviderLinodeObject,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9.\-]{3,63})\.([a-z0-9\-]+)\.linodeobjects\.com(?:/|$)`),
		Confidence:  ConfidenceHigh,
		Description: "Linode Object Storage bucket URL",
	},

	// -----------------------------------------------------------------
	// Scaleway Object Storage
	// -----------------------------------------------------------------
	{
		Provider:    ProviderScalewayObject,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.scw\.cloud$`),
		Confidence:  ConfidenceHigh,
		Description: "Scaleway endpoint",
	},
	{
		Provider:    ProviderScalewayObject,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9.\-]{3,63})\.s3\.([a-z0-9\-]+)\.scw\.cloud(?:/|$)`),
		Confidence:  ConfidenceHigh,
		Description: "Scaleway Object Storage bucket URL",
	},

	// -----------------------------------------------------------------
	// IBM Cloud Object Storage
	// -----------------------------------------------------------------
	{
		Provider:    ProviderIBMCOS,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.cloud-object-storage\.cloud\.ibm\.com$|\.s3\.[a-z0-9\-]+\.cloud-object-storage\.appdomain\.cloud$`),
		Confidence:  ConfidenceHigh,
		Description: "IBM COS endpoint",
	},
	{
		Provider:    ProviderIBMCOS,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9.\-]{3,63})\.s3\.([a-z0-9\-]+)\.cloud-object-storage\.appdomain\.cloud(?:/|$)`),
		Confidence:  ConfidenceHigh,
		Description: "IBM COS bucket URL",
	},
	{
		Provider:    ProviderIBMCOS,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)ibm-cos-sdk-js|ibm-cos-sdk`),
		Confidence:  ConfidenceHigh,
		Description: "IBM COS JS SDK import",
	},

	// -----------------------------------------------------------------
	// Vercel Blob
	// -----------------------------------------------------------------
	{
		Provider:    ProviderVercelBlob,
		Signal:      SignalFile,
		Pattern:     reMust(`(?i)@vercel/blob`),
		Confidence:  ConfidenceHigh,
		Description: "Vercel Blob SDK import",
	},
	{
		Provider:    ProviderVercelBlob,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.public\.blob\.vercel-storage\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "Vercel Blob public endpoint",
	},
	{
		Provider:    ProviderVercelBlob,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9]{20,})\.public\.blob\.vercel-storage\.com/`),
		Confidence:  ConfidenceHigh,
		Description: "Vercel Blob URL",
	},

	// -----------------------------------------------------------------
	// Filebase
	// -----------------------------------------------------------------
	{
		Provider:    ProviderFilebase,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.filebase\.com$`),
		Confidence:  ConfidenceHigh,
		Description: "Filebase endpoint",
	},
	{
		Provider:    ProviderFilebase,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//([a-z0-9.\-]{3,63})\.s3\.filebase\.com/`),
		Confidence:  ConfidenceHigh,
		Description: "Filebase S3-compatible bucket URL",
	},
	{
		Provider:    ProviderFilebase,
		Signal:      SignalAPI,
		Literals:    []string{"x-amz-meta-cid"},
		Confidence:  ConfidenceMedium,
		Description: "Filebase exposes IPFS CID via x-amz-meta-cid response header",
	},

	// -----------------------------------------------------------------
	// Bunny.net Storage Zone
	// -----------------------------------------------------------------
	{
		Provider:    ProviderBunnyStorage,
		Signal:      SignalTLS,
		Pattern:     reMust(`(?i)\.storage\.bunnycdn\.com$|\.b-cdn\.net$`),
		Confidence:  ConfidenceHigh,
		Description: "Bunny.net storage / CDN endpoint",
	},
	{
		Provider:    ProviderBunnyStorage,
		Signal:      SignalBucket,
		Pattern:     reMust(`(?i)//(storage|[a-z0-9\-]+)\.bunnycdn\.com/([a-z0-9\-]+)/`),
		Confidence:  ConfidenceHigh,
		Description: "Bunny storage zone URL",
	},
	{
		Provider:    ProviderBunnyStorage,
		Signal:      SignalAPI,
		Pattern:     reMust(`(?i)^server:\s*BunnyCDN`),
		Confidence:  ConfidenceHigh,
		Description: "BunnyCDN server header",
	},
}

// Catalogue returns the immutable list of registered signatures. Callers
// must not mutate the returned slice (it is the package-level catalogue).
func Catalogue() []Signature {
	return catalogue
}
