package tlsfingerprint

import "regexp"

// DefaultCatalog returns the seed Signature set for TLS-cert-based
// vendor detection. SAN-suffix matchers are the high-signal anchor
// because cloud platforms route every customer endpoint under a
// vendor-controlled wildcard zone; issuer matchers fill in for
// fronting providers whose certs come from a CA they operate
// themselves (Cloudflare, Amazon).
func DefaultCatalog() []Signature {
	return []Signature{
		// --- BaaS ---------------------------------------------------
		{
			Vendor: "Supabase", Product: "Supabase",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "supabase-co", SANSuffix: ".supabase.co",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Google", Product: "Firebase Hosting",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "firebaseapp", SANSuffix: ".firebaseapp.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "web-app", SANSuffix: ".web.app",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "firebaseio", SANSuffix: ".firebaseio.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Appwrite", Product: "Appwrite Cloud",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "appwrite-cloud", SANSuffix: ".appwrite.io",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Hasura", Product: "Hasura Cloud",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "hasura-app", SANSuffix: ".hasura.app",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},

		// --- Hosting / serverless platforms ------------------------
		{
			Vendor: "Vercel", Product: "Vercel",
			Category: CategoryHosting,
			Patterns: []Pattern{
				{
					Name: "vercel-app", SANSuffix: ".vercel.app",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "vercel-now", SANSuffix: ".now.sh",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Netlify", Product: "Netlify",
			Category: CategoryHosting,
			Patterns: []Pattern{
				{
					Name: "netlify-app", SANSuffix: ".netlify.app",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "netlify-com", SANSuffix: ".netlify.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Cloudflare", Product: "Cloudflare Pages",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "pages-dev", SANSuffix: ".pages.dev",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Cloudflare", Product: "Cloudflare Workers",
			Category: CategoryServerless,
			Patterns: []Pattern{{
				Name: "workers-dev", SANSuffix: ".workers.dev",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Cloudflare", Product: "Cloudflare edge CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name:        "issuer-cloudflare-inc",
					IssuerRegex: regexp.MustCompile(`Cloudflare,?\s*Inc`),
					Kind:        SignalIssuerName, Confidence: ConfidenceMedium,
				},
				{
					Name:     "ocsp-cloudflare",
					OCSPHost: "ocsp.cloudflare.com",
					Kind:     SignalOCSPHost, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Deno Land", Product: "Deno Deploy",
			Category: CategoryServerless,
			Patterns: []Pattern{{
				Name: "deno-dev", SANSuffix: ".deno.dev",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Fly", Product: "Fly.io",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "fly-dev", SANSuffix: ".fly.dev",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Salesforce", Product: "Heroku",
			Category: CategoryHosting,
			Patterns: []Pattern{
				{
					Name: "herokuapp", SANSuffix: ".herokuapp.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "heroku-app", SANSuffix: ".heroku.app",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Replit", Product: "Replit",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "repl-co", SANSuffix: ".repl.co",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Render", Product: "Render",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "onrender-com", SANSuffix: ".onrender.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Railway", Product: "Railway",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "railway-app", SANSuffix: ".railway.app",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "DigitalOcean", Product: "DigitalOcean App Platform",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "ondigitalocean-app", SANSuffix: ".ondigitalocean.app",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Linode", Product: "Linode Object Storage",
			Category: CategoryStorage,
			Patterns: []Pattern{{
				Name: "linodeobjects", SANSuffix: ".linodeobjects.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Backblaze", Product: "Backblaze B2",
			Category: CategoryStorage,
			Patterns: []Pattern{
				{
					Name: "backblazeb2", SANSuffix: ".backblazeb2.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "b2cdn", SANSuffix: ".b2cdn.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Bunny.net", Product: "Bunny CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "b-cdn-net", SANSuffix: ".b-cdn.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "bunnycdn", SANSuffix: ".bunnycdn.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Yandex", Product: "Yandex Cloud",
			Category: CategoryCloudCompute,
			Patterns: []Pattern{
				{
					Name: "yandexcloud-net", SANSuffix: ".yandexcloud.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "yandex-cloud", SANSuffix: ".yandex.cloud",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Oracle", Product: "Oracle Cloud Infrastructure",
			Category: CategoryCloudCompute,
			Patterns: []Pattern{
				{
					Name: "oraclecloud", SANSuffix: ".oraclecloud.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "oci-customer", SANSuffix: ".oci.customer-oci.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "OVHcloud", Product: "OVHcloud",
			Category: CategoryCloudCompute,
			Patterns: []Pattern{
				{
					Name: "ovh-net", SANSuffix: ".ovh.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "hosting-ovh", SANSuffix: ".hosting.ovh.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Scaleway", Product: "Scaleway",
			Category: CategoryCloudCompute,
			Patterns: []Pattern{
				{
					Name: "scw-cloud", SANSuffix: ".scw.cloud",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "scaleway", SANSuffix: ".scaleway.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Convex", Product: "Convex",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "convex-cloud", SANSuffix: ".convex.cloud",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Neon", Product: "Neon Postgres",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "neon-tech", SANSuffix: ".neon.tech",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},

		// --- Hosted-LLM / inference API providers -----------------
		{
			Vendor: "OpenAI", Product: "OpenAI API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "openai-com", SANSuffix: ".openai.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "openai-azure", SANSuffix: ".openai.azure.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Anthropic", Product: "Anthropic API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "anthropic-com", SANSuffix: ".anthropic.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Hugging Face", Product: "Hugging Face Hub / Inference",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "huggingface-co", SANSuffix: ".huggingface.co",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "hf-co", SANSuffix: ".hf.co",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Replicate", Product: "Replicate",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "replicate-com", SANSuffix: ".replicate.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Mistral AI", Product: "Mistral API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "mistral-ai", SANSuffix: ".mistral.ai",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Cohere", Product: "Cohere API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "cohere-com", SANSuffix: ".cohere.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "LangChain", Product: "LangSmith",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "smith-langchain", SANSuffix: ".smith.langchain.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "langchain-com", SANSuffix: ".langchain.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Together AI", Product: "Together API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "together-xyz", SANSuffix: ".together.xyz",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Groq", Product: "Groq API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "groq-com", SANSuffix: ".groq.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Perplexity", Product: "Perplexity API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "perplexity-ai", SANSuffix: ".perplexity.ai",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Fireworks AI", Product: "Fireworks API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "fireworks-ai", SANSuffix: ".fireworks.ai",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Pinecone Systems", Product: "Pinecone (vector DB)",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "pinecone-io", SANSuffix: ".pinecone.io",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Weaviate", Product: "Weaviate Cloud",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "weaviate-cloud", SANSuffix: ".weaviate.cloud",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "weaviate-network", SANSuffix: ".weaviate.network",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Qdrant", Product: "Qdrant Cloud",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "qdrant-io", SANSuffix: ".qdrant.io",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "qdrant-tech", SANSuffix: ".cloud.qdrant.io",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Chroma", Product: "Chroma Cloud",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "chroma-dev", SANSuffix: ".trychroma.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Astra DataStax", Product: "DataStax Astra DB",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "astra-datastax", SANSuffix: ".apps.astra.datastax.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Turso", Product: "Turso (libSQL)",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "turso-io", SANSuffix: ".turso.io",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "PartyKit", Product: "PartyKit",
			Category: CategoryServerless,
			Patterns: []Pattern{{
				Name: "partykit-dev", SANSuffix: ".partykit.dev",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Liveblocks", Product: "Liveblocks",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "liveblocks-io", SANSuffix: ".liveblocks.io",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "liveblocks-net", SANSuffix: ".liveblocks.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Intercom", Product: "Intercom",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "intercom-io", SANSuffix: ".intercom.io",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "intercomcdn", SANSuffix: ".intercomcdn.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Crisp", Product: "Crisp Chat",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "crisp-chat", SANSuffix: ".crisp.chat",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Trigger.dev", Product: "Trigger.dev",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "trigger-dev", SANSuffix: ".trigger.dev",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Inngest", Product: "Inngest",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name: "inngest-com", SANSuffix: ".inngest.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Zendesk", Product: "Zendesk",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name: "zendesk-com", SANSuffix: ".zendesk.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "zdassets", SANSuffix: ".zdassets.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Cloud compute / serverless functions ------------------
		{
			Vendor: "Amazon", Product: "AWS CloudFront",
			Category: CategoryCDN,
			Patterns: []Pattern{{
				Name: "cloudfront-net", SANSuffix: ".cloudfront.net",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Amazon", Product: "AWS API Gateway",
			Category: CategoryServerless,
			Patterns: []Pattern{
				{
					Name: "execute-api", SANSuffix: ".execute-api.amazonaws.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "lambda-url", SANSuffix: ".lambda-url.amazonaws.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Amazon", Product: "AWS S3 / amazonaws.com",
			Category: CategoryStorage,
			Patterns: []Pattern{
				{
					Name: "s3-amazonaws", SANSuffix: ".s3.amazonaws.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "amazonaws-tail", SANSuffix: ".amazonaws.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceMedium,
				},
				{
					Name:        "issuer-amazon",
					IssuerRegex: regexp.MustCompile(`Amazon`),
					Kind:        SignalIssuerName, Confidence: ConfidenceLow,
				},
			},
		},
		{
			Vendor: "Google", Product: "Google Cloud Run",
			Category: CategoryServerless,
			Patterns: []Pattern{{
				Name: "run-app", SANSuffix: ".run.app",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Google", Product: "Google Cloud Functions",
			Category: CategoryServerless,
			Patterns: []Pattern{{
				Name: "cloudfunctions-net", SANSuffix: ".cloudfunctions.net",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Google", Product: "Google App Engine",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "appspot-com", SANSuffix: ".appspot.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Microsoft", Product: "Azure App Service",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "azurewebsites-net", SANSuffix: ".azurewebsites.net",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Microsoft", Product: "Azure Static Web Apps",
			Category: CategoryStaticHost,
			Patterns: []Pattern{{
				Name: "azurestaticapps-net", SANSuffix: ".azurestaticapps.net",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Microsoft", Product: "Azure Front Door / CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "azureedge-net", SANSuffix: ".azureedge.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "azurefd-net", SANSuffix: ".azurefd.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Microsoft", Product: "Azure Blob Storage",
			Category: CategoryStorage,
			Patterns: []Pattern{{
				Name: "blob-core-windows", SANSuffix: ".blob.core.windows.net",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},

		// --- Static-site / git-pages -------------------------------
		{
			Vendor: "GitHub", Product: "GitHub Pages",
			Category: CategoryStaticHost,
			Patterns: []Pattern{{
				Name: "github-io", SANSuffix: ".github.io",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "GitLab", Product: "GitLab Pages",
			Category: CategoryStaticHost,
			Patterns: []Pattern{{
				Name: "gitlab-io", SANSuffix: ".gitlab.io",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Surge", Product: "Surge.sh",
			Category: CategoryStaticHost,
			Patterns: []Pattern{{
				Name: "surge-sh", SANSuffix: ".surge.sh",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Glitch", Product: "Glitch",
			Category: CategoryHosting,
			Patterns: []Pattern{{
				Name: "glitch-me", SANSuffix: ".glitch.me",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},

		// --- CDN tier 1 ---------------------------------------------
		{
			Vendor: "Akamai", Product: "Akamai CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "akamaiedge-net", SANSuffix: ".akamaiedge.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "akamaihd-net", SANSuffix: ".akamaihd.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "edgesuite-net", SANSuffix: ".edgesuite.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "edgekey-net", SANSuffix: ".edgekey.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Fastly", Product: "Fastly CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "fastly-net", SANSuffix: ".fastly.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "fastlylb-net", SANSuffix: ".fastlylb.net",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Auth-as-a-Service -------------------------------------
		{
			Vendor: "Okta", Product: "Auth0",
			Category: CategoryAuth,
			Patterns: []Pattern{{
				Name: "auth0-com", SANSuffix: ".auth0.com",
				Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Clerk Inc.", Product: "Clerk",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name: "clerk-accounts", SANSuffix: ".clerk.accounts.dev",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
				{
					Name: "clerk-com", SANSuffix: ".clerk.com",
					Kind: SignalSANSuffix, Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Issuer-only fingerprints (lower confidence) ----------
		{
			Vendor: "Let's Encrypt", Product: "Let's Encrypt CA",
			Category: CategoryGeneric,
			Patterns: []Pattern{{
				Name: "issuer-letsencrypt",
				IssuerRegex: regexp.MustCompile(
					`Let's Encrypt|^R1[01]$|^R3$|^E[15-9]$`,
				),
				Kind: SignalIssuerName, Confidence: ConfidenceMedium,
			}},
		},
		{
			Vendor: "Google", Product: "Google Trust Services",
			Category: CategoryGeneric,
			Patterns: []Pattern{{
				Name:        "issuer-gts",
				IssuerRegex: regexp.MustCompile(`Google Trust Services|^GTS\b`),
				Kind:        SignalIssuerName, Confidence: ConfidenceMedium,
			}},
		},
		{
			Vendor: "DigiCert", Product: "DigiCert CA",
			Category: CategoryGeneric,
			Patterns: []Pattern{{
				Name:        "issuer-digicert",
				IssuerRegex: regexp.MustCompile(`DigiCert`),
				Kind:        SignalIssuerName, Confidence: ConfidenceLow,
			}},
		},
		{
			Vendor: "ZeroSSL", Product: "ZeroSSL CA",
			Category: CategoryGeneric,
			Patterns: []Pattern{{
				Name:        "issuer-zerossl",
				IssuerRegex: regexp.MustCompile(`ZeroSSL`),
				Kind:        SignalIssuerName, Confidence: ConfidenceMedium,
			}},
		},
	}
}
