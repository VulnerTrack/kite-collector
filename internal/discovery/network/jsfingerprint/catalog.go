package jsfingerprint

import "regexp"

// DefaultCatalog returns the seed BaaS / auth / analytics / payments
// signature set. Patterns combine multiple kinds (script-src, config-
// literal, endpoint-url, public-key) so the Detector can emit a
// fingerprint from whichever signal the page surfaces — bundled SDKs
// produce script-src + global hits, while client-rendered apps surface
// endpoint-url + config-literal more reliably.
//
// All "id" capture groups are extracted into Fingerprint.ProjectID so
// an inventory consumer can correlate which Supabase project, Firebase
// app, Sanity dataset, or Auth0 tenant is bound to a discovered page.
func DefaultCatalog() []Signature {
	return []Signature{
		// --- Backend-as-a-Service ---------------------------------
		{
			Vendor: "Supabase", Product: "Supabase",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "supabase-co-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9]{20,32})\.supabase\.co`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "supabase-js-cdn",
					Regex:      regexp.MustCompile(`(?i)supabase-js[@/][\d.]+/dist|@supabase/supabase-js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "supabase-createClient",
					Regex:      regexp.MustCompile(`createClient\s*\(\s*['"]https?://(?P<id>[a-z0-9]{20,32})\.supabase\.co`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "next-public-supabase",
					Regex:      regexp.MustCompile(`NEXT_PUBLIC_SUPABASE_(URL|ANON_KEY)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Google", Product: "Firebase",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "firebase-config-literal",
					Regex:      regexp.MustCompile(`firebaseConfig\s*=\s*{[^}]*projectId\s*:\s*['"](?P<id>[a-z0-9-]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "firebase-firebaseio-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.firebaseio\.com`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "firebase-firebaseapp-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.firebaseapp\.com`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "firebase-app-js",
					Regex:      regexp.MustCompile(`(?i)firebasejs/[\d.]+/firebase-app|firebase-app-compat\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "firebase-identitytoolkit",
					Regex:      regexp.MustCompile(`identitytoolkit\.googleapis\.com`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Monospace Inc.", Product: "Directus",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "directus-sdk-import",
					Regex:      regexp.MustCompile(`(?i)@directus/sdk|directus\.io/dist`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "directus-rest-base",
					Regex:      regexp.MustCompile(`/items/[a-z_]+\?.*(directus|access_token)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceMedium,
				},
				{
					Name:       "directus-env",
					Regex:      regexp.MustCompile(`(?i)(NEXT_PUBLIC_|VITE_|REACT_APP_)?DIRECTUS_(URL|TOKEN|API)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Tryretool", Product: "Retool",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "retool-embed-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.retool\.com/embedded/`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "retool-iframe-src",
					Regex:      regexp.MustCompile(`(?i)<iframe[^>]+src\s*=\s*["'][^"']*retool\.com`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "retool-sdk",
					Regex:      regexp.MustCompile(`(?i)@tryretool/embed|retool-embed`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Hasura", Product: "Hasura Cloud",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "hasura-app-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.hasura\.app/v1/graphql`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "hasura-env",
					Regex:      regexp.MustCompile(`(?i)HASURA_GRAPHQL_(URL|ADMIN_SECRET)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Appwrite", Product: "Appwrite",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "appwrite-endpoint",
					Regex:      regexp.MustCompile(`(?i)\.setEndpoint\s*\(\s*['"][^"']+/v1['"]\s*\)\s*\.setProject\s*\(\s*['"](?P<id>[a-f0-9]{16,32})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "appwrite-cloud-host",
					Regex:      regexp.MustCompile(`https?://cloud\.appwrite\.io/v1`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "appwrite-sdk",
					Regex:      regexp.MustCompile(`(?i)appwrite[@/][\d.]+|node_modules/appwrite/dist`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "PocketBase", Product: "PocketBase",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "pocketbase-sdk",
					Regex:      regexp.MustCompile(`(?i)pocketbase[@/][\d.]+|new\s+PocketBase\s*\(`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "pocketbase-api",
					Regex:      regexp.MustCompile(`/api/collections/[a-z0-9_]+/records`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Strapi", Product: "Strapi (client)",
			Category: CategoryCMS,
			Patterns: []Pattern{
				{
					Name:       "strapi-api-base",
					Regex:      regexp.MustCompile(`/api/[a-z-]+\?(populate|pagination|filters)=`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceMedium,
				},
				{
					Name:       "strapi-env",
					Regex:      regexp.MustCompile(`(?i)(NEXT_PUBLIC_|VITE_|REACT_APP_)?STRAPI_(URL|API_TOKEN)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},

		// --- Headless CMS / content -------------------------------
		{
			Vendor: "Sanity.io", Product: "Sanity",
			Category: CategoryCMS,
			Patterns: []Pattern{
				{
					Name:       "sanity-createClient",
					Regex:      regexp.MustCompile(`createClient\s*\(\s*{[^}]*projectId\s*:\s*['"](?P<id>[a-z0-9]{8})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "sanity-api-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9]{8})\.api\.sanity\.io`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "sanity-sdk",
					Regex:      regexp.MustCompile(`(?i)@sanity/client|sanity-image`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Contentful", Product: "Contentful",
			Category: CategoryCMS,
			Patterns: []Pattern{
				{
					Name:       "contentful-cdn-host",
					Regex:      regexp.MustCompile(`https?://cdn\.contentful\.com/spaces/(?P<id>[a-z0-9]{12,16})`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "contentful-sdk",
					Regex:      regexp.MustCompile(`(?i)contentful[@/][\d.]+`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Storyblok", Product: "Storyblok",
			Category: CategoryCMS,
			Patterns: []Pattern{
				{
					Name:       "storyblok-api-host",
					Regex:      regexp.MustCompile(`https?://api\.storyblok\.com/v\d+`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "storyblok-sdk",
					Regex:      regexp.MustCompile(`(?i)@storyblok/(client|js)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Auth / identity --------------------------------------
		{
			Vendor: "Okta", Product: "Auth0",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "auth0-tenant-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.(?:eu\.|us\.|au\.|jp\.)?auth0\.com`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "auth0-sdk",
					Regex:      regexp.MustCompile(`(?i)auth0-spa-js|@auth0/(auth0-js|nextjs-auth0|auth0-react)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "auth0-domain-config",
					Regex:      regexp.MustCompile(`domain\s*:\s*['"](?P<id>[a-z0-9-]+\.(?:eu\.|us\.|au\.|jp\.)?auth0\.com)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Clerk Inc.", Product: "Clerk",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "clerk-publishable-key",
					Regex:      regexp.MustCompile(`pk_(?:test|live)_[A-Za-z0-9+/=]{30,}`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "clerk-frontend-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.clerk\.accounts\.dev`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "clerk-sdk",
					Regex:      regexp.MustCompile(`(?i)@clerk/(clerk-js|clerk-react|nextjs)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "NextAuth.js", Product: "Auth.js / NextAuth",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "nextauth-csrf-route",
					Regex:      regexp.MustCompile(`/api/auth/(csrf|session|signin|providers)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceMedium,
				},
				{
					Name:       "nextauth-env",
					Regex:      regexp.MustCompile(`(?i)NEXTAUTH_(URL|SECRET)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Stytch", Product: "Stytch",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "stytch-sdk",
					Regex:      regexp.MustCompile(`(?i)@stytch/(vanilla-js|stytch-js|react|nextjs)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "stytch-public-token",
					Regex:      regexp.MustCompile(`public-token-(test|live)-[a-f0-9-]{20,}`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Payments ---------------------------------------------
		{
			Vendor: "Stripe", Product: "Stripe.js",
			Category: CategoryPayments,
			Patterns: []Pattern{
				{
					Name:       "stripe-publishable-key",
					Regex:      regexp.MustCompile(`pk_(?:test|live)_[0-9A-Za-z]{24,}`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "stripe-js-cdn",
					Regex:      regexp.MustCompile(`https?://js\.stripe\.com/v\d+/`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "stripe-init",
					Regex:      regexp.MustCompile(`\bStripe\s*\(\s*['"]pk_`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "PayPal", Product: "PayPal JS SDK",
			Category: CategoryPayments,
			Patterns: []Pattern{
				{
					Name:       "paypal-sdk-host",
					Regex:      regexp.MustCompile(`https?://www\.paypal\.com/sdk/js\?client-id=(?P<id>[A-Za-z0-9_-]{20,})`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Lemon Squeezy", Product: "Lemon.js",
			Category: CategoryPayments,
			Patterns: []Pattern{
				{
					Name:       "lemonsqueezy-sdk",
					Regex:      regexp.MustCompile(`https?://assets\.lemonsqueezy\.com/lemon\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Search -----------------------------------------------
		{
			Vendor: "Algolia", Product: "Algolia Search",
			Category: CategorySearch,
			Patterns: []Pattern{
				{
					Name:       "algolia-app-host",
					Regex:      regexp.MustCompile(`https?://(?P<id>[A-Z0-9]{10})-dsn\.algolia\.net`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "algolia-sdk",
					Regex:      regexp.MustCompile(`(?i)algoliasearch[@/][\d.]+|@algolia/(client-search|instantsearch)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "algolia-init",
					Regex:      regexp.MustCompile(`algoliasearch\s*\(\s*['"](?P<id>[A-Z0-9]{10})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Typesense", Product: "Typesense (client)",
			Category: CategorySearch,
			Patterns: []Pattern{
				{
					Name:       "typesense-sdk",
					Regex:      regexp.MustCompile(`(?i)typesense-instantsearch-adapter|typesense\.client`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Feature flags / experimentation -----------------------
		{
			Vendor: "Catamorphic Co.", Product: "LaunchDarkly",
			Category: CategoryFeatureFlags,
			Patterns: []Pattern{
				{
					Name:       "launchdarkly-sdk",
					Regex:      regexp.MustCompile(`(?i)launchdarkly-js-client-sdk|ldclient-js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "launchdarkly-client-id",
					Regex:      regexp.MustCompile(`initialize\s*\(\s*['"](?P<id>[a-f0-9]{24})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "GrowthBook", Product: "GrowthBook",
			Category: CategoryFeatureFlags,
			Patterns: []Pattern{
				{
					Name:       "growthbook-sdk",
					Regex:      regexp.MustCompile(`(?i)@growthbook/growthbook|growthbook-js-sdk`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Statsig", Product: "Statsig",
			Category: CategoryFeatureFlags,
			Patterns: []Pattern{
				{
					Name:       "statsig-sdk",
					Regex:      regexp.MustCompile(`(?i)statsig-js[@/]|@statsig/(client-core|react)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "statsig-key",
					Regex:      regexp.MustCompile(`client-(?:test|prod|stg)-[a-zA-Z0-9]{40,}`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Analytics --------------------------------------------
		{
			Vendor: "PostHog", Product: "PostHog (client)",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "posthog-sdk",
					Regex:      regexp.MustCompile(`(?i)posthog-js|app\.posthog\.com/static/array\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "posthog-init",
					Regex:      regexp.MustCompile(`posthog\.init\s*\(\s*['"](?P<id>phc_[A-Za-z0-9]{30,})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Plausible Insights", Product: "Plausible",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "plausible-script",
					Regex:      regexp.MustCompile(`https?://(?:plausible\.io|[a-z0-9.-]+)/js/(?:plausible|script)(?:\.[a-z-]+)?\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "plausible-data-domain",
					Regex:      regexp.MustCompile(`data-domain\s*=\s*['"](?P<id>[a-z0-9.-]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Umami Software", Product: "Umami (client)",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "umami-script",
					Regex:      regexp.MustCompile(`/umami\.js|/script\.js\?[^"']*umami`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "umami-website-id",
					Regex:      regexp.MustCompile(`data-website-id\s*=\s*['"](?P<id>[a-f0-9-]{32,36})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Segment", Product: "Segment (analytics.js)",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "segment-cdn",
					Regex:      regexp.MustCompile(`https?://cdn\.segment\.com/analytics\.js/v\d+/(?P<id>[A-Za-z0-9]{16,32})/analytics(?:\.min)?\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "segment-load",
					Regex:      regexp.MustCompile(`analytics\.load\s*\(\s*['"](?P<id>[A-Za-z0-9]{16,32})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "HubSpot", Product: "HubSpot (tracking)",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "hubspot-script",
					Regex:      regexp.MustCompile(`https?://js\.hs-(?:scripts|analytics|banner|forms)\.com/(?P<id>\d{6,10})\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Mixpanel", Product: "Mixpanel (client)",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "mixpanel-cdn",
					Regex:      regexp.MustCompile(`https?://cdn\.mxpnl\.com/libs/mixpanel-`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "mixpanel-init",
					Regex:      regexp.MustCompile(`mixpanel\.init\s*\(\s*['"](?P<id>[a-f0-9]{32})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Monitoring / error tracking (client) ------------------
		{
			Vendor: "Functional Software", Product: "Sentry (browser)",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "sentry-dsn",
					Regex:      regexp.MustCompile(`https://(?P<id>[a-f0-9]{32})@[a-z0-9.-]+\.ingest\.(?:us\.|de\.)?sentry\.io/\d+`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "sentry-sdk",
					Regex:      regexp.MustCompile(`(?i)@sentry/(browser|react|nextjs|vue|svelte)|sentry-bundle/`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Datadog", Product: "Datadog RUM (browser)",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "datadog-rum-sdk",
					Regex:      regexp.MustCompile(`(?i)@datadog/browser-rum|datadog-rum\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "datadog-rum-init",
					Regex:      regexp.MustCompile(`DD_RUM\.init\s*\(\s*{[^}]*applicationId\s*:\s*['"](?P<id>[a-f0-9-]{32,36})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "New Relic", Product: "New Relic Browser",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "newrelic-nrba",
					Regex:      regexp.MustCompile(`(?i)NREUM\.info\s*=\s*{[^}]*accountID\s*:\s*['"]?(?P<id>\d+)['"]?`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "newrelic-agent",
					Regex:      regexp.MustCompile(`(?i)js-agent\.newrelic\.com/nr-`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Edge / hosting -------------------------------------
		{
			Vendor: "Vercel", Product: "Vercel-hosted (Next.js)",
			Category: CategoryEdge,
			Patterns: []Pattern{
				{
					Name:       "vercel-insights",
					Regex:      regexp.MustCompile(`/_vercel/insights/(?:script|next)\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "next-data-blob",
					Regex:      regexp.MustCompile(`<script\s+id="__NEXT_DATA__"\s+type="application/json"`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Netlify", Product: "Netlify-hosted",
			Category: CategoryEdge,
			Patterns: []Pattern{
				{
					Name:       "netlify-cdn-host",
					Regex:      regexp.MustCompile(`https?://[a-z0-9-]+\.netlify\.app`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceMedium,
				},
				{
					Name:       "netlify-identity",
					Regex:      regexp.MustCompile(`netlify-identity-widget`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Misc commercial APIs -------------------------------
		{
			Vendor: "Cloudinary", Product: "Cloudinary",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "cloudinary-cdn-host",
					Regex:      regexp.MustCompile(`https?://res\.cloudinary\.com/(?P<id>[a-z0-9_-]+)/(image|video)/upload/`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Mux", Product: "Mux (video)",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "mux-player",
					Regex:      regexp.MustCompile(`(?i)@mux/mux-player|stream\.mux\.com/`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Pusher", Product: "Pusher Channels",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "pusher-sdk",
					Regex:      regexp.MustCompile(`(?i)pusher\.com/.*/pusher\.min\.js|pusher-js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "pusher-key",
					Regex:      regexp.MustCompile(`new\s+Pusher\s*\(\s*['"](?P<id>[a-f0-9]{16,32})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Ably Realtime", Product: "Ably",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "ably-sdk",
					Regex:      regexp.MustCompile(`(?i)cdn\.ably\.com/lib/ably`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "ably-key",
					Regex:      regexp.MustCompile(`new\s+Ably\.Realtime\s*\(\s*['"](?P<id>[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+:[A-Za-z0-9_-]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "MongoDB", Product: "MongoDB Realm Web",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "realm-sdk",
					Regex:      regexp.MustCompile(`(?i)realm-web|MongoDB/.*realm`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "realm-app-id",
					Regex:      regexp.MustCompile(`new\s+(?:Realm\.)?App\s*\(\s*{[^}]*id\s*:\s*['"](?P<id>[a-z0-9-]+_[a-z0-9-]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Amazon", Product: "AWS Amplify (client)",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "amplify-sdk",
					Regex:      regexp.MustCompile(`(?i)aws-amplify[@/]|@aws-amplify/(auth|api|storage)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "amplify-aws-exports",
					Regex:      regexp.MustCompile(`aws_(?:user_pools_id|cognito_identity_pool_id|appsync_graphqlEndpoint)`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Source map + build-tool leaks -------------------------
		// Sourcemap URLs reveal original source paths (and let an
		// attacker fetch the unminified code). Detecting them is a
		// strong "this bundle was published with debug info on".
		{
			Vendor: "Mozilla", Product: "Source map URL",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "sourcemap-url",
					Regex:      regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*([^\s'"]+)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "data-sourcemap",
					Regex:      regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*data:application/json;base64,`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "webpack", Product: "webpack bundle",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "webpack-public-path",
					Regex:      regexp.MustCompile(`__webpack_require__\.p\s*=\s*['"]([^'"]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "webpack-chunk-loading",
					Regex:      regexp.MustCompile(`webpackChunk[A-Za-z0-9_]+\s*=|webpackJsonp\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Vite", Product: "Vite bundle",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "vite-import-meta",
					Regex:      regexp.MustCompile(`import\.meta\.env\.(?:VITE_|MODE|DEV|PROD|SSR)`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "vite-client",
					Regex:      regexp.MustCompile(`/@vite/client|/@react-refresh|__vite__`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Rollup", Product: "Rollup bundle",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "rollup-banner",
					Regex:      regexp.MustCompile(`(?m)^/\*\s*Rollup\.js\s*v[\d.]+`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Parcel", Product: "Parcel bundle",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "parcel-require",
					Regex:      regexp.MustCompile(`parcelRequire\s*=`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "esbuild", Product: "esbuild output",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "esbuild-banner",
					Regex:      regexp.MustCompile(`(?i)esbuild\s*v[\d.]+`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceLow,
				},
			},
		},

		// --- Common config / env-var leak markers ------------------
		// These are noisy alone but valuable as additional evidence
		// when one of the high-confidence BaaS signatures also fires.
		{
			Vendor: "n/a", Product: "Inlined env-var block",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "process-env-leak",
					Regex:      regexp.MustCompile(`process\.env\.(?:NEXT_PUBLIC|REACT_APP|VITE|VUE_APP|GATSBY|EXPO_PUBLIC)_[A-Z0-9_]+`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},

		// --- Framework-companion analytics + RUM SDKs --------------
		// These bundle with specific hosting platforms (Vercel,
		// Cloudflare) or sit alongside any JS framework; their presence
		// is a strong hint of how a page is built and shipped.
		{
			Vendor: "Vercel", Product: "Vercel Speed Insights",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "vercel-speed-insights-script",
					Regex:      regexp.MustCompile(`/_vercel/speed-insights/(?:script|vitals)\.js|@vercel/speed-insights`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Vercel", Product: "Vercel Web Analytics",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "vercel-analytics-script",
					Regex:      regexp.MustCompile(`/_vercel/insights/(?:script|next|view)\.js|@vercel/analytics`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Cloudflare", Product: "Cloudflare Web Analytics",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "cloudflare-insights-beacon",
					Regex:      regexp.MustCompile(`static\.cloudflareinsights\.com/beacon(?:\.min)?\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "cloudflare-insights-token",
					Regex:      regexp.MustCompile(`data-cf-beacon=['"]\{[^']*"token"\s*:\s*"(?P<id>[a-f0-9]{16,64})"`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Cloudflare", Product: "Cloudflare Turnstile",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "turnstile-script",
					Regex:      regexp.MustCompile(`challenges\.cloudflare\.com/turnstile/v0/api\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "turnstile-sitekey",
					Regex:      regexp.MustCompile(`data-sitekey=['"](?P<id>0x[a-zA-Z0-9_-]{18,})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Google", Product: "Google Tag Manager",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "gtm-loader",
					Regex:      regexp.MustCompile(`googletagmanager\.com/gtm\.js\?id=(?P<id>GTM-[A-Z0-9]{6,10})`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "gtm-datalayer-push",
					Regex:      regexp.MustCompile(`dataLayer\s*=\s*window\.dataLayer\s*\|\|\s*\[\]|\(window,document,'script','dataLayer'`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Google", Product: "Google Analytics 4",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "ga4-gtag-loader",
					Regex:      regexp.MustCompile(`googletagmanager\.com/gtag/js\?id=(?P<id>G-[A-Z0-9]{8,12})`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "ga4-gtag-config",
					Regex:      regexp.MustCompile(`gtag\s*\(\s*['"]config['"]\s*,\s*['"](?P<id>G-[A-Z0-9]{8,12})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Fathom Analytics", Product: "Fathom Analytics",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "fathom-script",
					Regex:      regexp.MustCompile(`cdn\.usefathom\.com/script\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "fathom-site-id",
					Regex:      regexp.MustCompile(`data-site=['"](?P<id>[A-Z]{8})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Adobe", Product: "Adobe Experience Cloud (DTM)",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "adobe-dtm-launch",
					Regex:      regexp.MustCompile(`assets\.adobedtm\.com/(?:launch|[a-f0-9]{40})|s\.adobedtm\.com/`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "adobe-target",
					Regex:      regexp.MustCompile(`at\.js|adobe\.target|window\.targetGlobalSettings`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "OneTrust", Product: "OneTrust Cookie Consent",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "onetrust-script",
					Regex:      regexp.MustCompile(`cdn\.cookielaw\.org/(?:scripttemplates|consent)/(?P<id>[a-f0-9-]{36})`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "onetrust-stub",
					Regex:      regexp.MustCompile(`OneTrust\.IsAlertBoxClosed\(\)|window\.OptanonWrapper|optanon\.blob\.core\.windows\.net`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Cybot", Product: "Cookiebot",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "cookiebot-script",
					Regex:      regexp.MustCompile(`consent\.cookiebot\.com/uc\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "cookiebot-cbid",
					Regex:      regexp.MustCompile(`data-cbid=['"](?P<id>[a-f0-9-]{36})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Session replay / heatmap / product analytics RUM -----
		{
			Vendor: "Hotjar", Product: "Hotjar",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "hotjar-script",
					Regex:      regexp.MustCompile(`static\.hotjar\.com/c/hotjar-(?P<id>\d{5,10})\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "hotjar-init",
					Regex:      regexp.MustCompile(`window\.hj\s*=|h\.hj\s*=|_hjSettings\s*=\s*\{\s*hjid\s*:\s*(?P<id>\d{5,10})`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "FullStory", Product: "FullStory",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "fullstory-script",
					Regex:      regexp.MustCompile(`edge\.fullstory\.com/s/fs(?:-v\d+)?\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "fullstory-org",
					Regex:      regexp.MustCompile(`window\['_fs_org'\]\s*=\s*['"](?P<id>[A-Z0-9]{6,10})['"]|_fs_org\s*=\s*['"](?P<id2>[A-Z0-9]{6,10})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "LogRocket", Product: "LogRocket",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "logrocket-script",
					Regex:      regexp.MustCompile(`cdn\.(?:logrocket|lr-ingest)\.io/(?:logger|browser)(?:[.-]\w+)?\.js|cdn\.lr-(?P<id>[a-z0-9]{6,16})\.com/(?:logger|browser)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "logrocket-init",
					Regex:      regexp.MustCompile(`LogRocket\.init\s*\(\s*['"](?P<id>[a-z0-9-]+/[a-z0-9-]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Heap", Product: "Heap Analytics",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "heap-script",
					Regex:      regexp.MustCompile(`(?:cdn\.|cdn1\.)?heapanalytics\.com/(?:js/heap-(?P<id>\d{6,12})|h\.js\?a=(?P<id2>\d{6,12}))`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "heap-load",
					Regex:      regexp.MustCompile(`heap\.load\s*\(\s*['"](?P<id>\d{6,12})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Amplitude", Product: "Amplitude",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "amplitude-script",
					Regex:      regexp.MustCompile(`cdn\.amplitude\.com/(?:libs|script)/amplitude(?:-(?:browser|analytics))?(?:[-.]?[\d.]+)?(?:\.min)?\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "amplitude-init",
					Regex:      regexp.MustCompile(`amplitude\.(?:getInstance\(\)\.init|init)\s*\(\s*['"](?P<id>[a-f0-9]{32})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Refinedev", Product: "Refine",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "refine-package-import",
					Regex:      regexp.MustCompile(`@refinedev/(?:core|antd|mui|mantine|chakra-ui|react-router|nextjs-router|remix-router|react-hook-form|react-table|inferencer|devtools)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "refine-jsx-component",
					Regex:      regexp.MustCompile(`<Refine[\s>]|RefineKbarProvider|useResourceParams|useGo\s*\(\s*\{`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceMedium,
				},
			},
		},

		// --- Browser-side ML/AI runtimes ---------------------------
		// The model files themselves often dwarf the page bundle, so
		// a single script-src match is the most reliable indicator;
		// global-symbol matches catch CDN-loaded usage with no
		// versioned filename.
		{
			Vendor: "Google", Product: "TensorFlow.js",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "tfjs-cdn",
					Regex:      regexp.MustCompile(`@tensorflow/tfjs(?:-(?:core|backend-(?:webgl|webgpu|wasm|cpu)|converter|layers))?|cdn\.jsdelivr\.net/npm/@tensorflow/tfjs`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "tfjs-symbol",
					Regex:      regexp.MustCompile(`\btf\.loadGraphModel\s*\(|\btf\.tensor\s*\(|\btf\.setBackend\s*\(\s*['"](?:webgl|webgpu|wasm|cpu)['"]`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Microsoft", Product: "ONNX Runtime Web",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "ort-web-cdn",
					Regex:      regexp.MustCompile(`onnxruntime-web(?:[/@-][\d.]+)?(?:/dist)?(?:\.min)?\.js|cdn\.jsdelivr\.net/npm/onnxruntime-web`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "ort-web-symbol",
					Regex:      regexp.MustCompile(`\bort\.InferenceSession\.create\s*\(|\bort\.env\.wasm\.|\bort\.Tensor\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Hugging Face", Product: "Transformers.js",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "transformers-js-cdn",
					Regex:      regexp.MustCompile(`@(?:xenova|huggingface)/transformers(?:[@-][\d.]+)?|cdn\.jsdelivr\.net/npm/@(?:xenova|huggingface)/transformers`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "transformers-js-pipeline",
					Regex:      regexp.MustCompile(`\bpipeline\s*\(\s*['"](?:text-generation|sentiment-analysis|feature-extraction|fill-mask|question-answering|summarization|translation|zero-shot-classification|automatic-speech-recognition|image-classification)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Hugging Face", Product: "Hugging Face Inference API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "hf-inference-endpoint",
					Regex:      regexp.MustCompile(`https?://api(?:-inference)?\.huggingface\.co/(?:models/|pipeline/)(?P<id>[A-Za-z0-9._/-]+)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "hf-token-env",
					Regex:      regexp.MustCompile(`HUGGINGFACE_(?:API_TOKEN|HUB_TOKEN)|HF_TOKEN`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "MLC", Product: "Web LLM",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "webllm-cdn",
					Regex:      regexp.MustCompile(`@mlc-ai/web-llm(?:[@-][\d.]+)?|esm\.run/@mlc-ai/web-llm`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "webllm-engine",
					Regex:      regexp.MustCompile(`\bCreateMLCEngine\s*\(|\bnew\s+webllm\.MLCEngine\s*\(|MLCEngineWorkerHandler`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Hosted-LLM provider SDKs ------------------------------
		// Browser-side use of these SDKs is a security-relevant
		// signal: shipping an API key to the browser is a common
		// inventory finding.
		{
			Vendor: "OpenAI", Product: "OpenAI SDK / API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "openai-sdk",
					Regex:      regexp.MustCompile(`["']openai["']|@openai/(?:openai|sdk)|cdn\.jsdelivr\.net/npm/openai`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "openai-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.openai\.com/v1/(?P<id>chat/completions|embeddings|images/generations|audio/(?:transcriptions|translations|speech)|moderations|responses|threads)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "openai-key-pattern",
					Regex:      regexp.MustCompile(`["'](sk-[A-Za-z0-9]{20,}|sk-proj-[A-Za-z0-9_-]{20,})["']`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Anthropic", Product: "Anthropic SDK / API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "anthropic-sdk",
					Regex:      regexp.MustCompile(`@anthropic-ai/(?:sdk|vertex-sdk|bedrock-sdk)|cdn\.jsdelivr\.net/npm/@anthropic-ai/sdk`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "anthropic-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.anthropic\.com/v1/(?P<id>messages|complete|models)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "anthropic-key-pattern",
					Regex:      regexp.MustCompile(`["'](sk-ant-(?:api03-|test01-|admin01-)[A-Za-z0-9_-]{20,})["']`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Replicate", Product: "Replicate API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "replicate-sdk",
					Regex:      regexp.MustCompile(`["']replicate["']|cdn\.jsdelivr\.net/npm/replicate`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "replicate-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.replicate\.com/v1/(?P<id>predictions|models|deployments|trainings|collections)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "replicate-key-pattern",
					Regex:      regexp.MustCompile(`["'](r8_[A-Za-z0-9]{32,40})["']`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "LangChain", Product: "LangChain JS / LangSmith",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "langchain-sdk",
					Regex:      regexp.MustCompile(`@langchain/(?:core|community|openai|anthropic|google-genai|aws|cohere|mistralai|pinecone|qdrant|weaviate|cloudflare|vercel|langgraph|langsmith)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "langsmith-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.smith\.langchain\.com/(?P<id>runs|sessions|datasets|examples|projects)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "langchain-env",
					Regex:      regexp.MustCompile(`LANGCHAIN_(?:TRACING_V2|API_KEY|PROJECT|ENDPOINT)|LANGSMITH_(?:API_KEY|PROJECT|ENDPOINT)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Together AI", Product: "Together API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "together-sdk",
					Regex:      regexp.MustCompile(`["']together-ai["']|together-ai/sdk|cdn\.jsdelivr\.net/npm/together-ai`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "together-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.together\.xyz/v1/(?P<id>chat/completions|completions|embeddings|images/generations|audio/transcriptions|models|files|fine-tunes)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Groq", Product: "Groq API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "groq-sdk",
					Regex:      regexp.MustCompile(`groq-sdk|cdn\.jsdelivr\.net/npm/groq-sdk`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "groq-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.groq\.com/openai/v1/(?P<id>chat/completions|embeddings|audio/transcriptions|audio/translations|models)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "groq-key-pattern",
					Regex:      regexp.MustCompile(`["'](gsk_[A-Za-z0-9]{50,60})["']`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Perplexity", Product: "Perplexity API",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name:       "perplexity-endpoint",
				Regex:      regexp.MustCompile(`https?://api\.perplexity\.ai/(?P<id>chat/completions)`),
				Kind:       SignalEndpointURL,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Fireworks AI", Product: "Fireworks API",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "fireworks-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.fireworks\.ai/inference/v1/(?P<id>chat/completions|completions|embeddings|images/generations)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "fireworks-sdk",
					Regex:      regexp.MustCompile(`["']fireworks-ai["']|@fireworks-ai/`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Modern JS data-layer SDKs ----------------------------
		{
			Vendor: "TRPC", Product: "tRPC",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "trpc-package-import",
					Regex:      regexp.MustCompile(`@trpc/(?:client|server|react-query|next|nuxt|express-adapter|fastify-adapter|server/adapters)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "trpc-link-pattern",
					Regex:      regexp.MustCompile(`\bcreateTRPCNext\s*\(|\bcreateTRPCReact\s*\(|\bhttpBatchLink\s*\(\s*\{|\bsplitLink\s*\(|\bcreateTRPCProxyClient\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "TanStack", Product: "TanStack Query (React Query)",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "tanstack-query-package",
					Regex:      regexp.MustCompile(`@tanstack/(?:react-query|vue-query|svelte-query|solid-query|angular-query|query-core|query-devtools|query-broadcast-client-experimental|query-async-storage-persister)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "tanstack-query-symbol",
					Regex:      regexp.MustCompile(`\bnew QueryClient\s*\(|\bQueryClientProvider\b|\buseQuery\s*\(\s*\{?[^)]*queryKey\s*:|\buseInfiniteQuery\s*\(|\buseMutation\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Vercel", Product: "Vercel AI SDK",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "vercel-ai-package",
					Regex:      regexp.MustCompile(`(?:^|[/"'])(?:ai)(?:/(?:react|svelte|vue|solid|rsc))?["']|@ai-sdk/(?:openai|anthropic|google|mistral|cohere|amazon-bedrock|azure|xai|deepseek|provider|provider-utils|react|svelte|vue|solid|rsc|ui-utils)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "vercel-ai-symbol",
					Regex:      regexp.MustCompile(`\buseChat\s*\(|\buseCompletion\s*\(|\buseAssistant\s*\(|\bstreamText\s*\(\s*\{|\bgenerateText\s*\(\s*\{|\bgenerateObject\s*\(\s*\{|\bstreamUI\s*\(\s*\{`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- React state management libraries -------------------
		{
			Vendor: "Redux", Product: "Redux / Redux Toolkit",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "redux-package",
					Regex:      regexp.MustCompile(`@reduxjs/toolkit|["']redux["']|["']react-redux["']|redux-(?:thunk|saga|persist|logger|observable)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "redux-devtools-symbol",
					Regex:      regexp.MustCompile(`window\.__REDUX_DEVTOOLS_EXTENSION__|__REDUX_DEVTOOLS_EXTENSION_COMPOSE__|\bconfigureStore\s*\(\s*\{[^}]*reducer\s*:|\bcreateSlice\s*\(\s*\{[^}]*name\s*:|\bcreateAsyncThunk\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Poimandres", Product: "Zustand",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "zustand-package",
					Regex:      regexp.MustCompile(`["']zustand["']|zustand/(?:middleware|vanilla|shallow|context|traditional)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "zustand-symbol",
					Regex:      regexp.MustCompile(`\bcreate\s*\(\s*\(\s*set\s*[,)]\s*get\s*\)\s*=>|\bcreateStore\s*\(\s*\(\s*set\s*[,)]|\bsubscribeWithSelector\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Jotai", Product: "Jotai",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "jotai-package",
					Regex:      regexp.MustCompile(`["']jotai["']|jotai/(?:utils|vanilla|babel|query|tanstack-query|valtio|immer)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "jotai-symbol",
					Regex:      regexp.MustCompile(`\bnew Jotai\b|\bcreateStore\s*\(\s*\)|\batomWithStorage\s*\(|\buseAtomValue\s*\(|\buseSetAtom\s*\(|\b\w+\s*=\s*atom\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "MobX", Product: "MobX",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "mobx-package",
					Regex:      regexp.MustCompile(`["']mobx["']|mobx-(?:react|react-lite|state-tree|persist-store|undo|formatters)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "mobx-symbol",
					Regex:      regexp.MustCompile(`window\.__MOBX_DEVTOOLS_GLOBAL_HOOK__|\bmakeObservable\s*\(|\bmakeAutoObservable\s*\(|\bobservable\.(?:box|map|set|object|ref|deep|struct)\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Stately", Product: "XState",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "xstate-package",
					Regex:      regexp.MustCompile(`["']xstate["']|@xstate/(?:react|vue|svelte|solid|store|graph|test|inspect|cli|fsm)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "xstate-symbol",
					Regex:      regexp.MustCompile(`\bcreateMachine\s*\(\s*\{|\bsetup\s*\(\s*\{[^}]*types\s*:|\bcreateActor\s*\(|\buseMachine\s*\(|\buseSelector\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Vector DBs (RAG/AI infrastructure) -----------------
		{
			Vendor: "Pinecone Systems", Product: "Pinecone",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "pinecone-sdk",
					Regex:      regexp.MustCompile(`@pinecone-database/pinecone|cdn\.jsdelivr\.net/npm/@pinecone-database/pinecone`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "pinecone-endpoint",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+-[a-z0-9]{6})\.svc\.[a-z0-9-]+\.pinecone\.io`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "pinecone-env",
					Regex:      regexp.MustCompile(`PINECONE_(?:API_KEY|ENVIRONMENT|INDEX|HOST|PROJECT_ID)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Weaviate", Product: "Weaviate (client)",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "weaviate-sdk",
					Regex:      regexp.MustCompile(`weaviate-(?:ts-client|client|graphql-client)|cdn\.jsdelivr\.net/npm/weaviate-`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "weaviate-endpoint",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.weaviate\.(?:cloud|network)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Qdrant", Product: "Qdrant (client)",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "qdrant-sdk",
					Regex:      regexp.MustCompile(`@qdrant/js-client-(?:rest|grpc)|cdn\.jsdelivr\.net/npm/@qdrant/js-client`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "qdrant-endpoint",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-f0-9-]{36})\.(?:[a-z0-9-]+\.)?cloud\.qdrant\.io`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Chroma", Product: "Chroma (client)",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name:       "chromadb-sdk",
				Regex:      regexp.MustCompile(`["']chromadb["']|cdn\.jsdelivr\.net/npm/chromadb`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- React UI component libraries -----------------------
		{
			Vendor: "Chakra UI", Product: "Chakra UI",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "chakra-package",
					Regex:      regexp.MustCompile(`@chakra-ui/(?:react|core|theme|icons|next-js|provider|system|styled-system|css-reset)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "chakra-symbol",
					Regex:      regexp.MustCompile(`\bChakraProvider\b|\bextendTheme\s*\(|\buseToast\s*\(|\buseDisclosure\s*\(\s*\)`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Mantine", Product: "Mantine",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "mantine-package",
					Regex:      regexp.MustCompile(`@mantine/(?:core|hooks|form|dates|notifications|modals|carousel|dropzone|nprogress|prism|rte|spotlight|tiptap|charts|emotion|next|styles|vanilla-extract)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "mantine-symbol",
					Regex:      regexp.MustCompile(`\bMantineProvider\b|\bcreateTheme\s*\(\s*\{|\buseMantineTheme\s*\(\s*\)|\buseMantineColorScheme\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Radix UI", Product: "Radix UI",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "radix-package",
					Regex:      regexp.MustCompile(`@radix-ui/(?:react-|colors|themes)|@radix-ui/themes/styles\.css`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "radix-symbol",
					Regex:      regexp.MustCompile(`\bTheme\s*=\s*RadixThemes|RadixThemes\.|\bDialog\.Root\b|\bDropdownMenu\.Root\b|\bPopover\.Root\b|\bTooltip\.Provider\b`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "NextUI / HeroUI", Product: "NextUI (HeroUI)",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "nextui-package",
					Regex:      regexp.MustCompile(`@(?:nextui-org|heroui)/(?:react|theme|system|use-clipboard|button|card|input|modal|table|dropdown|tabs|popover)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "nextui-symbol",
					Regex:      regexp.MustCompile(`\bNextUIProvider\b|\bHeroUIProvider\b|\bnextui\s*\(\s*\{|\bheroui\s*\(\s*\{`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Socket.IO", Product: "Socket.IO (client)",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "socketio-package",
					Regex:      regexp.MustCompile(`socket\.io-client|cdn\.socket\.io/[\d.]+/socket\.io\.(?:min\.)?js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "socketio-connect",
					Regex:      regexp.MustCompile(`\bio\s*\(\s*['"]https?://[^'"]+['"]|\bio\s*\(\s*\{[^}]*transports\s*:\s*\[|\bnew\s+Manager\s*\(\s*['"]https?://`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Realtime / collaboration backends ------------------
		{
			Vendor: "Convex", Product: "Convex",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "convex-package",
					Regex:      regexp.MustCompile(`["']convex/(?:react|browser|server|values|nextjs|svelte|vue|react-clerk|react-auth0)["']`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "convex-endpoint",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.convex\.cloud`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "convex-client",
					Regex:      regexp.MustCompile(`\bnew\s+ConvexReactClient\s*\(|\bConvexProvider\s+client=|NEXT_PUBLIC_CONVEX_URL`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Liveblocks", Product: "Liveblocks",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "liveblocks-package",
					Regex:      regexp.MustCompile(`@liveblocks/(?:client|react|node|yjs|zustand|redux|emails|core)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "liveblocks-init",
					Regex:      regexp.MustCompile(`\bcreateClient\s*\(\s*\{[^}]*(?:publicApiKey|authEndpoint)\s*:\s*['"](?P<id>pk_[a-zA-Z0-9_-]{20,})['"]|\bLiveblocksProvider\b|\bcreateRoomContext\b`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "PartyKit", Product: "PartyKit",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "partykit-package",
					Regex:      regexp.MustCompile(`partysocket|["']partykit/(?:client|server)["']`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "partykit-endpoint",
					Regex:      regexp.MustCompile(`https?://(?P<id>[a-z0-9-]+)\.(?:[a-z0-9-]+\.)?partykit\.dev|wss?://[a-z0-9-]+\.partykit\.dev`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Turso", Product: "Turso (libSQL)",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "turso-sdk",
					Regex:      regexp.MustCompile(`@libsql/(?:client|core|hrana-client|isomorphic-fetch|isomorphic-ws)|["']libsql["']`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "turso-endpoint",
					Regex:      regexp.MustCompile(`(?:libsql|https?)://(?P<id>[a-z0-9-]+)-[a-z0-9-]+\.turso\.io`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Transactional email SDKs ---------------------------
		{
			Vendor: "Resend", Product: "Resend",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "resend-sdk",
					Regex:      regexp.MustCompile(`["']resend["']|@react-email/components`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "resend-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.resend\.com/(?P<id>emails|domains|audiences|broadcasts|contacts|api-keys)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "resend-key-pattern",
					Regex:      regexp.MustCompile(`["'](re_[A-Za-z0-9_-]{20,})["']`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Twilio", Product: "SendGrid",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "sendgrid-sdk",
					Regex:      regexp.MustCompile(`@sendgrid/(?:mail|client|helpers|inbound-mail-parser|eventwebhook)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "sendgrid-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.sendgrid\.com/v3/(?P<id>mail/send|marketing|user|templates|sender_authentication|contactdb)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "sendgrid-key-pattern",
					Regex:      regexp.MustCompile(`["'](SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})["']`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "ActiveCampaign", Product: "Postmark",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "postmark-sdk",
					Regex:      regexp.MustCompile(`["']postmark["']|cdn\.jsdelivr\.net/npm/postmark`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "postmark-endpoint",
					Regex:      regexp.MustCompile(`https?://api\.postmarkapp\.com/(?P<id>email|messages|servers|templates|bounces|stats|domains)`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Mailgun", Product: "Mailgun",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "mailgun-sdk",
					Regex:      regexp.MustCompile(`["']mailgun\.js["']|["']mailgun-js["']|@mailgun/`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "mailgun-endpoint",
					Regex:      regexp.MustCompile(`https?://api(?:\.eu|\.us)?\.mailgun\.net/v3/(?P<id>[a-z0-9.-]+)/messages`),
					Kind:       SignalEndpointURL,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "mailgun-key-pattern",
					Regex:      regexp.MustCompile(`["'](key-[a-f0-9]{32})["']`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- ORMs and query builders ----------------------------
		{
			Vendor: "Drizzle Team", Product: "Drizzle ORM",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "drizzle-package",
					Regex:      regexp.MustCompile(`drizzle-orm(?:/(?:pg-core|mysql-core|sqlite-core|d1|libsql|neon|postgres-js|node-postgres|mysql2|better-sqlite3|bun-sqlite|expo-sqlite|vercel-postgres|planetscale-serverless|aws-data-api|sql\.js))?|drizzle-kit`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "drizzle-symbol",
					Regex:      regexp.MustCompile(`\bdrizzle\s*\(\s*\w+\s*\)|\bpgTable\s*\(\s*['"]|\bmysqlTable\s*\(\s*['"]|\bsqliteTable\s*\(\s*['"]|\beq\s*\(\s*\w+\.\w+|drizzle-zod`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Customer support / live chat widgets ----------------
		{
			Vendor: "Intercom", Product: "Intercom (widget)",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "intercom-widget",
					Regex:      regexp.MustCompile(`widget\.intercom\.io/widget/(?P<id>[a-z0-9]{8,12})|js\.intercomcdn\.com`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "intercom-boot",
					Regex:      regexp.MustCompile(`window\.intercomSettings\s*=\s*\{[^}]*app_id\s*:\s*['"](?P<id>[a-z0-9]{8,12})['"]|\bIntercom\s*\(\s*['"]boot['"]\s*,\s*\{`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Crisp", Product: "Crisp Chat",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "crisp-widget",
					Regex:      regexp.MustCompile(`client\.crisp\.chat/(?:l\.js|metrics/widget\.js)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "crisp-website-id",
					Regex:      regexp.MustCompile(`window\.CRISP_WEBSITE_ID\s*=\s*['"](?P<id>[a-f0-9-]{36})['"]|CRISP_TOKEN_ID`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Salesforce", Product: "Drift",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "drift-widget",
					Regex:      regexp.MustCompile(`js\.driftt?\.com/include/[\d.]+/(?P<id>[a-z0-9]+)\.js|js\.drift\.com/playbookUrl`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "drift-load",
					Regex:      regexp.MustCompile(`drift\.load\s*\(\s*['"](?P<id>[a-z0-9]+)['"]\s*\)|window\.drift\.SNIPPET_VERSION`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Zendesk", Product: "Zendesk Web Widget",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "zendesk-widget",
					Regex:      regexp.MustCompile(`static\.zdassets\.com/ekr/snippet\.js\?key=(?P<id>[a-f0-9-]{36})|widget-mediator\.zopim\.com`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Background jobs / workflow platforms ----------------
		{
			Vendor: "Trigger.dev", Product: "Trigger.dev",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "trigger-sdk",
					Regex:      regexp.MustCompile(`@trigger\.dev/(?:sdk|core|react|nextjs|express|sveltekit|nuxt|astro|hono|build|cli)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "trigger-define-job",
					Regex:      regexp.MustCompile(`\bclient\.defineJob\s*\(|\btask\s*\(\s*\{[^}]*id\s*:|\bnew TriggerClient\s*\(`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "trigger-env",
					Regex:      regexp.MustCompile(`TRIGGER_(?:API_KEY|API_URL|SECRET_KEY|PUBLIC_API_KEY|PROJECT_ID)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Inngest", Product: "Inngest",
			Category: CategoryBaaS,
			Patterns: []Pattern{
				{
					Name:       "inngest-sdk",
					Regex:      regexp.MustCompile(`["']inngest["']|inngest/(?:next|express|fastify|astro|nuxt|sveltekit|h3|edge|cloudflare|deno|bun|node)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "inngest-create",
					Regex:      regexp.MustCompile(`\bnew Inngest\s*\(\s*\{|\binngest\.createFunction\s*\(|\binngest\.send\s*\(\s*\{[^}]*name\s*:|\bserve\s*\(\s*\{[^}]*client\s*:`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "inngest-env",
					Regex:      regexp.MustCompile(`INNGEST_(?:EVENT_KEY|SIGNING_KEY|API_BASE_URL|DEV)`),
					Kind:       SignalEnvVarName,
					Confidence: ConfidenceMedium,
				},
			},
		},

		// --- Legacy web JS (high install base, often vulnerable) -
		{
			Vendor: "jQuery Foundation", Product: "jQuery",
			Category: CategoryGeneric,
			Patterns: []Pattern{
				{
					Name:       "jquery-cdn",
					Regex:      regexp.MustCompile(`code\.jquery\.com/jquery-(?P<id>[\d.]+)(?:\.slim)?(?:\.min)?\.js|cdn\.jsdelivr\.net/npm/jquery@(?P<id2>[\d.]+)|ajax\.googleapis\.com/ajax/libs/jquery/(?P<id3>[\d.]+)/jquery`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "jquery-symbol",
					Regex:      regexp.MustCompile(`\bwindow\.jQuery\b|\bjQuery\.fn\.jquery\b|\bjQuery\s*\(\s*function\s*\(\$\)|\bjQuery\(document\)\.ready`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Bootstrap Core Team", Product: "Bootstrap",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "bootstrap-cdn",
					Regex:      regexp.MustCompile(`cdn\.jsdelivr\.net/npm/bootstrap@(?P<id>[\d.]+)|stackpath\.bootstrapcdn\.com/bootstrap/(?P<id2>[\d.]+)|maxcdn\.bootstrapcdn\.com/bootstrap/(?P<id3>[\d.]+)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "bootstrap-attrs",
					Regex:      regexp.MustCompile(`\bdata-bs-(?:toggle|target|dismiss|placement|theme|spy|ride|interval|wrap|content|trigger|html|original-title)=|<link[^>]+href="[^"]*bootstrap(?:[.-][\d.]+)?(?:\.min)?\.css"`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Known-compromised supply-chain risk (HIGH CTI VALUE) -
		// In mid-2024 the polyfill.io CDN was sold to a malicious
		// actor and began serving malware to ~100K sites. Detecting
		// any reference is a flag-worthy finding even though the
		// domain may rotate ownership again.
		{
			Vendor: "Funnull (compromised)", Product: "polyfill.io (supply-chain risk)",
			Category: CategoryGeneric,
			Patterns: []Pattern{{
				Name:       "polyfill-io-reference",
				Regex:      regexp.MustCompile(`(?:cdn\.|cdn3\.)?polyfill\.io/(?:v\d+|polyfill)(?:\.min)?\.js|polyfill\.io/v\d+/polyfill`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Denis Pushkarev", Product: "core-js (polyfill)",
			Category: CategoryGeneric,
			Patterns: []Pattern{{
				Name:       "core-js-cdn",
				Regex:      regexp.MustCompile(`cdn\.jsdelivr\.net/npm/core-js@?(?P<id>[\d.]+)?|unpkg\.com/core-js@?(?P<id2>[\d.]+)?|cdnjs\.cloudflare\.com/ajax/libs/core-js/(?P<id3>[\d.]+)`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- Ad tracking pixels (privacy/compliance signals) -----
		{
			Vendor: "Meta", Product: "Facebook Pixel",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "fb-pixel-script",
					Regex:      regexp.MustCompile(`connect\.facebook\.net/[a-z_]+/fbevents\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "fb-pixel-init",
					Regex:      regexp.MustCompile(`\bfbq\s*\(\s*['"]init['"]\s*,\s*['"](?P<id>\d{15,16})['"]|\bfbq\.queue\b|\b_fbp\b`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "LinkedIn", Product: "LinkedIn Insight Tag",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "linkedin-script",
					Regex:      regexp.MustCompile(`snap\.licdn\.com/li\.lms-analytics/insight\.min\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "linkedin-partner-id",
					Regex:      regexp.MustCompile(`_linkedin_partner_id\s*=\s*['"](?P<id>\d{4,10})['"]|window\._linkedin_data_partner_ids`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "TikTok / ByteDance", Product: "TikTok Pixel",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "tiktok-script",
					Regex:      regexp.MustCompile(`analytics\.tiktok\.com/i18n/pixel/events\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "tiktok-pixel-id",
					Regex:      regexp.MustCompile(`\bttq\.load\s*\(\s*['"](?P<id>[A-Z0-9]{20})['"]|window\.TiktokAnalyticsObject`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "X / Twitter", Product: "X (Twitter) Pixel",
			Category: CategoryAnalytics,
			Patterns: []Pattern{
				{
					Name:       "x-pixel-script",
					Regex:      regexp.MustCompile(`static\.ads-twitter\.com/uwt\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "x-pixel-config",
					Regex:      regexp.MustCompile(`\btwq\s*\(\s*['"](?:init|config)['"]\s*,\s*['"](?P<id>[a-z0-9]{5,8})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Reddit", Product: "Reddit Pixel",
			Category: CategoryAnalytics,
			Patterns: []Pattern{{
				Name:       "reddit-pixel",
				Regex:      regexp.MustCompile(`www\.redditstatic\.com/ads/pixel\.js|\brdt\s*\(\s*['"]init['"]\s*,\s*['"](?P<id>t2_[a-z0-9]{6,12})['"]`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Pinterest", Product: "Pinterest Tag",
			Category: CategoryAnalytics,
			Patterns: []Pattern{{
				Name:       "pinterest-tag",
				Regex:      regexp.MustCompile(`s\.pinimg\.com/ct/core\.js|\bpintrk\s*\(\s*['"]load['"]\s*,\s*['"](?P<id>\d{13,16})['"]`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- Maps APIs (often expose unrestricted keys) ----------
		{
			Vendor: "Google", Product: "Google Maps JavaScript API",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "gmaps-script",
					Regex:      regexp.MustCompile(`maps\.googleapis\.com/maps/api/js\?(?:[^"']*&)?key=(?P<id>AIza[A-Za-z0-9_-]{35})`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "gmaps-symbol",
					Regex:      regexp.MustCompile(`\bnew google\.maps\.Map\s*\(|google\.maps\.LatLng\s*\(|google\.maps\.places\.Autocomplete`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Mapbox", Product: "Mapbox GL JS",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "mapbox-script",
					Regex:      regexp.MustCompile(`api\.mapbox\.com/mapbox-gl-js/v?(?P<id>[\d.]+)/mapbox-gl(?:\.min)?\.js|cdn\.jsdelivr\.net/npm/mapbox-gl@(?P<id2>[\d.]+)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "mapbox-token",
					Regex:      regexp.MustCompile(`mapboxgl\.accessToken\s*=\s*['"](?P<id>pk\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['"]`),
					Kind:       SignalPublicKey,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- CAPTCHA / bot mitigation ----------------------------
		{
			Vendor: "Google", Product: "reCAPTCHA",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "recaptcha-script",
					Regex:      regexp.MustCompile(`(?:www\.)?google\.com/recaptcha/(?:api\.js|enterprise\.js)|www\.recaptcha\.net/recaptcha/api\.js|recaptcha/api\.js\?render=(?P<id>6L[A-Za-z0-9_-]{38,40})`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "recaptcha-sitekey",
					Regex:      regexp.MustCompile(`(?:class="g-recaptcha"\s+)?data-sitekey=['"](?P<id>6L[A-Za-z0-9_-]{38,40})['"]|grecaptcha\.execute\s*\(\s*['"](?P<id2>6L[A-Za-z0-9_-]{38,40})['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Intuition Machines", Product: "hCaptcha",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name:       "hcaptcha-script",
					Regex:      regexp.MustCompile(`(?:js\.|api\.)?hcaptcha\.com/(?:1/api\.js|captcha/v1)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "hcaptcha-sitekey",
					Regex:      regexp.MustCompile(`(?:class="h-captcha"\s+)?data-sitekey=['"](?P<id>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['"]|hcaptcha\.execute\s*\(`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Friendly Captcha", Product: "Friendly Captcha",
			Category: CategoryAuth,
			Patterns: []Pattern{{
				Name:       "friendlycaptcha",
				Regex:      regexp.MustCompile(`cdn\.jsdelivr\.net/npm/friendly-challenge|class="frc-captcha"|data-sitekey=['"](?P<id>FC[A-Z0-9_-]{20,})['"]`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- Payment processors ---------------------------------
		{
			Vendor: "Plaid", Product: "Plaid Link",
			Category: CategoryPayments,
			Patterns: []Pattern{
				{
					Name:       "plaid-script",
					Regex:      regexp.MustCompile(`cdn\.plaid\.com/link/v\d+/stable/link-initialize\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "plaid-create",
					Regex:      regexp.MustCompile(`Plaid\.create\s*\(\s*\{[^}]*token\s*:\s*['"](?P<id>link-(?:sandbox|development|production)-[a-f0-9-]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Klarna", Product: "Klarna Checkout / Payments",
			Category: CategoryPayments,
			Patterns: []Pattern{
				{
					Name:       "klarna-script",
					Regex:      regexp.MustCompile(`x\.klarnacdn\.net/(?:kp|on-site-messaging|checkout)/lib/v\d+/(?:lib|messaging|api)\.js|js\.klarna\.com/web-sdk/v\d+/klarna\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "klarna-mid",
					Regex:      regexp.MustCompile(`data-client-id=['"](?P<id>[a-f0-9-]{36})['"]|window\.klarnaAsyncCallback`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Block", Product: "Square Web Payments SDK",
			Category: CategoryPayments,
			Patterns: []Pattern{
				{
					Name:       "square-script",
					Regex:      regexp.MustCompile(`(?:sandbox\.)?web\.squarecdn\.com/v1/square\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "square-payments",
					Regex:      regexp.MustCompile(`\bSquare\.payments\s*\(\s*['"](?P<id>sq0idp-[A-Za-z0-9_-]+)['"]|\bSquare\.payments\s*\(\s*['"](?P<id2>sandbox-sq0idb-[A-Za-z0-9_-]+)['"]`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Paddle", Product: "Paddle Checkout",
			Category: CategoryPayments,
			Patterns: []Pattern{
				{
					Name:       "paddle-script",
					Regex:      regexp.MustCompile(`cdn\.paddle\.com/paddle/(?:v2/)?paddle\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "paddle-setup",
					Regex:      regexp.MustCompile(`Paddle\.Setup\s*\(\s*\{[^}]*(?:vendor|seller)\s*:\s*(?P<id>\d{4,8})|Paddle\.Environment\.set`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Exposed webhook URLs (very-high-value CTI findings) -
		// A webhook URL in a publicly served JS bundle lets anyone
		// post to that Slack channel / Discord channel until the
		// secret is rotated. Detection is high-CTI because remediation
		// is one-click for the victim.
		{
			Vendor: "Slack (exposed)", Product: "Slack incoming webhook URL",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "slack-webhook-url",
				Regex:      regexp.MustCompile(`https?://hooks\.slack\.com/services/(?P<id>T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{24})`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Discord (exposed)", Product: "Discord webhook URL",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "discord-webhook-url",
				Regex:      regexp.MustCompile(`https?://(?:discord\.com|discordapp\.com|ptb\.discord\.com|canary\.discord\.com)/api/(?:v\d+/)?webhooks/(?P<id>\d{17,20}/[A-Za-z0-9_-]{60,80})`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Atlassian (exposed)", Product: "Microsoft Teams / Atlassian webhook URL",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "teams-webhook-url",
				Regex:      regexp.MustCompile(`https?://outlook\.office\.com/webhook/(?P<id>[a-f0-9-]{36}@[a-f0-9-]{36}/IncomingWebhook/[a-f0-9]{32}/[a-f0-9-]{36})`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- Comments / discussion widgets ----------------------
		{
			Vendor: "Disqus", Product: "Disqus",
			Category: CategoryMonitoring,
			Patterns: []Pattern{
				{
					Name:       "disqus-script",
					Regex:      regexp.MustCompile(`(?:https?://)?(?P<id>[a-z0-9-]+)\.disqus\.com/embed\.js|disqus\.com/count\.js`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "disqus-shortname",
					Regex:      regexp.MustCompile(`disqus_config\s*=\s*function|disqus_shortname\s*=\s*['"](?P<id>[a-z0-9-]+)['"]|var\s+disqus_thread\s*=`),
					Kind:       SignalConfigLiteral,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Giscus", Product: "Giscus (GitHub Discussions)",
			Category: CategoryMonitoring,
			Patterns: []Pattern{{
				Name:       "giscus-script",
				Regex:      regexp.MustCompile(`giscus\.app/client\.js|data-repo=['"](?P<id>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)['"]\s*data-repo-id=`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- Video players --------------------------------------
		{
			Vendor: "Brightcove", Product: "Video.js",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{
				{
					Name:       "videojs-cdn",
					Regex:      regexp.MustCompile(`vjs\.zencdn\.net/(?P<id>[\d.]+)/video(?:-js)?(?:\.min)?\.js|cdn\.jsdelivr\.net/npm/video\.js@(?P<id2>[\d.]+)`),
					Kind:       SignalScriptSrc,
					Confidence: ConfidenceHigh,
				},
				{
					Name:       "videojs-symbol",
					Regex:      regexp.MustCompile(`\bvideojs\s*\(\s*['"][^'"]+['"]\s*,\s*\{|\bvideojs\.getPlayer\s*\(|class="video-js`),
					Kind:       SignalGlobalSymbol,
					Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Vimeo", Product: "Vimeo Player",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{{
				Name:       "vimeo-player",
				Regex:      regexp.MustCompile(`player\.vimeo\.com/api/player\.js|player\.vimeo\.com/video/(?P<id>\d{7,12})`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Bitmovin", Product: "HLS.js",
			Category: CategoryHeadlessUI,
			Patterns: []Pattern{{
				Name:       "hlsjs-cdn",
				Regex:      regexp.MustCompile(`cdn\.jsdelivr\.net/npm/hls\.js@(?P<id>[\d.]+)|cdnjs\.cloudflare\.com/ajax/libs/hls\.js/(?P<id2>[\d.]+)/hls(?:\.min)?\.js|\bnew\s+Hls\s*\(\s*\{`),
				Kind:       SignalScriptSrc,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- IP geolocation APIs --------------------------------
		{
			Vendor: "IPinfo", Product: "ipinfo.io",
			Category: CategoryBaaS,
			Patterns: []Pattern{{
				Name:       "ipinfo-endpoint",
				Regex:      regexp.MustCompile(`https?://ipinfo\.io/(?:json|geo|[\d.]+/json|country|city|loc)(?:\?token=(?P<id>[a-f0-9]{14,20}))?|api\.ipinfo\.io`),
				Kind:       SignalEndpointURL,
				Confidence: ConfidenceHigh,
			}},
		},

		// --- Generic secret-token leakage (highest CTI value) ----
		// Cloud/SCM access tokens shipped in a public JS bundle are
		// immediately-exploitable; rotation is the only fix. The
		// patterns deliberately match the strict canonical formats
		// to keep false positives near zero.
		{
			Vendor: "Amazon (exposed)", Product: "AWS Access Key ID",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "aws-akia",
				Regex:      regexp.MustCompile(`\b(?P<id>(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "GitHub (exposed)", Product: "GitHub Personal Access Token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "github-pat",
				Regex:      regexp.MustCompile(`\b(?P<id>gh[pousr]_[A-Za-z0-9]{36,255})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "GitHub (exposed)", Product: "GitHub fine-grained PAT",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "github-finegrained-pat",
				Regex:      regexp.MustCompile(`\b(?P<id>github_pat_[A-Z0-9]{22}_[A-Za-z0-9_]{59})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "GitLab (exposed)", Product: "GitLab Personal Access Token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "gitlab-pat",
				Regex:      regexp.MustCompile(`\b(?P<id>glpat-[A-Za-z0-9_-]{20,})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Generic (exposed)", Product: "JWT bearer token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "jwt-token",
				Regex:      regexp.MustCompile(`\b(?P<id>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceMedium,
			}},
		},
		{
			Vendor: "Atlassian (exposed)", Product: "Atlassian API Token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "atlassian-token",
				Regex:      regexp.MustCompile(`\b(?P<id>ATATT3[A-Za-z0-9_-]{180,})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Square (exposed)", Product: "Square Access Token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "square-token",
				Regex:      regexp.MustCompile(`\b(?P<id>EAAA[A-Za-z0-9_-]{56,})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "PyPI (exposed)", Product: "PyPI API Token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "pypi-token",
				Regex:      regexp.MustCompile(`\b(?P<id>pypi-[A-Za-z0-9_-]{50,})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "npm (exposed)", Product: "npm Access Token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "npm-token",
				Regex:      regexp.MustCompile(`\b(?P<id>npm_[A-Za-z0-9]{36})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Slack (exposed)", Product: "Slack OAuth token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "slack-oauth-token",
				Regex:      regexp.MustCompile(`\b(?P<id>xox[abprs]-(?:\d+-){1,4}[A-Za-z0-9]{20,40})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Twilio (exposed)", Product: "Twilio Account SID",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "twilio-account-sid",
				Regex:      regexp.MustCompile(`\b(?P<id>AC[a-f0-9]{32})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Mailchimp (exposed)", Product: "Mailchimp API Key",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "mailchimp-key",
				Regex:      regexp.MustCompile(`\b(?P<id>[a-f0-9]{32}-us\d{1,3})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Stripe (exposed)", Product: "Stripe Restricted / Secret Key",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "stripe-restricted-key",
				Regex:      regexp.MustCompile(`\b(?P<id>(?:rk|sk)_(?:live|test)_[A-Za-z0-9]{24,99})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Cloudflare (exposed)", Product: "Cloudflare API Token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "cloudflare-api-token",
				Regex:      regexp.MustCompile(`\b(?P<id>v1\.0-[a-f0-9]{40,128})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceMedium,
			}},
		},
		{
			Vendor: "HashiCorp (exposed)", Product: "Vault token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "vault-token",
				Regex:      regexp.MustCompile(`\b(?P<id>hv[bs]\.[A-Za-z0-9_-]{24,200})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Doppler (exposed)", Product: "Doppler service token",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "doppler-token",
				Regex:      regexp.MustCompile(`\b(?P<id>dp\.(?:pt|st|ct|sa|scim|audit)\.[a-z]{1,6}_?[A-Za-z0-9_-]{20,60})\b`),
				Kind:       SignalPublicKey,
				Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Apple (exposed)", Product: "App Store Connect API key reference",
			Category: CategorySecretLeak,
			Patterns: []Pattern{{
				Name:       "apple-asc-key",
				Regex:      regexp.MustCompile(`\b(?:APP_STORE_CONNECT_API_KEY_ID|ASC_KEY_ID)\s*[:=]\s*['"]?(?P<id>[A-Z0-9]{10})['"]?`),
				Kind:       SignalConfigLiteral,
				Confidence: ConfidenceMedium,
			}},
		},
	}
}
