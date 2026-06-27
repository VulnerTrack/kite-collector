package headerfingerprint

import "regexp"

// DefaultCatalog returns the seed Signature set for HTTP-header based
// fingerprinting. Patterns split between three sources of evidence:
// (1) Server / X-Powered-By / X-Generator value regexes that identify
// the runtime or CMS, (2) vendor-specific request-id headers
// (CF-Ray, X-Vercel-Id, Fly-Request-Id, X-Amz-Cf-Pop) that prove the
// origin is fronted by a known provider, and (3) Set-Cookie name
// patterns that pin down a session library (PHPSESSID = PHP,
// JSESSIONID = Java servlet container, connect.sid = Express, etc.).
func DefaultCatalog() []Signature {
	return []Signature{
		// --- Web servers (Server header) ---------------------------
		{
			Vendor: "F5 NGINX", Product: "nginx",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-nginx", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^nginx(/[\d.]+)?$`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Apache httpd",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-apache", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^Apache(/[\d.]+)?(\s|$)`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Microsoft", Product: "IIS",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-iis", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)Microsoft-IIS`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Stack Holdings", Product: "Caddy",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-caddy", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^Caddy`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "LiteSpeed Technologies", Product: "LiteSpeed / OpenLiteSpeed",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-litespeed", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)(open)?LiteSpeed`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "lighttpd", Product: "lighttpd",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-lighttpd", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^lighttpd`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Alibaba", Product: "Tengine",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-tengine", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^Tengine`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "H2O", Product: "h2o",
			Category: CategoryWebServer,
			Patterns: []Pattern{{
				Name: "server-h2o", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^h2o`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},

		// --- App runtimes / framework signatures -------------------
		{
			Vendor: "Erlang Solutions", Product: "Cowboy (Phoenix)",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-cowboy", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^Cowboy`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Pallets Projects", Product: "Werkzeug (Flask)",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-werkzeug", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)Werkzeug`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Benoit Chesneau", Product: "gunicorn",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-gunicorn", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^gunicorn`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Encode OSS", Product: "uvicorn / Starlette",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-uvicorn", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^uvicorn`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Puma HTTP", Product: "Puma (Ruby)",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-puma", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^puma`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Phusion", Product: "Phusion Passenger",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "x-powered-by-passenger", HeaderName: "X-Powered-By",
				ValueRegex: regexp.MustCompile(`(?i)Phusion Passenger`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Tomcat",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-tomcat", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)Apache-Coyote|Tomcat`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Eclipse Foundation", Product: "Jetty",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-jetty", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^Jetty`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Microsoft", Product: "Kestrel (ASP.NET Core)",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-kestrel", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^Kestrel`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Express Foundation", Product: "Express (Node.js)",
			Category: CategoryFramework,
			Patterns: []Pattern{
				{
					Name: "x-powered-by-express", HeaderName: "X-Powered-By",
					ValueRegex: regexp.MustCompile(`(?i)^Express`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "cookie-connect-sid", CookieName: "connect.sid",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Microsoft", Product: "ASP.NET",
			Category: CategoryFramework,
			Patterns: []Pattern{
				{
					Name: "x-aspnet-version", HeaderName: "X-AspNet-Version",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-powered-by-aspnet", HeaderName: "X-Powered-By",
					ValueRegex: regexp.MustCompile(`(?i)ASP\.NET`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "cookie-aspnet-session", CookieName: "ASP.NET_SessionId",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Rails Core Team", Product: "Ruby on Rails",
			Category: CategoryFramework,
			Patterns: []Pattern{
				{
					Name: "cookie-rails-session", CookieName: "_session_id",
					Kind: SignalCookieName, Confidence: ConfidenceMedium,
				},
				{
					Name: "x-runtime", HeaderName: "X-Runtime",
					Kind: SignalHeaderName, Confidence: ConfidenceMedium,
				},
			},
		},
		{
			Vendor: "Laravel", Product: "Laravel (PHP)",
			Category: CategoryFramework,
			Patterns: []Pattern{
				{
					Name: "cookie-laravel-session", CookieName: "laravel_session",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
				{
					Name: "cookie-xsrf-token", CookieName: "XSRF-TOKEN",
					Kind: SignalCookieName, Confidence: ConfidenceLow,
				},
			},
		},
		{
			Vendor: "Sails", Product: "Sails.js",
			Category: CategoryFramework,
			Patterns: []Pattern{{
				Name: "cookie-sails-sid", CookieName: "sails.sid",
				Kind: SignalCookieName, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "The PHP Group", Product: "PHP",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{
				{
					Name: "x-powered-by-php", HeaderName: "X-Powered-By",
					ValueRegex: regexp.MustCompile(`(?i)^PHP(/[\d.]+)?$`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "cookie-phpsessid", CookieName: "PHPSESSID",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Java Servlet Container",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "cookie-jsessionid", CookieName: "JSESSIONID",
				Kind: SignalCookieName, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Vercel", Product: "Next.js (X-Powered-By)",
			Category: CategoryFramework,
			Patterns: []Pattern{{
				Name: "x-powered-by-next", HeaderName: "X-Powered-By",
				ValueRegex: regexp.MustCompile(`(?i)^Next\.js`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},

		// --- CDN / edge providers ----------------------------------
		{
			Vendor: "Cloudflare", Product: "Cloudflare edge",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "cf-ray", HeaderName: "CF-Ray",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "cf-cache-status", HeaderName: "CF-Cache-Status",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "server-cloudflare", HeaderName: "Server",
					ValueRegex: regexp.MustCompile(`(?i)^cloudflare`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Amazon", Product: "AWS CloudFront",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "x-amz-cf-pop", HeaderName: "X-Amz-Cf-Pop",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-amz-cf-id", HeaderName: "X-Amz-Cf-Id",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "via-cloudfront", HeaderName: "Via",
					ValueRegex: regexp.MustCompile(`(?i)cloudfront`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Fastly", Product: "Fastly CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "x-served-by-fastly", HeaderName: "X-Served-By",
					ValueRegex: regexp.MustCompile(`(?i)cache-`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceMedium,
				},
				{
					Name: "fastly-debug-digest", HeaderName: "Fastly-Debug-Digest",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-cache-fastly", HeaderName: "X-Cache",
					ValueRegex: regexp.MustCompile(`(?i)Fastly`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Akamai", Product: "Akamai edge",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "akamai-grn", HeaderName: "Akamai-GRN",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-akamai-transformed", HeaderName: "X-Akamai-Transformed",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "server-akamaighost", HeaderName: "Server",
					ValueRegex: regexp.MustCompile(`(?i)AkamaiGHost`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Microsoft", Product: "Azure Front Door / CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{
				{
					Name: "x-azure-ref", HeaderName: "X-Azure-Ref",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-msedge-ref", HeaderName: "X-MSEdge-Ref",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Bunny.net", Product: "Bunny CDN",
			Category: CategoryCDN,
			Patterns: []Pattern{{
				Name: "server-bunnycdn", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)BunnyCDN`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},

		// --- Edge hosting / PaaS -----------------------------------
		{
			Vendor: "Vercel", Product: "Vercel-hosted",
			Category: CategoryEdgeHosting,
			Patterns: []Pattern{
				{
					Name: "x-vercel-id", HeaderName: "X-Vercel-Id",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-vercel-cache", HeaderName: "X-Vercel-Cache",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "server-vercel", HeaderName: "Server",
					ValueRegex: regexp.MustCompile(`(?i)^Vercel`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Netlify", Product: "Netlify-hosted",
			Category: CategoryEdgeHosting,
			Patterns: []Pattern{
				{
					Name: "server-netlify", HeaderName: "Server",
					ValueRegex: regexp.MustCompile(`(?i)Netlify`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-nf-request-id", HeaderName: "X-Nf-Request-Id",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Render", Product: "Render-hosted",
			Category: CategoryEdgeHosting,
			Patterns: []Pattern{{
				Name: "x-render-origin", HeaderName: "X-Render-Origin-Server",
				Kind: SignalHeaderName, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Fly", Product: "Fly.io-hosted",
			Category: CategoryEdgeHosting,
			Patterns: []Pattern{{
				Name: "fly-request-id", HeaderName: "Fly-Request-Id",
				Kind: SignalHeaderName, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Salesforce", Product: "Heroku-hosted",
			Category: CategoryEdgeHosting,
			Patterns: []Pattern{
				{
					Name: "via-heroku", HeaderName: "Via",
					ValueRegex: regexp.MustCompile(`(?i)heroku`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-request-id-heroku", HeaderName: "X-Request-Id",
					Kind: SignalHeaderName, Confidence: ConfidenceLow,
				},
			},
		},
		{
			Vendor: "Railway", Product: "Railway-hosted",
			Category: CategoryEdgeHosting,
			Patterns: []Pattern{{
				Name: "x-railway-request-id", HeaderName: "X-Railway-Request-Id",
				Kind: SignalHeaderName, Confidence: ConfidenceHigh,
			}},
		},

		// --- CMS / specific stacks --------------------------------
		{
			Vendor: "Drupal Association", Product: "Drupal",
			Category: CategoryCMS,
			Patterns: []Pattern{
				{
					Name: "x-generator-drupal", HeaderName: "X-Generator",
					ValueRegex: regexp.MustCompile(`(?i)Drupal`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-drupal-cache", HeaderName: "X-Drupal-Cache",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "WordPress.org", Product: "WordPress",
			Category: CategoryCMS,
			Patterns: []Pattern{
				{
					Name: "x-pingback", HeaderName: "X-Pingback",
					ValueRegex: regexp.MustCompile(`(?i)xmlrpc\.php`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceMedium,
				},
				{
					Name: "cookie-wordpress", CookieName: "wordpress_test_cookie",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Shopify", Product: "Shopify",
			Category: CategoryCMS,
			Patterns: []Pattern{
				{
					Name: "x-shopify-stage", HeaderName: "X-Shopify-Stage",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
				{
					Name: "server-shopify", HeaderName: "Server",
					ValueRegex: regexp.MustCompile(`(?i)^Shopify`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Ghost Foundation", Product: "Ghost CMS",
			Category: CategoryCMS,
			Patterns: []Pattern{{
				Name: "x-powered-by-ghost", HeaderName: "X-Powered-By",
				ValueRegex: regexp.MustCompile(`(?i)^Express|^Ghost`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceLow,
			}},
		},

		// --- Auth / SSO --------------------------------------------
		{
			Vendor: "Red Hat", Product: "Keycloak (cookie)",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name: "cookie-keycloak-identity", CookieName: "KEYCLOAK_IDENTITY",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
				{
					Name: "cookie-keycloak-session", CookieName: "KEYCLOAK_SESSION",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Okta", Product: "Auth0 (cookie)",
			Category: CategoryAuth,
			Patterns: []Pattern{
				{
					Name: "cookie-auth0-state", CookieName: "auth0.is.authenticated",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Cache / proxy --------------------------------------
		{
			Vendor: "Varnish Software", Product: "Varnish Cache",
			Category: CategoryCache,
			Patterns: []Pattern{
				{
					Name: "via-varnish", HeaderName: "Via",
					ValueRegex: regexp.MustCompile(`(?i)varnish`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-varnish", HeaderName: "X-Varnish",
					Kind: SignalHeaderName, Confidence: ConfidenceHigh,
				},
			},
		},
		{
			Vendor: "Squid", Product: "Squid proxy",
			Category: CategoryCache,
			Patterns: []Pattern{
				{
					Name: "via-squid", HeaderName: "Via",
					ValueRegex: regexp.MustCompile(`(?i)squid`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
				{
					Name: "x-cache-squid", HeaderName: "X-Cache",
					ValueRegex: regexp.MustCompile(`(?i)squid`),
					Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
				},
			},
		},

		// --- JS runtimes (Server header signal) ------------------
		{
			Vendor: "Oven", Product: "Bun (runtime)",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-bun", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^Bun(?:/[\d.]+)?$`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Deno Land", Product: "Deno (runtime / Deploy)",
			Category: CategoryAppRuntime,
			Patterns: []Pattern{{
				Name: "server-deno", HeaderName: "Server",
				ValueRegex: regexp.MustCompile(`(?i)^deno(?:[/_-][\d.]+)?(?:\s+deploy)?$`),
				Kind:       SignalHeaderValue, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "NextAuth.js", Product: "Auth.js / NextAuth (session)",
			Category: CategorySessionTrack,
			Patterns: []Pattern{
				{
					Name: "cookie-nextauth-session", CookieName: "next-auth.session-token",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
				{
					Name: "cookie-nextauth-secure", CookieName: "__Secure-next-auth.session-token",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
				{
					Name: "cookie-authjs-session", CookieName: "authjs.session-token",
					Kind: SignalCookieName, Confidence: ConfidenceHigh,
				},
			},
		},

		// --- Security headers (informational) ----------------------
		{
			Vendor: "Multiple", Product: "HSTS enabled",
			Category: CategorySecurity,
			Patterns: []Pattern{{
				Name: "strict-transport-security", HeaderName: "Strict-Transport-Security",
				Kind: SignalHeaderName, Confidence: ConfidenceHigh,
			}},
		},
		{
			Vendor: "Multiple", Product: "Content-Security-Policy enabled",
			Category: CategorySecurity,
			Patterns: []Pattern{{
				Name: "csp-header", HeaderName: "Content-Security-Policy",
				Kind: SignalHeaderName, Confidence: ConfidenceHigh,
			}},
		},
	}
}
