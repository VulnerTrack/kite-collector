package filefingerprint

import "regexp"

// DefaultCatalog returns the seed Probe set. Severities reflect
// real-world impact:
//
//   - critical: VCS HEAD pointers that enable full source recovery,
//     credentials files that almost always carry production secrets.
//   - high: PHP debug pages, backup variants of config files, admin
//     UIs that are common pivot points.
//   - medium: dependency manifests (CVE matching surface), .DS_Store
//     directory listings, server-status endpoints.
//   - low: standards endpoints that may leak deployment metadata.
//   - info: robots.txt, security.txt — useful for inventory.
//
// Every Probe with a likely-200-on-SPA path carries either a
// BodyContains or BodyRegex matcher so single-page apps that serve
// the index for unknown paths do not false-positive.
func DefaultCatalog() []Probe {
	return []Probe{
		// --- Version-control exposure -----------------------------
		{
			Path: "/.git/HEAD", Description: "Exposed Git repository (HEAD pointer accessible)",
			Category: CategoryVCS, Severity: SeverityCritical,
			ExpectedStatus: []int{200}, BodyRegex: regexp.MustCompile(`^ref:\s+refs/`),
		},
		{
			Path: "/.git/config", Description: "Git config exposed",
			Category: CategoryVCS, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "[core]",
		},
		{
			Path: "/.git/index", Description: "Git index file accessible",
			Category: CategoryVCS, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "DIRC",
		},
		{
			Path: "/.svn/entries", Description: "SVN metadata exposed",
			Category: CategoryVCS, Severity: SeverityHigh,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`^\d+\s+dir|svn:|entries`),
		},
		{
			Path: "/.svn/wc.db", Description: "SVN working-copy database accessible",
			Category: CategoryVCS, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "SQLite format",
		},
		{
			Path: "/.hg/store/00manifest.i", Description: "Mercurial repository accessible",
			Category: CategoryVCS, Severity: SeverityHigh,
			ExpectedStatus: []int{200},
		},
		{
			Path: "/.bzr/branch/format", Description: "Bazaar branch metadata exposed",
			Category: CategoryVCS, Severity: SeverityMedium,
			ExpectedStatus: []int{200}, BodyRegex: regexp.MustCompile(`Bazaar`),
		},

		// --- Environment / secrets --------------------------------
		{
			Path: "/.env", Description: "Environment file exposed (likely credentials)",
			Category: CategorySecrets, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?i)(DB_|DATABASE_|SECRET|API_KEY|AWS_|TOKEN|PASSWORD)\s*=`),
			MustNotContain: "<html",
		},
		{
			Path: "/.env.local", Description: "Local environment file exposed",
			Category: CategorySecrets, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?i)(DB_|SECRET|API_KEY|TOKEN)\s*=`),
			MustNotContain: "<html",
		},
		{
			Path: "/.env.production", Description: "Production environment file exposed",
			Category: CategorySecrets, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?i)(DB_|SECRET|API_KEY|TOKEN)\s*=`),
			MustNotContain: "<html",
		},
		{
			Path: "/.env.development", Description: "Development environment file exposed",
			Category: CategorySecrets, Severity: SeverityHigh,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?i)(DB_|SECRET|API_KEY|TOKEN)\s*=`),
			MustNotContain: "<html",
		},
		{
			Path: "/wp-config.php", Description: "WordPress wp-config.php exposed",
			Category: CategorySecrets, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`DB_PASSWORD|DB_USER|wp-settings`),
		},
		{
			Path: "/wp-config.php.bak", Description: "WordPress wp-config backup exposed",
			Category: CategorySecrets, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`DB_PASSWORD|DB_USER`),
		},
		{
			Path: "/config.php.bak", Description: "PHP config backup exposed",
			Category: CategorySecrets, Severity: SeverityHigh,
			ExpectedStatus: []int{200},
			BodyContains:   "<?php",
		},
		{
			Path: "/database.yml", Description: "Rails database.yml exposed (likely credentials)",
			Category: CategorySecrets, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?i)password\s*:|adapter\s*:`),
		},
		{
			Path: "/credentials/master.key", Description: "Rails credentials master key exposed",
			Category: CategorySecrets, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`^[0-9a-f]{32}\s*$`),
		},

		// --- Debug / info pages -----------------------------------
		{
			Path: "/phpinfo.php", Description: "phpinfo() output exposed",
			Category: CategoryDebug, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "PHP Version",
		},
		{
			Path: "/info.php", Description: "phpinfo() at /info.php",
			Category: CategoryDebug, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "PHP Version",
		},
		{
			Path: "/test.php", Description: "Likely phpinfo() at /test.php",
			Category: CategoryDebug, Severity: SeverityMedium,
			ExpectedStatus: []int{200}, BodyContains: "PHP Version",
		},
		{
			Path: "/server-status", Description: "Apache server-status exposed",
			Category: CategoryDebug, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "Apache Server Status",
		},
		{
			Path: "/server-info", Description: "Apache server-info exposed",
			Category: CategoryDebug, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "Apache Server Information",
		},
		{
			Path: "/debug/pprof/", Description: "Go pprof debug endpoint exposed",
			Category: CategoryDebug, Severity: SeverityHigh,
			ExpectedStatus: []int{200}, BodyContains: "Types of profiles available",
		},
		{
			Path: "/actuator/env", Description: "Spring Boot Actuator /env exposed (likely secrets)",
			Category: CategoryDebug, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"propertySources"|"activeProfiles"`),
		},
		{
			Path: "/actuator/heapdump", Description: "Spring Boot heapdump exposed",
			Category: CategoryDebug, Severity: SeverityCritical,
			ExpectedStatus: []int{200},
		},

		// --- Dependency manifests --------------------------------
		{
			Path: "/package.json", Description: "Node.js package manifest exposed",
			Category: CategoryManifest, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"dependencies"\s*:|"name"\s*:\s*"`),
		},
		{
			Path: "/package-lock.json", Description: "npm lockfile exposed (full dep tree)",
			Category: CategoryManifest, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"lockfileVersion"\s*:`),
		},
		{
			Path: "/yarn.lock", Description: "Yarn lockfile exposed",
			Category: CategoryManifest, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`# yarn lockfile v\d`),
		},
		{
			Path: "/composer.json", Description: "Composer manifest exposed (PHP)",
			Category: CategoryManifest, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"require"\s*:|"autoload"\s*:`),
		},
		{
			Path: "/composer.lock", Description: "Composer lockfile exposed",
			Category: CategoryManifest, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyContains:   `"_readme"`,
		},
		{
			Path: "/Gemfile", Description: "Ruby Gemfile exposed",
			Category: CategoryManifest, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?m)^source\s+['"]`),
		},
		{
			Path: "/Gemfile.lock", Description: "Ruby Gemfile.lock exposed",
			Category: CategoryManifest, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyContains:   "GEM",
		},
		{
			Path: "/requirements.txt", Description: "Python requirements.txt exposed",
			Category: CategoryManifest, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?m)^[a-zA-Z][a-zA-Z0-9._-]*\s*[~=<>!]?=`),
		},
		{
			Path: "/pom.xml", Description: "Maven pom.xml exposed (Java)",
			Category: CategoryManifest, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`<project[^>]+xmlns=|<groupId>`),
		},
		{
			Path: "/build.gradle", Description: "Gradle build file exposed",
			Category: CategoryManifest, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`apply plugin|dependencies\s*{|implementation`),
		},
		{
			Path: "/Cargo.toml", Description: "Rust Cargo manifest exposed",
			Category: CategoryManifest, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyContains:   "[package]",
		},
		{
			Path: "/go.mod", Description: "Go module file exposed",
			Category: CategoryManifest, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`^module\s+`),
		},

		// --- Build / framework config -----------------------------
		{
			Path: "/webpack.config.js", Description: "webpack config exposed",
			Category: CategoryConfig, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyContains:   "module.exports",
		},
		{
			Path: "/vite.config.js", Description: "Vite config exposed",
			Category: CategoryConfig, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyContains:   "defineConfig",
		},
		{
			Path: "/next.config.js", Description: "Next.js config exposed",
			Category: CategoryConfig, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyContains:   "module.exports",
		},
		{
			Path: "/nuxt.config.js", Description: "Nuxt config exposed",
			Category: CategoryConfig, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyContains:   "defineNuxtConfig",
		},
		{
			Path: "/tsconfig.json", Description: "TypeScript config exposed",
			Category: CategoryConfig, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyContains:   `"compilerOptions"`,
		},

		// --- IDE / OS detritus -----------------------------------
		{
			Path: "/.DS_Store", Description: "macOS directory listing leak (.DS_Store)",
			Category: CategoryIDE, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyContains:   "Bud1",
		},
		{
			Path: "/.idea/workspace.xml", Description: "JetBrains IDE workspace exposed",
			Category: CategoryIDE, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`<project[^>]*version=|<component`),
		},
		{
			Path: "/.vscode/settings.json", Description: "VS Code settings exposed",
			Category: CategoryIDE, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"editor\.|"workbench\.|"files\.`),
		},

		// --- Server config / .htaccess -----------------------------
		{
			Path: "/.htaccess", Description: "Apache .htaccess exposed",
			Category: CategoryConfig, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?m)^\s*(RewriteEngine|Options|Order|Allow|Deny|AuthType)`),
		},
		{
			Path: "/web.config", Description: "IIS web.config exposed",
			Category: CategoryConfig, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyContains:   "<configuration>",
		},
		{
			Path: "/nginx.conf", Description: "nginx.conf exposed",
			Category: CategoryConfig, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyContains:   "server {",
		},

		// --- Admin entry points ----------------------------------
		{
			Path: "/wp-login.php", Description: "WordPress admin login page",
			Category: CategoryAdmin, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   "wp-submit",
		},
		{
			Path: "/wp-admin/", Description: "WordPress admin path",
			Category: CategoryAdmin, Severity: SeverityInfo,
			ExpectedStatus: []int{200, 302, 401, 403},
			BodyRegex:      regexp.MustCompile(`(?i)wordpress|wp-login|/wp-admin/`),
		},
		{
			Path: "/administrator/", Description: "Joomla administrator panel",
			Category: CategoryAdmin, Severity: SeverityInfo,
			ExpectedStatus: []int{200, 302, 401, 403},
			BodyContains:   "Joomla",
		},
		{
			Path: "/phpmyadmin/", Description: "phpMyAdmin exposed",
			Category: CategoryAdmin, Severity: SeverityHigh,
			ExpectedStatus: []int{200, 302, 401},
			BodyContains:   "phpMyAdmin",
		},
		{
			Path: "/adminer.php", Description: "Adminer DB client exposed",
			Category: CategoryAdmin, Severity: SeverityHigh,
			ExpectedStatus: []int{200},
			BodyContains:   "Adminer",
		},

		// --- Well-known endpoints --------------------------------
		// These are standards-compliant disclosures; severity=info.
		{
			Path: "/robots.txt", Description: "Robots exclusion file",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?im)^User-agent:|^Disallow:|^Allow:|^Sitemap:`),
		},
		{
			Path: "/sitemap.xml", Description: "XML sitemap",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`<urlset|<sitemapindex`),
		},
		{
			Path: "/.well-known/security.txt", Description: "Security disclosure policy",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`(?im)^Contact:|^Expires:|^Policy:`),
		},
		{
			Path: "/.well-known/openid-configuration",
			Description: "OIDC discovery document",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   `"issuer"`,
		},
		{
			Path: "/.well-known/oauth-authorization-server",
			Description: "OAuth 2.0 authorization server metadata",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   `"issuer"`,
		},
		{
			Path: "/.well-known/jwks.json", Description: "JSON Web Key Set",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   `"keys"`,
		},
		{
			Path: "/.well-known/apple-app-site-association",
			Description: "Apple Universal Links / app-site association",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   `"applinks"`,
		},
		{
			Path: "/.well-known/assetlinks.json",
			Description: "Android Asset Links (App Links)",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   `"relation"`,
		},
		{
			Path: "/.well-known/matrix/server", Description: "Matrix federation server discovery",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   `"m.server"`,
		},
		{
			Path: "/.well-known/host-meta", Description: "WebFinger host-meta",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`<XRD|<Link rel`),
		},
		{
			Path: "/.well-known/dnt-policy.txt", Description: "Do-Not-Track policy",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
		},
		{
			Path: "/.well-known/change-password",
			Description: "Well-known password change redirect (RFC 8615)",
			Category: CategoryWellKnown, Severity: SeverityInfo,
			ExpectedStatus: []int{200, 302, 303, 307, 308},
		},

		// --- API docs --------------------------------------------
		{
			Path: "/swagger-ui/", Description: "Swagger UI exposed",
			Category: CategoryDocs, Severity: SeverityLow,
			ExpectedStatus: []int{200, 302},
			BodyContains:   "Swagger UI",
		},
		{
			Path: "/swagger.json", Description: "Swagger 2.0 spec exposed",
			Category: CategoryDocs, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"swagger"\s*:\s*"2\.0"`),
		},
		{
			Path: "/openapi.json", Description: "OpenAPI 3.x spec exposed",
			Category: CategoryDocs, Severity: SeverityLow,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"openapi"\s*:\s*"3\.`),
		},
		{
			Path: "/api-docs", Description: "Generic /api-docs endpoint",
			Category: CategoryDocs, Severity: SeverityLow,
			ExpectedStatus: []int{200, 302},
		},
		{
			Path: "/graphql/schema.json", Description: "GraphQL introspection schema exposed",
			Category: CategoryDocs, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyContains:   `"__schema"`,
		},

		// --- Build artefacts ------------------------------------
		{
			Path: "/static/js/main.js.map", Description: "Source map exposed (Create React App default path)",
			Category: CategoryDebug, Severity: SeverityMedium,
			ExpectedStatus: []int{200},
			BodyRegex:      regexp.MustCompile(`"version"\s*:\s*3,\s*"sources"`),
		},
		{
			Path: "/_next/static/", Description: "Next.js _next/static directory listing",
			Category: CategoryDebug, Severity: SeverityInfo,
			ExpectedStatus: []int{200},
			BodyContains:   "Index of",
		},
	}
}
