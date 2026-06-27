package apifingerprint

import "regexp"

// DefaultCatalog returns the seed Signature set. Probes are stable
// public health/version endpoints sourced from each project's docs.
// Confidence is set to High when both the path and a body regex are
// uniquely attributable to the product; Medium when only one strong
// signal exists; Low when only a header or generic body hint exists.
//
// Add a new Signature here; if it shares a Path with an existing
// Signature the engine still works (paths are deduplicated when the
// HTTP fetch is dispatched), but each Signature is evaluated against
// the response independently.
func DefaultCatalog() []Signature {
	return []Signature{
		// --- Observability stack ----------------------------------
		{
			Vendor: "Grafana Labs", Product: "Grafana",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"database"\s*:\s*"ok".*"version"\s*:\s*"`),
			}},
		},
		{
			Vendor: "Prometheus", Product: "Prometheus Server",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/status/buildinfo",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"success"`),
				BodyContains: `"version"`,
			}},
		},
		{
			Vendor: "Prometheus", Product: "Alertmanager",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v2/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"versionInfo"\s*:\s*{`),
			}},
		},
		{
			Vendor: "Grafana Labs", Product: "Loki",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/loki/api/v1/status/buildinfo",
				ExpectedStatus: []int{200},
				BodyContains: `"version"`,
			}},
		},
		{
			Vendor: "Elastic", Product: "Kibana",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"name"\s*:\s*"[^"]+".*"status"\s*:\s*{`),
			}},
		},
		{
			Vendor: "Jaegertracing", Product: "Jaeger Query",
			Category: CategoryObservability, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/api/services",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"data"\s*:\s*\[.*"total"\s*:`),
			}},
		},

		// --- Search / databases ------------------------------------
		{
			Vendor: "Elastic", Product: "Elasticsearch",
			Category: CategorySearch, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"lucene_version"\s*:`),
			}},
		},
		{
			Vendor: "OpenSearch", Product: "OpenSearch",
			Category: CategorySearch, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"distribution"\s*:\s*"opensearch"`),
			}},
		},
		{
			Vendor: "ClickHouse", Product: "ClickHouse Server",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/ping",
					ExpectedStatus: []int{200},
					BodyContains: "Ok.",
				},
				{
					Path: "/",
					HeaderName: "X-ClickHouse-Server-Display-Name",
				},
			},
		},
		{
			Vendor: "Apache", Product: "CouchDB",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyContains: `"couchdb":"Welcome"`,
			}},
		},
		{
			Vendor: "InfluxData", Product: "InfluxDB",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"name"\s*:\s*"influxdb"`),
			}},
		},

		// --- Service mesh / infra control --------------------------
		{
			Vendor: "HashiCorp", Product: "Consul",
			Category: CategoryServiceMesh, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/agent/self",
				ExpectedStatus: []int{200, 403},
				BodyContains: `"Config"`,
			}},
		},
		{
			Vendor: "HashiCorp", Product: "Vault",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/sys/health",
				ExpectedStatus: []int{200, 429, 472, 473, 501, 503},
				BodyRegex: regexp.MustCompile(`"initialized"\s*:\s*(true|false).*"sealed"\s*:`),
			}},
		},
		{
			Vendor: "HashiCorp", Product: "Nomad",
			Category: CategoryServiceMesh, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/agent/self",
				ExpectedStatus: []int{200, 403},
				BodyRegex: regexp.MustCompile(`"member"\s*:\s*{[^}]*"Name"\s*:`),
			}},
		},
		{
			Vendor: "etcd-io", Product: "etcd",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"etcdserver"\s*:\s*"`),
			}},
		},
		{
			Vendor: "Traefik Labs", Product: "Traefik",
			Category: CategoryServiceMesh, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"Version"\s*:\s*"[^"]+".*"Codename"\s*:`),
			}},
		},
		{
			Vendor: "Envoy", Product: "Envoy Proxy admin",
			Category: CategoryServiceMesh, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/server_info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[^"]+".*"state"\s*:`),
			}},
		},

		// --- Kubernetes-adjacent -----------------------------------
		{
			Vendor: "CNCF", Product: "Kubernetes API Server",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/version",
				ExpectedStatus: []int{200, 401, 403},
				BodyRegex: regexp.MustCompile(`"gitVersion"\s*:\s*"v\d`),
			}},
		},
		{
			Vendor: "Argo Project", Product: "Argo CD",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"Version"\s*:\s*"[^"]+".*"BuildDate"\s*:`),
			}},
		},
		{
			Vendor: "Argo Project", Product: "Argo Workflows",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"Version"\s*:\s*"v[\d\.]+"`),
			}},
		},
		{
			Vendor: "SUSE", Product: "Rancher",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v3/settings",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"id"\s*:\s*"server-url"`),
			}},
		},
		{
			Vendor: "Portainer.io", Product: "Portainer",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"Version"\s*:\s*"[^"]+".*"InstanceID"\s*:`),
			}},
		},
		{
			Vendor: "VMware", Product: "Harbor",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v2.0/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"healthy".*"components"\s*:\s*\[`),
			}},
		},

		// --- CI/CD / artifact stores ------------------------------
		{
			Vendor: "Jenkins", Product: "Jenkins",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/json",
				ExpectedStatus: []int{200, 403},
				HeaderName: "X-Jenkins",
				HeaderRegex: regexp.MustCompile(`^\d`),
			}},
		},
		{
			Vendor: "GitLab", Product: "GitLab",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v4/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[\d\.]+"`),
			}},
		},
		{
			Vendor: "Gitea", Product: "Gitea / Forgejo",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[\d\.]+`),
			}},
		},
		{
			Vendor: "SonarSource", Product: "SonarQube",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/system/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"UP".*"version"\s*:`),
			}},
		},
		{
			Vendor: "JFrog", Product: "Artifactory",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/artifactory/api/system/ping",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName: "X-JFrog-Version-Info",
			}},
		},
		{
			Vendor: "Sonatype", Product: "Nexus Repository",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/service/rest/v1/status",
				ExpectedStatus: []int{200},
				HeaderName: "Server",
				HeaderRegex: regexp.MustCompile(`(?i)nexus`),
			}},
		},

		// --- Auth / identity ---------------------------------------
		{
			Vendor: "Red Hat", Product: "Keycloak",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/realms/master/.well-known/openid-configuration",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"issuer"\s*:\s*"[^"]+/realms/`),
			}},
		},
		{
			Vendor: "Authentik", Product: "Authentik",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/-/health/ready/",
				ExpectedStatus: []int{200, 204},
				HeaderName: "X-Powered-By",
				HeaderRegex: regexp.MustCompile(`(?i)authentik`),
			}},
		},

		// --- Storage / object stores -------------------------------
		{
			Vendor: "MinIO", Product: "MinIO",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/minio/health/live",
				ExpectedStatus: []int{200},
				HeaderName: "Server",
				HeaderRegex: regexp.MustCompile(`(?i)minio`),
			}},
		},

		// --- GraphQL ------------------------------------------------
		// Generic GraphQL: GET /graphql with an introspection query in
		// the URL is widely supported. We use the simpler heuristic of
		// hitting /graphql and looking for the GraphiQL HTML or an
		// "errors":"[Must provide query string." JSON response — both
		// are stable across Apollo, Yoga, Hot Chocolate, gqlgen.
		{
			Vendor: "GraphQL", Product: "Generic GraphQL endpoint",
			Category: CategoryGraphQL, Confidence: ConfidenceMedium,
			Probes: []Probe{
				{
					Path: "/graphql",
					ExpectedStatus: []int{200, 400, 405},
					BodyRegex: regexp.MustCompile(`(?i)(graphiql|must provide query string|GET query missing|"errors":\s*\[)`),
				},
			},
		},
		{
			Vendor: "Hasura", Product: "Hasura GraphQL Engine",
			Category: CategoryGraphQL, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/healthz",
					ExpectedStatus: []int{200},
					BodyContains: "OK",
					HeaderName: "X-Hasura-Query-Plan-Cache-Hit",
				},
				{
					Path: "/v1/version",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"server_type"\s*:\s*"ce"|"version"\s*:\s*"v\d`),
				},
			},
		},
		{
			Vendor: "Apollo", Product: "Apollo Server",
			Category: CategoryGraphQL, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/.well-known/apollo/server-health",
				ExpectedStatus: []int{200},
				BodyContains: `"status":"pass"`,
			}},
		},

		// --- Generic REST / OpenAPI ---------------------------------
		// A plain-vanilla REST signal: the existence of an OpenAPI doc
		// at one of the canonical paths. Confidence is Medium because
		// many frameworks expose this and the vendor is unknowable
		// from the path alone — but it confirms "this is a REST API".
		{
			Vendor: "OpenAPI Initiative", Product: "OpenAPI document",
			Category: CategoryRESTAPI, Confidence: ConfidenceMedium,
			Probes: []Probe{
				{
					Path: "/openapi.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"openapi"\s*:\s*"3\.`),
				},
				{
					Path: "/swagger.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"swagger"\s*:\s*"2\.0"`),
				},
				{
					Path: "/v3/api-docs",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"openapi"\s*:\s*"3\.`),
				},
			},
		},

		// --- App servers ------------------------------------------
		{
			Vendor: "Spring", Product: "Spring Boot Actuator",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/actuator/health",
				ExpectedStatus: []int{200, 401, 403},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"`),
			}},
		},

		// --- Message brokers / queues -----------------------------
		{
			Vendor: "VMware", Product: "RabbitMQ Management",
			Category: CategoryMessageQueue, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/overview",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"rabbitmq_version"\s*:\s*"`),
			}},
		},
		{
			Vendor: "Apache", Product: "Kafka Connect",
			Category: CategoryMessageQueue, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"kafka_cluster_id"\s*:\s*"[^"]+".*"version"\s*:`),
			}},
		},
		{
			Vendor: "Confluent", Product: "Confluent Schema Registry",
			Category: CategoryMessageQueue, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/subjects",
				ExpectedStatus: []int{200},
				HeaderName:  "Content-Type",
				HeaderRegex: regexp.MustCompile(`(?i)application/vnd\.schemaregistry`),
			}},
		},
		{
			Vendor: "Synadia", Product: "NATS Server (monitor)",
			Category: CategoryMessageQueue, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/varz",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"server_id"\s*:\s*"[^"]+".*"version"\s*:\s*"`),
			}},
		},
		{
			Vendor: "EMQ Technologies", Product: "EMQX MQTT Broker",
			Category: CategoryMessageQueue, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v5/status",
				ExpectedStatus: []int{200},
				BodyContains: "Node ",
			}},
		},
		{
			Vendor: "Redpanda Data", Product: "Redpanda Console",
			Category: CategoryMessageQueue, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/admin/api/console/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"v?\d`),
			}},
		},
		{
			Vendor: "Apache", Product: "Pulsar Broker",
			Category: CategoryMessageQueue, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/admin/v2/brokers/health",
				ExpectedStatus: []int{200},
				BodyContains: "ok",
				HeaderName:   "Content-Type",
			}},
		},

		// --- Data infrastructure / analytics ----------------------
		{
			Vendor: "Apache Software Foundation", Product: "Airflow",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"metadatabase"\s*:\s*{\s*"status"\s*:\s*"healthy"`),
			}},
		},
		{
			Vendor: "Trino Software Foundation", Product: "Trino",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"nodeVersion"\s*:\s*{\s*"version"\s*:`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Flink JobManager",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/overview",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"flink-version"\s*:\s*"`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Spark UI",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/applications",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"sparkUser"|"attempts"\s*:\s*\[`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Druid",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[\d\.]+".*"modules"\s*:\s*\[`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Pinot",
			Category: CategoryDataInfra, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)pinot|jetty`),
			}},
		},

		// --- API gateways ------------------------------------------
		{
			Vendor: "Kong", Product: "Kong Gateway",
			Category: CategoryAPIGateway, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"\d.*"hostname"\s*:`),
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)kong`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "APISIX",
			Category: CategoryAPIGateway, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/apisix/admin/services",
				ExpectedStatus: []int{401, 403},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)apisix`),
			}},
		},
		{
			Vendor: "Tyk Technologies", Product: "Tyk Gateway",
			Category: CategoryAPIGateway, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/hello",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"pass".*"version"\s*:`),
			}},
		},
		{
			Vendor: "KrakenD", Product: "KrakenD",
			Category: CategoryAPIGateway, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/__health",
				ExpectedStatus: []int{200},
				BodyContains: "status",
				HeaderName:   "X-Krakend",
			}},
		},

		// --- Auth (extends) ----------------------------------------
		{
			Vendor: "Ory", Product: "Ory Kratos",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health/ready",
				ExpectedStatus: []int{200, 503},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"ok"`),
				HeaderName: "X-Kratos-Authenticated-Identity-Id",
			}},
		},
		{
			Vendor: "Ory", Product: "Ory Hydra",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/.well-known/openid-configuration",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"issuer"\s*:.*"backchannel_logout_supported"\s*:\s*true`),
			}},
		},
		{
			Vendor: "Zitadel", Product: "Zitadel",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/.well-known/openid-configuration",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)zitadel|caddy`),
				BodyContains: `"issuer"`,
			}},
		},
		{
			Vendor: "FusionAuth", Product: "FusionAuth",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/status",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "X-FusionAuth-TenantId",
			}},
		},

		// --- Observability (extends) -------------------------------
		{
			Vendor: "VictoriaMetrics", Product: "VictoriaMetrics",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/status/buildinfo",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)victoriametrics`),
			}},
		},
		{
			Vendor: "Grafana Labs", Product: "Pyroscope",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/system/buildinfo",
				ExpectedStatus: []int{200},
				BodyContains: `"version"`,
				BodyRegex:    regexp.MustCompile(`"goVersion"|"goos"`),
			}},
		},
		{
			Vendor: "Datadog", Product: "Vector",
			Category: CategoryObservability, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyContains: "ok",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)vector`),
			}},
		},
		{
			Vendor: "Fluent", Product: "Fluent Bit HTTP server",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/uptime",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"uptime_sec"\s*:\s*\d+`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "SkyWalking OAP",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/graphql",
					ExpectedStatus: []int{200, 400, 405},
					BodyRegex: regexp.MustCompile(`(?i)skywalking|"errors":\s*\[`),
				},
			},
		},

		// --- CI/CD (extends) ---------------------------------------
		{
			Vendor: "Harness", Product: "Drone CI",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"\d.*"source"`),
			}},
		},
		{
			Vendor: "Concourse CI", Product: "Concourse",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[\d\.]+".*"worker_version"`),
			}},
		},
		{
			Vendor: "Woodpecker CI", Product: "Woodpecker",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/version.json",
				ExpectedStatus: []int{200},
				BodyContains: `"version"`,
				HeaderName:   "X-Frame-Options",
			}},
		},
		{
			Vendor: "JetBrains", Product: "TeamCity",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/login.html",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "X-TeamCity-Node-Id",
			}},
		},

		// --- CMS / headless content / commerce ---------------------
		{
			Vendor: "WordPress.org", Product: "WordPress",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/wp-json/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"namespaces"\s*:\s*\[\s*"wp/v2"`),
			}},
		},
		{
			Vendor: "Drupal", Product: "Drupal JSON:API",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/jsonapi/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"jsonapi"\s*:\s*{\s*"version"`),
			}},
		},
		{
			Vendor: "Ghost Foundation", Product: "Ghost",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/ghost/api/admin/site/",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"site"\s*:\s*{|"errors"\s*:\s*\[`),
				HeaderName: "X-Powered-By",
			}},
		},
		{
			Vendor: "Strapi", Product: "Strapi",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/admin/init",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"data"\s*:\s*{\s*"uuid"\s*:`),
			}},
		},
		{
			Vendor: "Directus", Product: "Directus",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/server/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"project_name"\s*:|"directus"\s*:`),
			}},
		},
		{
			Vendor: "PocketBase", Product: "PocketBase",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"code"\s*:\s*200.*"message"\s*:`),
			}},
		},
		{
			Vendor: "PostgREST", Product: "PostgREST",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)postgrest`),
			}},
		},

		// --- Collaboration / chat / wiki ---------------------------
		{
			Vendor: "Mattermost", Product: "Mattermost",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v4/system/ping",
				ExpectedStatus: []int{200},
				BodyContains: `"status":"OK"`,
			}},
		},
		{
			Vendor: "Rocket.Chat", Product: "Rocket.Chat",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[\d\.]+".*"success"\s*:\s*true`),
			}},
		},
		{
			Vendor: "Matrix.org", Product: "Synapse",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/_matrix/client/versions",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"versions"\s*:\s*\[\s*"r0\.|"v1\.|"unstable_features"`),
			}},
		},
		{
			Vendor: "Wikimedia", Product: "MediaWiki",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api.php?action=siteinfo&format=json",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"generator"\s*:\s*"MediaWiki`),
			}},
		},

		// --- Container / cluster control ---------------------------
		{
			Vendor: "Docker", Product: "Docker Engine API",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"ApiVersion"\s*:\s*"[\d\.]+".*"GoVersion"`),
			}},
		},
		{
			Vendor: "OpenFaaS", Product: "OpenFaaS Gateway",
			Category: CategoryAPIGateway, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/system/info",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"provider"\s*:\s*{[^}]*"name"\s*:\s*"faas-`),
			}},
		},

		// --- Container registries ---------------------------------
		{
			Vendor: "Docker", Product: "Docker Registry v2 / OCI Distribution",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v2/",
				ExpectedStatus: []int{200, 401},
				HeaderName: "Docker-Distribution-Api-Version",
			}},
		},
		{
			Vendor: "Red Hat", Product: "Quay Registry",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/discovery",
				ExpectedStatus: []int{200, 401},
				BodyContains: `"endpoints"`,
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)nginx|quay`),
			}},
		},

		// --- Self-hosted SaaS-alternatives -------------------------
		{
			Vendor: "Nextcloud", Product: "Nextcloud",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/status.php",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"productname"\s*:\s*"Nextcloud"`),
			}},
		},
		{
			Vendor: "ownCloud", Product: "ownCloud",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/status.php",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"productname"\s*:\s*"ownCloud"`),
			}},
		},
		{
			Vendor: "Vaultwarden", Product: "Vaultwarden",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/alive",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}`),
			}},
		},
		{
			Vendor: "Bitwarden", Product: "Bitwarden Server",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"\d+\.\d+\.\d+"`),
				HeaderName: "X-Powered-By",
			}},
		},
		{
			Vendor: "AdGuard", Product: "AdGuard Home",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/control/status",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"v?\d.*"protection_enabled"`),
			}},
		},
		{
			Vendor: "Pi-hole", Product: "Pi-hole",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/admin/api.php?summary",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"domains_being_blocked"\s*:|"dns_queries_today"`),
			}},
		},
		{
			Vendor: "Jellyfin", Product: "Jellyfin",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/System/Info/Public",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"ServerName"\s*:|"ProductName"\s*:\s*"Jellyfin"`),
			}},
		},
		{
			Vendor: "Plex", Product: "Plex Media Server",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/identity",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`(?i)<MediaContainer.+machineIdentifier=`),
			}},
		},
		{
			Vendor: "Home Assistant", Product: "Home Assistant",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/",
				ExpectedStatus: []int{200, 401},
				HeaderName: "WWW-Authenticate",
				HeaderRegex: regexp.MustCompile(`(?i)bearer|Hass`),
			}},
		},
		{
			Vendor: "Node-RED Foundation", Product: "Node-RED",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/settings",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"editorTheme"|"flowFilePretty"`),
			}},
		},
		{
			Vendor: "Outline Foundation", Product: "Outline",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/auth.config",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"data"\s*:\s*{[^}]*"services"\s*:\s*\[`),
			}},
		},
		{
			Vendor: "HedgeDoc", Product: "HedgeDoc / CodiMD",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"onlineNotes"\s*:|"distinctOnlineUsers"`),
			}},
		},

		// --- Mail / newsletter -------------------------------------
		{
			Vendor: "Mailcow", Product: "Mailcow Admin",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/get/status/containers",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`(?i)"image"\s*:\s*"mailcow|"unauthorized"`),
			}},
		},
		{
			Vendor: "Listmonk", Product: "Listmonk",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyContains: `"data":true`,
			}},
		},

		// --- Marketing / analytics (self-hosted) -------------------
		{
			Vendor: "Plausible Analytics", Product: "Plausible",
			Category: CategoryRESTAPI, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"clickhouse"|"postgres"`),
			}},
		},
		{
			Vendor: "Umami Software", Product: "Umami",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/heartbeat",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName:   "X-Powered-By",
			}},
		},
		{
			Vendor: "PostHog", Product: "PostHog",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/_health/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"postgres"\s*:|"clickhouse"\s*:`),
			}},
		},

		// --- Monitoring (legacy + lightweight) ---------------------
		{
			Vendor: "Zabbix", Product: "Zabbix Frontend",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api_jsonrpc.php",
				ExpectedStatus: []int{200, 400, 412},
				HeaderName:  "Content-Type",
				HeaderRegex: regexp.MustCompile(`(?i)application/json`),
			}},
		},
		{
			Vendor: "Icinga", Product: "Icinga2 API",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/status",
				ExpectedStatus: []int{401},
				HeaderName: "WWW-Authenticate",
				HeaderRegex: regexp.MustCompile(`(?i)icinga`),
			}},
		},
		{
			Vendor: "Uptime Kuma", Product: "Uptime Kuma",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/status-page/list",
				ExpectedStatus: []int{200, 403},
				BodyRegex: regexp.MustCompile(`"statusPageList"|"error_msg"`),
			}},
		},

		// --- Auth proxies (extends) --------------------------------
		{
			Vendor: "Authelia", Product: "Authelia",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"OK"`),
			}},
		},
		{
			Vendor: "OAuth2 Proxy", Product: "OAuth2 Proxy",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/oauth2/sign_in",
				ExpectedStatus: []int{200, 401, 403},
				BodyRegex: regexp.MustCompile(`(?i)oauth2-proxy|sign in with`),
			}},
		},
		{
			Vendor: "Pomerium", Product: "Pomerium",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/.pomerium/",
				ExpectedStatus: []int{200, 302, 401},
				HeaderName: "Set-Cookie",
				HeaderRegex: regexp.MustCompile(`_pomerium`),
			}},
		},

		// --- Mesh / VPN control planes -----------------------------
		{
			Vendor: "Juan Font", Product: "Headscale",
			Category: CategoryServiceMesh, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"pass"`),
			}},
		},

		// --- Kubernetes ecosystem (extends) ------------------------
		{
			Vendor: "Cilium", Product: "Hubble UI",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/healthz",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)hubble`),
			}},
		},
		{
			Vendor: "Linkerd", Product: "Linkerd dashboard",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"linkerd"|"controlPlaneVersion"`),
			}},
		},
		{
			Vendor: "Kiali", Product: "Kiali",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/status",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"Kiali commit hash"|"Kiali container version"|"externalServices"`),
			}},
		},
		{
			Vendor: "Tekton CD", Product: "Tekton Dashboard",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/properties",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"DashboardVersion"|"PipelinesVersion"`),
			}},
		},
		{
			Vendor: "Crossplane", Product: "Crossplane",
			Category: CategoryKubernetes, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/healthz",
				ExpectedStatus: []int{200},
				BodyContains: "ok",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)crossplane|kubernetes`),
			}},
		},
		{
			Vendor: "Backstage.io", Product: "Backstage",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/catalog/entities",
				ExpectedStatus: []int{200, 401},
				HeaderName: "Backstage-Correlation-Id",
			}},
		},

		// --- Secrets / vaults (extends) ---------------------------
		{
			Vendor: "CyberArk", Product: "Conjur",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200, 503},
				BodyRegex: regexp.MustCompile(`"services"\s*:|"database"\s*:`),
			}},
		},
		{
			Vendor: "Infisical", Product: "Infisical",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"date"\s*:|"message"\s*:\s*"Ok"`),
			}},
		},
		{
			Vendor: "1Password", Product: "1Password Connect",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/heartbeat",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"name"\s*:\s*"1Password Connect`),
			}},
		},

		// --- Sync / backup ----------------------------------------
		{
			Vendor: "Syncthing", Product: "Syncthing",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/rest/noauth/health",
				ExpectedStatus: []int{200},
				BodyContains: `"status":"OK"`,
			}},
		},
		{
			Vendor: "Kopia", Product: "Kopia Repository Server",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/repo/status",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"storage"\s*:|"hash"\s*:|"uniqueId"`),
			}},
		},

		// --- CI/CD (extends 2) -------------------------------------
		{
			Vendor: "GoCD", Product: "GoCD",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/go/api/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[\d\.]+".*"build_number"`),
			}},
		},
		{
			Vendor: "Red Hat", Product: "Ansible AWX / Tower",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v2/ping/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"ha"\s*:\s*(true|false).*"version"`),
			}},
		},
		{
			Vendor: "Octopus Deploy", Product: "Octopus Server",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/octopusservernodes/ping",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "Octopus-Node",
			}},
		},
		{
			Vendor: "Spinnaker", Product: "Spinnaker Gate",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/auth/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"authEnabled"|"authenticated"`),
			}},
		},

		// --- LLM serving / inference -------------------------------
		{
			Vendor: "Ollama", Product: "Ollama",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/tags",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"models"\s*:\s*\[`),
			}},
		},
		{
			Vendor: "vLLM Project", Product: "vLLM (OpenAI-compatible)",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/models",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"object"\s*:\s*"list".*"data"\s*:\s*\[`),
				HeaderName: "Server",
				HeaderRegex: regexp.MustCompile(`(?i)uvicorn|vllm`),
			}},
		},
		{
			Vendor: "Mudler", Product: "LocalAI",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/readyz",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)localai|fiber`),
			}},
		},
		{
			Vendor: "ggml.ai", Product: "llama.cpp server",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/props",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"default_generation_settings"|"chat_template"`),
			}},
		},
		{
			Vendor: "NVIDIA", Product: "Triton Inference Server",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v2/health/live",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)triton`),
			}},
		},
		{
			Vendor: "PyTorch Foundation", Product: "TorchServe",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/ping",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"Healthy"`),
			}},
		},
		{
			Vendor: "Google", Product: "TensorFlow Serving",
			Category: CategoryAIInference, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/v1/models",
				ExpectedStatus: []int{200, 400},
				BodyRegex: regexp.MustCompile(`"model_version_status"|"Malformed request"`),
			}},
		},
		{
			Vendor: "BentoML", Product: "BentoML",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/healthz",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)bentoml|uvicorn`),
			}},
		},
		{
			Vendor: "Ray Project", Product: "Ray Serve",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/-/healthz",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)uvicorn|ray`),
			}},
		},
		{
			Vendor: "Open WebUI", Product: "Open WebUI",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"v?\d+\.\d+\.\d+"`),
			}},
		},
		{
			Vendor: "LangChain", Product: "Dify",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/console/api/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"version"\s*:|"released_at"`),
			}},
		},
		{
			Vendor: "Flowise AI", Product: "Flowise",
			Category: CategoryAIInference, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/ping",
				ExpectedStatus: []int{200},
				BodyContains: "pong",
			}},
		},

		// --- Vector / search databases -----------------------------
		{
			Vendor: "Meilisearch", Product: "Meilisearch",
			Category: CategoryVectorDB, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"available"`),
			}},
		},
		{
			Vendor: "Typesense", Product: "Typesense",
			Category: CategoryVectorDB, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyContains: `"ok":true`,
			}},
		},
		{
			Vendor: "Qdrant", Product: "Qdrant",
			Category: CategoryVectorDB, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"title"\s*:\s*"qdrant`),
			}},
		},
		{
			Vendor: "SeMI Technologies", Product: "Weaviate",
			Category: CategoryVectorDB, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v1/.well-known/ready",
				ExpectedStatus: []int{200, 503},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)weaviate`),
			}},
		},
		{
			Vendor: "Chroma", Product: "Chroma",
			Category: CategoryVectorDB, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/heartbeat",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"nanosecond heartbeat"\s*:\s*\d+`),
			}},
		},
		{
			Vendor: "Milvus", Product: "Milvus",
			Category: CategoryVectorDB, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/healthz",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)milvus`),
			}},
		},

		// --- Big-data / analytics extends --------------------------
		{
			Vendor: "Apache Software Foundation", Product: "Superset",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName:   "Set-Cookie",
				HeaderRegex:  regexp.MustCompile(`(?i)session=`),
			}},
		},
		{
			Vendor: "Metabase", Product: "Metabase",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyContains: `"status":"ok"`,
				HeaderName:   "X-Metabase-Version",
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Zeppelin",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"git"\s*:|"version"\s*:\s*"\d`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "YARN ResourceManager",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/ws/v1/cluster/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"clusterInfo"\s*:\s*{[^}]*"hadoopVersion"`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "NiFi",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/nifi-api/system-diagnostics",
				ExpectedStatus: []int{200, 401, 403},
				HeaderName:  "X-Frame-Options",
				HeaderRegex: regexp.MustCompile(`(?i)SAMEORIGIN|DENY`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "DolphinScheduler",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/dolphinscheduler/actuator/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"UP"`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Doris FE",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/show_runtime_info",
				ExpectedStatus: []int{200, 401},
				BodyContains: `"data"`,
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)doris|baidu|jetty`),
			}},
		},
		{
			Vendor: "PrefectHQ", Product: "Prefect Server",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyContains: "true",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)uvicorn`),
			}},
		},
		{
			Vendor: "Temporal Technologies", Product: "Temporal Web UI",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/cluster-info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"serverVersion"\s*:|"temporalVersion"`),
			}},
		},
		{
			Vendor: "Kestra", Product: "Kestra",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/configs",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"uri"\s*:\s*"http|"isAnonymousUsageEnabled"`),
			}},
		},

		// --- Fediverse / community ---------------------------------
		{
			Vendor: "Mastodon", Product: "Mastodon",
			Category: CategoryFediverse, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/instance",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"uri"\s*:\s*"[^"]+".*"version"\s*:\s*"[\d\.]+`),
			}},
		},
		{
			Vendor: "Pleroma", Product: "Pleroma / Akkoma",
			Category: CategoryFediverse, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/instance",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[^"]*pleroma|akkoma`),
			}},
		},
		{
			Vendor: "Lemmy", Product: "Lemmy",
			Category: CategoryFediverse, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v3/site",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"lemmy_version"\s*:|"site_view"\s*:`),
			}},
		},
		{
			Vendor: "Misskey", Product: "Misskey",
			Category: CategoryFediverse, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/meta",
				ExpectedStatus: []int{200, 405},
				BodyRegex: regexp.MustCompile(`"misskey"|"version"\s*:\s*"\d`),
			}},
		},
		{
			Vendor: "Pixelfed", Product: "Pixelfed",
			Category: CategoryFediverse, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/instance",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[^"]+".*"thumbnail"`),
			}},
		},
		{
			Vendor: "CIVITED", Product: "Discourse",
			Category: CategoryFediverse, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/about.json",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"[\d\.]+".*"discourse_version"`),
			}},
		},

		// --- ITSM / asset management -------------------------------
		{
			Vendor: "Grokability", Product: "Snipe-IT",
			Category: CategoryITSM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/hardware",
				ExpectedStatus: []int{401, 403},
				HeaderName: "WWW-Authenticate",
				HeaderRegex: regexp.MustCompile(`(?i)bearer`),
			}},
		},
		{
			Vendor: "Teclib", Product: "GLPI",
			Category: CategoryITSM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/apirest.php/initSession/",
				ExpectedStatus: []int{200, 400, 401, 405},
				BodyRegex: regexp.MustCompile(`(?i)ERROR_LOGIN|app_token|session_token`),
			}},
		},
		{
			Vendor: "Zammad Foundation", Product: "Zammad",
			Category: CategoryITSM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/getting_started",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)nginx|zammad`),
				BodyContains: "setup_done",
			}},
		},
		{
			Vendor: "Open-Source", Product: "osTicket",
			Category: CategoryITSM, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/api/tasks.json",
				ExpectedStatus: []int{200, 400, 401, 403},
				HeaderName:  "X-Api-Key",
				HeaderRegex: regexp.MustCompile(`.*`),
				BodyRegex:   regexp.MustCompile(`(?i)osticket|api key`),
			}},
		},

		// --- Low-code / internal-tools -----------------------------
		{
			Vendor: "NocoDB", Product: "NocoDB",
			Category: CategoryLowCode, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"message"\s*:\s*"OK".*"timestamp"`),
			}},
		},
		{
			Vendor: "Appsmith", Product: "Appsmith",
			Category: CategoryLowCode, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/health",
				ExpectedStatus: []int{200},
				BodyContains: "appsmith is running",
			}},
		},
		{
			Vendor: "ToolJet", Product: "ToolJet",
			Category: CategoryLowCode, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"tooljet_version"|"status"\s*:\s*"ok"`),
			}},
		},
		{
			Vendor: "Budibase", Product: "Budibase",
			Category: CategoryLowCode, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/system/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"passed"\s*:|"version"\s*:`),
				HeaderName: "X-Budibase-Type",
			}},
		},

		// --- Workspace / dev environments --------------------------
		{
			Vendor: "Coder", Product: "Coder",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v2/buildinfo",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"external_url"\s*:|"version"\s*:\s*"v\d`),
			}},
		},
		{
			Vendor: "Daytona", Product: "Daytona",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"ok"|"daytona"`),
			}},
		},

		// --- Terraform / GitOps ------------------------------------
		{
			Vendor: "Atlantis", Product: "Atlantis (Terraform)",
			Category: CategoryCICD, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/healthz",
				ExpectedStatus: []int{200},
				BodyContains: "ok",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)atlantis`),
			}},
		},

		// --- Notes / PKM -------------------------------------------
		{
			Vendor: "Memos", Product: "Memos",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"profile"\s*:\s*{[^}]*"version"`),
			}},
		},
		{
			Vendor: "Trilium", Product: "Trilium Notes",
			Category: CategoryCMS, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/api/health",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)trilium|node\.js`),
			}},
		},

		// --- Object/file storage extends ---------------------------
		{
			Vendor: "SeaweedFS", Product: "SeaweedFS Master",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/dir/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"Topology"\s*:|"Version"\s*:\s*"\d`),
			}},
		},
		{
			Vendor: "Treeverse", Product: "lakeFS",
			Category: CategoryStorage, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/healthcheck",
				ExpectedStatus: []int{204, 200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)lakefs|nginx`),
			}},
		},
		{
			Vendor: "Filebrowser", Product: "Filebrowser",
			Category: CategoryStorage, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/api/renew",
				ExpectedStatus: []int{401, 403},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)nginx|caddy`),
				BodyContains: "Unauthorized",
			}},
		},

		// --- ITSM (extends) ----------------------------------------
		{
			Vendor: "OpenProject Foundation", Product: "OpenProject",
			Category: CategoryITSM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v3/configuration",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"_type"\s*:\s*"Configuration"|"maximumAttachmentFileSize"`),
			}},
		},
		{
			Vendor: "Taiga.io", Product: "Taiga",
			Category: CategoryITSM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/application-tokens",
				ExpectedStatus: []int{401, 403, 405},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)nginx|taiga`),
				BodyContains: "_error_message",
			}},
		},
		{
			Vendor: "Plane", Product: "Plane",
			Category: CategoryITSM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/instances/",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"instance"\s*:\s*{|"is_setup_done"|"current_version"`),
			}},
		},

		// --- Hypervisors / virtualisation -------------------------
		{
			Vendor: "Proxmox", Product: "Proxmox VE",
			Category: CategoryHypervisor, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api2/json/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"\d.*"release"\s*:|"data"\s*:\s*null`),
			}},
		},
		{
			Vendor: "Proxmox", Product: "Proxmox Backup Server",
			Category: CategoryHypervisor, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api2/json/version",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)proxmox`),
			}},
		},
		{
			Vendor: "OpenStack Foundation", Product: "OpenStack Keystone",
			Category: CategoryHypervisor, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v3/",
				ExpectedStatus: []int{200, 300},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*{[^}]*"id"\s*:\s*"v3`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "CloudStack",
			Category: CategoryHypervisor, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/client/api?command=listCapabilities",
				ExpectedStatus: []int{200, 401, 432},
				BodyRegex: regexp.MustCompile(`(?i)listcapabilitiesresponse|cloudstackversion|unable to verify user credentials`),
			}},
		},
		{
			Vendor: "VMware", Product: "vCenter SDK",
			Category: CategoryHypervisor, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/sdk",
				ExpectedStatus: []int{200, 400},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)vmware|jetty`),
				BodyContains: "SOAP",
			}},
		},

		// --- Database admin UIs ------------------------------------
		{
			Vendor: "pgAdmin", Product: "pgAdmin",
			Category: CategoryDBAdmin, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/misc/ping",
				ExpectedStatus: []int{200},
				BodyContains: "PING",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)pgadmin|werkzeug|gunicorn`),
			}},
		},
		{
			Vendor: "phpMyAdmin", Product: "phpMyAdmin",
			Category: CategoryDBAdmin, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/phpmyadmin/",
				ExpectedStatus: []int{200, 302},
				HeaderName:  "Set-Cookie",
				HeaderRegex: regexp.MustCompile(`(?i)phpmyadmin|pmaCookieVer`),
			}},
		},
		{
			Vendor: "Adminer", Product: "Adminer",
			Category: CategoryDBAdmin, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`(?i)<title>Login - Adminer|Adminer-DB`),
			}},
		},
		{
			Vendor: "DBeaver", Product: "CloudBeaver",
			Category: CategoryDBAdmin, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/gql",
				ExpectedStatus: []int{200, 400, 405},
				HeaderName:  "Set-Cookie",
				HeaderRegex: regexp.MustCompile(`(?i)cb-session-id|JSESSIONID`),
			}},
		},
		{
			Vendor: "RedisLabs", Product: "RedisInsight",
			Category: CategoryDBAdmin, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/info",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"appVersion"\s*:\s*"\d.*"sessionId"|"redisInsight"`),
			}},
		},

		// --- Stream processing -------------------------------------
		{
			Vendor: "Confluent", Product: "Kafka REST Proxy",
			Category: CategoryStreaming, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/v3/clusters",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"kind"\s*:\s*"KafkaClusterList"|"cluster_id"`),
			}},
		},
		{
			Vendor: "Confluent", Product: "ksqlDB Server",
			Category: CategoryStreaming, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"KsqlServerInfo"\s*:|"version"\s*:\s*"\d.*"kafkaClusterId"`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Storm UI",
			Category: CategoryStreaming, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/cluster/summary",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"stormVersion"\s*:|"supervisors"`),
			}},
		},

		// --- Queue UIs --------------------------------------------
		{
			Vendor: "felixmosh", Product: "Bull Board",
			Category: CategoryQueueUI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/queues/api/queues",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"queues"\s*:\s*\[|"bullStats"`),
			}},
		},
		{
			Vendor: "hibiken", Product: "Asynq Monitoring",
			Category: CategoryQueueUI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/queues",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"queues"\s*:\s*\[[^\]]*"queue"\s*:\s*"`),
			}},
		},
		{
			Vendor: "Sidekiq LLC", Product: "Sidekiq Dashboard",
			Category: CategoryQueueUI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/sidekiq/",
				ExpectedStatus: []int{200, 401, 403},
				BodyRegex: regexp.MustCompile(`(?i)<title>[^<]*Sidekiq|sidekiq/web`),
			}},
		},

		// --- E-commerce backend APIs ------------------------------
		{
			Vendor: "shopware AG", Product: "Shopware 6 API",
			Category: CategoryEcommerce, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/_info/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"\d|"errors"\s*:\s*\[[^\]]*"shop"`),
			}},
		},
		{
			Vendor: "Adobe", Product: "Magento REST",
			Category: CategoryEcommerce, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/rest/V1/store/storeViews",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"code"\s*:\s*"default"|"website_id"|"consumer is not authorized"`),
			}},
		},
		{
			Vendor: "Automattic", Product: "WooCommerce REST",
			Category: CategoryEcommerce, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/wp-json/wc/v3/",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"namespace"\s*:\s*"wc/v3"|woocommerce_rest_cannot_view`),
			}},
		},
		{
			Vendor: "Saleor", Product: "Saleor (GraphQL)",
			Category: CategoryEcommerce, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/graphql/",
				ExpectedStatus: []int{200, 400, 405},
				BodyRegex: regexp.MustCompile(`(?i)<title>[^<]*GraphQL Playground|saleor|"data":\s*null,\s*"errors"`),
			}},
		},
		{
			Vendor: "Medusa", Product: "Medusa",
			Category: CategoryEcommerce, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName:   "X-Powered-By",
				HeaderRegex:  regexp.MustCompile(`(?i)express|medusa`),
			}},
		},

		// --- APM / error tracking / logs ---------------------------
		{
			Vendor: "Functional Software", Product: "Sentry",
			Category: CategoryAPM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/0/projects/",
				ExpectedStatus: []int{200, 401, 403},
				HeaderName:  "X-Frame-Options",
				HeaderRegex: regexp.MustCompile(`.+`),
				BodyRegex: regexp.MustCompile(`"detail"\s*:\s*"Authentication credentials were not provided|"id"\s*:\s*"\d+"`),
			}},
		},
		{
			Vendor: "GlitchTip", Product: "GlitchTip",
			Category: CategoryAPM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/0/",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)glitchtip|uvicorn|gunicorn`),
			}},
		},
		{
			Vendor: "Graylog", Product: "Graylog",
			Category: CategoryAPM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/system/cluster/health",
				ExpectedStatus: []int{200, 401},
				HeaderName: "X-Graylog-Node-Id",
			}},
		},
		{
			Vendor: "Treasure Data", Product: "Fluentd HTTP server",
			Category: CategoryAPM, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/plugins.json",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"output_plugins"\s*:|"plugin_id"\s*:`),
			}},
		},

		// --- Mail servers -----------------------------------------
		{
			Vendor: "axllent", Product: "Mailpit",
			Category: CategoryMail, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"Version"\s*:|"DatabaseSize"`),
			}},
		},
		{
			Vendor: "Krystal", Product: "Postal",
			Category: CategoryMail, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/send/message",
				ExpectedStatus: []int{400, 401, 405},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)nginx|postal|puma`),
				BodyContains: "status",
			}},
		},
		{
			Vendor: "Modoboa Foundation", Product: "Modoboa",
			Category: CategoryMail, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v2/parameters/",
				ExpectedStatus: []int{200, 401, 403},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)nginx|gunicorn|modoboa`),
				BodyContains: "modoboa",
			}},
		},

		// --- RPA / workflow automation ----------------------------
		{
			Vendor: "n8n", Product: "n8n",
			Category: CategoryRPA, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/healthz",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"ok"`),
				HeaderName: "X-Powered-By",
				HeaderRegex: regexp.MustCompile(`(?i)express|n8n`),
			}},
		},
		{
			Vendor: "Activepieces", Product: "Activepieces",
			Category: CategoryRPA, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/flags",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"PRIVATE_PIECES_ENABLED"|"INSTANCE_ID"`),
			}},
		},
		{
			Vendor: "Huginn", Product: "Huginn",
			Category: CategoryRPA, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/about",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`(?i)huginn|jonhyman`),
			}},
		},

		// --- Identity / SSO (extends 3) ---------------------------
		{
			Vendor: "Casbin", Product: "Casdoor",
			Category: CategoryAuth, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/get-default-application",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"ok"|"msg"\s*:\s*""`),
			}},
		},
		{
			Vendor: "TandoorRecipes", Product: "Tandoor (auth)",
			Category: CategoryAuth, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName:   "X-Frame-Options",
			}},
		},

		// --- K8s tooling (extends 2) ------------------------------
		{
			Vendor: "KubeSphere", Product: "KubeSphere",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/kapis/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"gitVersion"\s*:\s*"|"kubeSphereVersion"`),
			}},
		},
		{
			Vendor: "Kinvolk", Product: "Headlamp",
			Category: CategoryKubernetes, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/config",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"clusters"\s*:\s*\{|"defaultClusters"`),
				HeaderName: "Server",
				HeaderRegex: regexp.MustCompile(`.*`),
			}},
		},

		// --- Wiki / docs (extends) --------------------------------
		{
			Vendor: "Requarks", Product: "Wiki.js",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/healthz",
				ExpectedStatus: []int{200},
				BodyContains: "OK",
				HeaderName:   "X-Powered-By",
				HeaderRegex:  regexp.MustCompile(`(?i)wiki\.js|express`),
			}},
		},
		{
			Vendor: "BookStackApp", Product: "BookStack",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/docs.json",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"books-list"\s*:|"BookStack API"`),
			}},
		},

		// --- Hadoop ecosystem -------------------------------------
		{
			Vendor: "Apache Software Foundation", Product: "Atlas",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/atlas/admin/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"Version"\s*:\s*"\d.*"Name"\s*:\s*"apache-atlas`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Knox Gateway",
			Category: CategoryAPIGateway, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/gateway/admin/api/v1/version",
				ExpectedStatus: []int{200, 401, 403},
				HeaderName:  "Set-Cookie",
				HeaderRegex: regexp.MustCompile(`(?i)JSESSIONID`),
				BodyContains: "version",
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "HBase Master",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/jmx?qry=Hadoop:service=HBase,name=Master,sub=Server",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"beans"\s*:\s*\[|"hbase.regionserver"`),
			}},
		},

		// --- Hub / Hazelcast / Geode -----------------------------
		{
			Vendor: "Hazelcast", Product: "Hazelcast Management Center",
			Category: CategoryDataInfra, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health/check",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)hazelcast|jetty`),
				BodyContains: "UP",
			}},
		},

		// --- Legacy / regional CMS ---------------------------------
		{
			Vendor: "TYPO3 Association", Product: "TYPO3",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/typo3/",
				ExpectedStatus: []int{200, 302},
				BodyRegex: regexp.MustCompile(`(?i)<title>[^<]*TYPO3|t3-username`),
			}},
		},
		{
			Vendor: "Open Source Matters", Product: "Joomla",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/administrator/manifests/files/joomla.xml",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`<extension[^>]+>.*<name>files_joomla|<version>\d+\.\d+`),
			}},
		},
		{
			Vendor: "Pixel & Tonic", Product: "Craft CMS",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/index.php?p=admin/login",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`(?i)craft cms|<title>[^<]*Craft`),
				HeaderName: "Set-Cookie",
				HeaderRegex: regexp.MustCompile(`(?i)CraftSessionId`),
			}},
		},
		{
			Vendor: "Statamic", Product: "Statamic",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/cp/",
				ExpectedStatus: []int{200, 302},
				HeaderName:  "Set-Cookie",
				HeaderRegex: regexp.MustCompile(`(?i)statamic_session|XSRF-TOKEN`),
				BodyContains: "Statamic",
			}},
		},
		{
			Vendor: "concrete5", Product: "Concrete CMS",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/index.php/dashboard/system/environment/info",
				ExpectedStatus: []int{200, 302, 401, 403},
				BodyRegex: regexp.MustCompile(`(?i)concrete CMS|<title>[^<]*Concrete`),
			}},
		},
		{
			Vendor: "ProcessWire", Product: "ProcessWire",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/processwire/",
				ExpectedStatus: []int{200, 302},
				BodyRegex: regexp.MustCompile(`(?i)processwire|<title>[^<]*ProcessWire`),
			}},
		},

		// --- NewSQL / distributed DBs ------------------------------
		{
			Vendor: "PingCAP", Product: "TiDB Dashboard",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/dashboard/api/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:|"pd_version"`),
			}},
		},
		{
			Vendor: "Cockroach Labs", Product: "CockroachDB Admin UI",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/_status/details/local",
				ExpectedStatus: []int{200, 401, 403},
				BodyRegex: regexp.MustCompile(`"node_id"\s*:|"address"\s*:\s*{[^}]*"network_field"`),
			}},
		},
		{
			Vendor: "Yugabyte", Product: "YugabyteDB Master",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version_number"\s*:|"build_type"\s*:|"build_id"`),
			}},
		},
		{
			Vendor: "ScyllaDB", Product: "Scylla Manager",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/clusters",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)scylla|nginx`),
				BodyContains: "[",
			}},
		},
		{
			Vendor: "Cassandra Reaper Project", Product: "Cassandra Reaper",
			Category: CategoryDatabase, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/ping",
				ExpectedStatus: []int{200, 204},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)jetty|reaper`),
			}},
		},
		{
			Vendor: "Apache Software Foundation", Product: "Solr",
			Category: CategorySearch, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/solr/admin/info/system",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"solr-spec-version"\s*:|"lucene"\s*:\s*{`),
			}},
		},

		// --- Notebooks / data science ------------------------------
		{
			Vendor: "Jupyter Project", Product: "JupyterHub",
			Category: CategoryNotebook, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/hub/api",
				ExpectedStatus: []int{200, 401, 403},
				BodyRegex: regexp.MustCompile(`"version"\s*:\s*"\d.*"authenticator_class"|"hub"`),
			}},
		},
		{
			Vendor: "Jupyter Project", Product: "JupyterLab / Jupyter Server",
			Category: CategoryNotebook, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/status",
				ExpectedStatus: []int{200, 403},
				BodyRegex: regexp.MustCompile(`"started"\s*:|"kernels"\s*:|"last_activity"`),
			}},
		},
		{
			Vendor: "Snowflake / Streamlit", Product: "Streamlit",
			Category: CategoryNotebook, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/_stcore/health",
				ExpectedStatus: []int{200},
				BodyContains: "ok",
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)tornado|streamlit`),
			}},
		},
		{
			Vendor: "Hugging Face", Product: "Gradio",
			Category: CategoryNotebook, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"gradio_version"\s*:|"named_endpoints"`),
			}},
		},

		// --- Document management -----------------------------------
		{
			Vendor: "paperless-ngx", Product: "Paperless-ngx",
			Category: CategoryDocMgmt, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/?format=json",
				ExpectedStatus: []int{200, 401, 403},
				BodyRegex: regexp.MustCompile(`"documents"\s*:|"correspondents"|"detail"\s*:\s*"Authentication credentials`),
			}},
		},
		{
			Vendor: "Mayan EDMS", Product: "Mayan EDMS",
			Category: CategoryDocMgmt, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v4/",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`"documents"\s*:|"workflow_templates"`),
			}},
		},
		{
			Vendor: "Eike Hirsch", Product: "Docspell",
			Category: CategoryDocMgmt, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/info",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"name"\s*:\s*"docspell"|"version"\s*:\s*"\d`),
			}},
		},

		// --- Media servers ----------------------------------------
		{
			Vendor: "Navidrome", Product: "Navidrome",
			Category: CategoryMedia, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/app",
				ExpectedStatus: []int{200},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)navidrome`),
			}},
		},
		{
			Vendor: "Airsonic", Product: "Airsonic / Airsonic-Advanced",
			Category: CategoryMedia, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/rest/ping.view?u=&p=&v=1.16.1&c=probe&f=json",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"subsonic-response"\s*:\s*{[^}]*"type"\s*:\s*"airsonic`),
			}},
		},
		{
			Vendor: "Photoview", Product: "Photoview",
			Category: CategoryMedia, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/api/graphql",
				ExpectedStatus: []int{200, 400, 405},
				BodyRegex: regexp.MustCompile(`(?i)photoview|"errors"\s*:\s*\[`),
			}},
		},
		{
			Vendor: "Immich Team", Product: "Immich",
			Category: CategoryMedia, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/server-info/ping",
				ExpectedStatus: []int{200},
				BodyContains: `"res":"pong"`,
			}},
		},
		{
			Vendor: "PhotoPrism", Product: "PhotoPrism",
			Category: CategoryMedia, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"status"\s*:\s*"(operational|unstable|client)"`),
			}},
		},

		// --- Geo / mapping ----------------------------------------
		{
			Vendor: "GeoServer", Product: "GeoServer",
			Category: CategoryGeo, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/geoserver/rest/about/version",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`(?i)geoserver|<about>|"about"`),
			}},
		},
		{
			Vendor: "MapTiler", Product: "TileServer GL",
			Category: CategoryGeo, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"version"\s*:|"styles_loaded"`),
				HeaderName: "Server",
				HeaderRegex: regexp.MustCompile(`.*`),
			}},
		},
		{
			Vendor: "OpenStreetMap", Product: "Nominatim",
			Category: CategoryGeo, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/status",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`(?i)data_updated|nominatim version`),
			}},
		},
		{
			Vendor: "CrunchyData", Product: "pg_tileserv",
			Category: CategoryGeo, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/index.json",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"PgTileservHome"\s*:|"FunctionsHome"`),
			}},
		},

		// --- ERP / CRM (self-hosted) -------------------------------
		{
			Vendor: "Frappe Technologies", Product: "Frappe / ERPNext",
			Category: CategoryERP, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/method/ping",
				ExpectedStatus: []int{200, 403},
				BodyRegex: regexp.MustCompile(`"message"\s*:\s*"pong"|"exc_type"\s*:\s*"PermissionError"`),
			}},
		},
		{
			Vendor: "Odoo S.A.", Product: "Odoo",
			Category: CategoryERP, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/web/database/list",
				ExpectedStatus: []int{200},
				HeaderName:  "Set-Cookie",
				HeaderRegex: regexp.MustCompile(`(?i)session_id`),
				BodyContains: "jsonrpc",
			}},
		},
		{
			Vendor: "EspoCRM", Product: "EspoCRM",
			Category: CategoryERP, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/App/user",
				ExpectedStatus: []int{401, 403},
				HeaderName:  "WWW-Authenticate",
				HeaderRegex: regexp.MustCompile(`(?i)basic|espo`),
			}},
		},
		{
			Vendor: "SalesAgility", Product: "SuiteCRM",
			Category: CategoryERP, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/Api/V8/meta/swagger.json",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`(?i)SuiteCRM API|"info"\s*:\s*{[^}]*"title"`),
			}},
		},
		{
			Vendor: "WeKan Team", Product: "WeKan",
			Category: CategoryERP, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/info",
				ExpectedStatus: []int{200, 401},
				HeaderName:  "X-Frame-Options",
				HeaderRegex: regexp.MustCompile(`.*`),
				BodyRegex:   regexp.MustCompile(`"version"\s*:|wekan`),
			}},
		},

		// --- Service mesh (extends 2) ------------------------------
		{
			Vendor: "Kong Inc.", Product: "Kuma",
			Category: CategoryServiceMesh, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"tagline"\s*:\s*"Kuma"|"hostname"`),
			}},
		},
		{
			Vendor: "Solo.io", Product: "Gloo Edge",
			Category: CategoryServiceMesh, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v1/version",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"gloo"\s*:|"buildDate"|"version"`),
			}},
		},

		// --- PKI / certificate authorities ------------------------
		{
			Vendor: "Smallstep Labs", Product: "step-ca",
			Category: CategoryPKI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/health",
				ExpectedStatus: []int{200},
				BodyContains: `"status":"ok"`,
				HeaderName:   "Server",
				HeaderRegex:  regexp.MustCompile(`(?i)step|nginx`),
			}},
		},
		{
			Vendor: "PrimeKey", Product: "EJBCA",
			Category: CategoryPKI, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/ejbca/",
				ExpectedStatus: []int{200, 302},
				BodyRegex: regexp.MustCompile(`(?i)EJBCA|<title>[^<]*EJBCA`),
			}},
		},

		// --- Game-server panels -----------------------------------
		{
			Vendor: "Pterodactyl Software", Product: "Pterodactyl Panel",
			Category: CategoryGameAdmin, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/application/users",
				ExpectedStatus: []int{401, 403},
				HeaderName:  "WWW-Authenticate",
				HeaderRegex: regexp.MustCompile(`(?i)bearer`),
				BodyContains: "Unauthenticated",
			}},
		},

		// --- More observability / metrics --------------------------
		{
			Vendor: "OpenZipkin", Product: "Zipkin",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v2/services",
				ExpectedStatus: []int{200, 204},
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)zipkin|jetty`),
			}},
		},
		{
			Vendor: "Thanos community", Product: "Thanos Query",
			Category: CategoryObservability, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/-/healthy",
				ExpectedStatus: []int{200},
				BodyContains: "Thanos",
			}},
		},
		{
			Vendor: "Cortex Labs", Product: "Cortex",
			Category: CategoryObservability, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/services",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`(?i)ingester|distributor|querier`),
			}},
		},

		// --- Wikis / docs (extends) -------------------------------
		{
			Vendor: "XWiki SAS", Product: "XWiki",
			Category: CategoryCMS, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/rest",
				ExpectedStatus: []int{200, 401},
				BodyRegex: regexp.MustCompile(`(?i)xwiki|<xwiki:link`),
			}},
		},

		// --- JavaScript web frameworks (SSR/SSG/SPA) --------------
		// Probes target server-rendered HTML or framework-emitted
		// asset routes. Body markers come from each project's own
		// runtime hydration scripts and are stable across versions.
		{
			Vendor: "Vercel", Product: "Next.js",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/",
					BodyRegex: regexp.MustCompile(`<script id="__NEXT_DATA__"|/_next/static/`),
				},
				{
					Path: "/",
					HeaderName:  "X-Powered-By",
					HeaderRegex: regexp.MustCompile(`(?i)next\.?js`),
				},
			},
		},
		{
			Vendor: "NuxtLabs", Product: "Nuxt",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<div id="__nuxt"|window\.__NUXT__\s*=|/_nuxt/`),
			}},
		},
		{
			Vendor: "Remix Software", Product: "Remix",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`window\.__remixContext|window\.__remixManifest|window\.__remixRouteModules`),
			}},
		},
		{
			Vendor: "The Astro Technology Company", Product: "Astro",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<meta\s+name="generator"\s+content="Astro\b|<astro-island|/_astro/`),
			}},
		},
		{
			Vendor: "Svelte Society", Product: "SvelteKit",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/",
					BodyRegex: regexp.MustCompile(`data-sveltekit-preload-|__sveltekit_|/_app/immutable/`),
				},
				{
					Path: "/_app/version.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"version"\s*:\s*"`),
				},
			},
		},
		{
			Vendor: "Gatsby Inc.", Product: "Gatsby",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/",
					BodyRegex: regexp.MustCompile(`<meta\s+name="generator"\s+content="Gatsby\b|window\.___gatsby|/page-data/`),
				},
				{
					Path: "/page-data/index/page-data.json",
					ExpectedStatus: []int{200},
					BodyContains:   `"path":"/"`,
				},
			},
		},
		{
			Vendor: "Deno Land", Product: "Fresh",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<script id="__FRSH_STATE|<style id="__FRSH_STYLE|/_frsh/`),
			}},
		},
		{
			Vendor: "Builder.io", Product: "Qwik",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bq:container=|<script type="qwik/json"|q:base="/build/`),
			}},
		},
		{
			Vendor: "SolidJS", Product: "SolidStart",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`_\$HY\s*=|\bdata-hk="|<script type="module"\s+src="/_build/`),
			}},
		},
		{
			Vendor: "Google", Product: "Angular",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bng-version="\d|\b_nghost-|\b_ngcontent-`),
			}},
		},
		{
			Vendor: "Vue.js", Product: "Vue",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bdata-v-app\b|\bdata-v-[a-f0-9]{8}\b|window\.__vue__`),
			}},
		},
		{
			Vendor: "Vite Core Team", Product: "Vite (dev server)",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/@vite/client",
				ExpectedStatus: []int{200},
				BodyContains:   "import.meta.hot",
			}},
		},
		{
			Vendor: "OpenJS Foundation", Product: "Express",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				HeaderName:  "X-Powered-By",
				HeaderRegex: regexp.MustCompile(`(?i)\bexpress\b`),
			}},
		},
		{
			Vendor: "hapi.dev", Product: "hapi",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)\bhapi\b`),
			}},
		},
		{
			Vendor: "Deno Land", Product: "Deno (runtime)",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				HeaderName:  "Server",
				HeaderRegex: regexp.MustCompile(`(?i)^deno($|/)`),
			}},
		},

		// --- JS framework overlays / progressive-enhancement libs -
		{
			Vendor: "Big Sky Software", Product: "htmx",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bhx-(get|post|put|delete|swap|target|trigger|boost)=|<script[^>]+src="[^"]*\bhtmx(?:[.@-][\d.]+)?(?:\.min)?\.js`),
			}},
		},
		{
			Vendor: "Caleb Porzio", Product: "Alpine.js",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bx-data="|\bx-show="|\bx-bind:|<script[^>]+src="[^"]*alpinejs(?:@[\d.]+)?(?:/dist)?/cdn(?:\.min)?\.js`),
			}},
		},
		{
			Vendor: "Hotwire", Product: "Stimulus",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bdata-controller="[a-z][\w-]*"|<script[^>]+src="[^"]*@hotwired/stimulus|<script[^>]+src="[^"]*stimulus(?:\.min)?\.js`),
			}},
		},
		{
			Vendor: "Inertia.js", Product: "Inertia.js",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<div\s+id="app"\s+data-page="\{|data-page='\{[^']*"component"[^']*"version"|@inertiajs/`),
			}},
		},
		{
			Vendor: "Ember.js", Product: "Ember.js",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<meta\s+name="[a-z0-9-]+/config/environment"|class="ember-application"|<script[^>]+src="[^"]*assets/vendor-[a-f0-9]+\.js`),
			}},
		},
		{
			Vendor: "Quasar Framework", Product: "Quasar",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<div\s+id="q-app"|<link[^>]+href="[^"]*quasar(?:[.-][\d.]+)?(?:\.min)?\.css|window\.__QUASAR_SSR`),
			}},
		},
		{
			Vendor: "eBay", Product: "Marko",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<!--M_\$-->|window\.\$initComponents|<script[^>]+src="[^"]*marko-runtime`),
			}},
		},
		{
			Vendor: "Phoenix Framework", Product: "Phoenix LiveView",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bphx-(static|session|view)=|\bdata-phx-(main|session|view|root)=|<script[^>]+src="[^"]*phoenix_live_view`),
			}},
		},
		{
			Vendor: "11ty", Product: "Eleventy",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<meta\s+name="generator"\s+content="Eleventy\b`),
			}},
		},

		// --- WASM-delivered framework apps -----------------------
		{
			Vendor: "Microsoft", Product: "Blazor WebAssembly",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/_framework/blazor.boot.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"mainAssemblyName"\s*:|"resources"\s*:\s*\{[^}]*"assembly"`),
				},
				{
					Path: "/",
					BodyRegex: regexp.MustCompile(`<script[^>]+src="[^"]*_framework/blazor\.(webassembly|server)\.js`),
				},
			},
		},

		// --- More JS framework runtimes --------------------------
		{
			Vendor: "Preact Core Team", Product: "Preact",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<script[^>]+src="[^"]*\bpreact(?:[@/-][\d.]+)?(?:/dist)?/preact(?:\.[\w-]+)?\.js|window\.__PREACT_DEVTOOLS__`),
			}},
		},
		{
			Vendor: "Ionic", Product: "Stencil",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<script[^>]+src="[^"]*/build/p-[a-f0-9]{8,}\.(esm\.)?js|data-stencil-build=|<script[^>]+data-stencil-namespace=`),
			}},
		},
		{
			Vendor: "Riot.js", Product: "Riot.js",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<script[^>]+src="[^"]*\briot(?:@[\d.]+)?(?:/dist)?(?:\+compiler)?(?:\.min)?\.js|\briot\.mount\s*\(`),
			}},
		},
		{
			Vendor: "Storybook", Product: "Storybook",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/iframe.html",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`<title>[^<]*Storybook|id="storybook-(preview|root)"|window\.__STORYBOOK_`),
				},
				{
					Path: "/index.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"v"\s*:\s*[3-9].*"entries"\s*:\s*\{|"stories"\s*:\s*\{[^}]*"id"\s*:`),
				},
			},
		},
		{
			Vendor: "Google", Product: "Flutter Web",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/main.dart.js",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`dart\.global|_dart_invokeFunction|@dart2js\.platformDeferredLibrarySize`),
				},
				{
					Path: "/",
					BodyRegex: regexp.MustCompile(`<script[^>]+src="main\.dart\.js"|<meta\s+name="flutter-web-renderer"|_flutter\.loader\.loadEntrypoint|<script[^>]+src="flutter_bootstrap\.js"`),
				},
			},
		},
		{
			Vendor: "Decap CMS", Product: "Decap CMS / Netlify CMS",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/admin/config.yml",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`(?m)^backend\s*:|^collections\s*:|^media_folder\s*:`),
				},
				{
					Path: "/admin/",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`<script[^>]+src="[^"]*(?:decap-cms|netlify-cms)(?:@[\d.]+)?/dist/(?:decap-cms|netlify-cms)\.js`),
				},
			},
		},

		// --- JS-based docs / SSG platforms ----------------------
		{
			Vendor: "Vue Team", Product: "VitePress",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<meta\s+name="generator"\s+content="VitePress\b|window\.__VP_HASH_MAP__|<div\s+id="VPContent\b`),
			}},
		},
		{
			Vendor: "Meta", Product: "Docusaurus",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<meta\s+name="generator"\s+content="Docusaurus\b|data-theme-config|<div\s+id="__docusaurus`),
			}},
		},
		{
			Vendor: "Mintlify", Product: "Mintlify",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<meta\s+name="generator"\s+content="Mintlify\b|mintlify\.s3\.|cdn\.mintlify\.com`),
			}},
		},
		{
			Vendor: "GitBook", Product: "GitBook",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<meta\s+name="generator"\s+content="GitBook\b|assets\.gitbook\.com|<script[^>]+src="[^"]*static\.gitbook\.com`),
			}},
		},
		{
			Vendor: "Anthony Fu", Product: "Slidev",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`\bdata-slidev-no-transition\b|\bdata-slidev-id\b|<title>[^<]+- Slidev</title>|@slidev/client`),
			}},
		},

		// --- Hybrid / headless app runtimes ----------------------
		{
			Vendor: "Ionic", Product: "Capacitor",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/capacitor.js",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`window\.Capacitor|Capacitor\.Plugins|capacitorWebView`),
				},
				{
					Path: "/",
					BodyRegex: regexp.MustCompile(`<script[^>]+src="[^"]*capacitor\.js|window\.Capacitor\s*=|@capacitor/core`),
				},
			},
		},
		{
			Vendor: "Payload CMS", Product: "Payload CMS",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/api/access",
					ExpectedStatus: []int{200, 401, 403},
					BodyRegex: regexp.MustCompile(`"canAccessAdmin"|"collections"\s*:\s*\{[^}]*"create"`),
				},
				{
					Path: "/admin",
					ExpectedStatus: []int{200, 302},
					BodyRegex: regexp.MustCompile(`<title>[^<]*Payload(?:\s+CMS)?\b|<div\s+id="app"[^>]*>\s*<noscript>[^<]*Payload`),
				},
			},
		},

		// --- Headless CMS / search / GraphQL surfaces -----------
		{
			Vendor: "Sanity.io", Product: "Sanity Studio",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/studio/",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`<title>[^<]*Sanity(?:\s+Studio)?\b|/static/sanity-loader\.js|@sanity/`),
				},
				{
					Path: "/",
					BodyRegex: regexp.MustCompile(`<title>[^<]*Sanity Studio</title>|<div\s+id="sanity"\b|window\.SANITY_STUDIO`),
				},
			},
		},
		{
			Vendor: "Prismic", Product: "Prismic CMS",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/api/v2",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"refs"\s*:\s*\[[^\]]*"ref"\s*:\s*"[A-Za-z0-9_-]{16,}"[^\]]*"isMasterRef"|"version"\s*:\s*"[^"]+",\s*"license"\s*:\s*"|cdn\.prismic\.io`),
			}},
		},
		{
			Vendor: "MeiliSearch", Product: "MeiliSearch",
			Category: CategorySearch, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/health",
					ExpectedStatus: []int{200},
					BodyContains: `"status":"available"`,
				},
				{
					Path: "/version",
					ExpectedStatus: []int{200, 401, 403},
					BodyRegex: regexp.MustCompile(`"pkgVersion"\s*:\s*"[\d.]+|"commitSha"\s*:\s*"[a-f0-9]{7,40}"`),
				},
			},
		},
		{
			Vendor: "Apollo / Generic", Product: "GraphQL endpoint (introspection-on)",
			Category: CategoryGraphQL, Confidence: ConfidenceMedium,
			Probes: []Probe{
				{
					Path: "/graphql",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`<title>[^<]*Apollo Sandbox|<title>[^<]*GraphiQL|embeddable-sandbox\.cdn\.apollographql\.com|unpkg\.com/graphiql`),
				},
				{
					Path: "/playground",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`<title>[^<]*GraphQL Playground|cdn\.jsdelivr\.net/npm/graphql-playground`),
				},
			},
		},
		{
			Vendor: "Google", Product: "Workbox (PWA Service Worker)",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/sw.js",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`importScripts\(\s*['"]https?://storage\.googleapis\.com/workbox-cdn|workbox\.routing\.|workbox\.precaching\.`),
				},
				{
					Path: "/service-worker.js",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`importScripts\(\s*['"]https?://storage\.googleapis\.com/workbox-cdn|workbox\.routing\.|workbox\.precaching\.`),
				},
			},
		},
		{
			Vendor: "TanStack", Product: "TanStack Start",
			Category: CategoryWebFramework, Confidence: ConfidenceHigh,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`window\.__TSR_ROUTE_MANIFEST__|window\.__TSR__\s*=|data-tanstack-router-html-cache|@tanstack/start`),
			}},
		},
		{
			Vendor: "Aiden Bai", Product: "Million.js",
			Category: CategoryWebFramework, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/",
				BodyRegex: regexp.MustCompile(`<million-block\b|data-million=|<script[^>]+src="[^"]*million(?:@[\d.]+)?(?:/dist)?(?:\.min)?\.js`),
			}},
		},

		// --- Standards-based discovery endpoints -------------------
		// RFC-defined paths every framework can expose. Vendor stays
		// generic because the endpoint identifies a protocol, not a
		// product; matching specific vendor signatures (Keycloak, Ory,
		// Auth0, etc.) elsewhere narrows the attribution further.
		{
			Vendor: "OpenID Foundation", Product: "OpenID Connect Discovery",
			Category: CategoryAuth, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/.well-known/openid-configuration",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"issuer"\s*:\s*"https?://|"authorization_endpoint"\s*:\s*"|"token_endpoint"\s*:\s*"`),
			}},
		},
		{
			Vendor: "IETF", Product: "OAuth2 Authorization Server Metadata (RFC 8414)",
			Category: CategoryAuth, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/.well-known/oauth-authorization-server",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"issuer"\s*:\s*"https?://|"authorization_endpoint"\s*:|"grant_types_supported"\s*:`),
			}},
		},
		{
			Vendor: "IETF", Product: "security.txt (RFC 9116)",
			Category: CategoryGeneric, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/.well-known/security.txt",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`(?im)^Contact\s*:|^Expires\s*:|^Preferred-Languages\s*:|^Policy\s*:|^Encryption\s*:`),
				},
				{
					Path: "/security.txt",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`(?im)^Contact\s*:|^Expires\s*:`),
				},
			},
		},
		{
			Vendor: "OpenAPI Initiative", Product: "OpenAPI 3.1 document",
			Category: CategoryRESTAPI, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/openapi.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"openapi"\s*:\s*"3\.1`),
				},
				{
					Path: "/api/openapi.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"openapi"\s*:\s*"3\.[01]`),
				},
				{
					Path: "/api-docs/openapi.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"openapi"\s*:\s*"3\.[01]`),
				},
			},
		},
		{
			Vendor: "IETF", Product: "Web App Manifest (PWA)",
			Category: CategoryGeneric, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/manifest.webmanifest",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"start_url"\s*:|"display"\s*:\s*"(?:standalone|fullscreen|minimal-ui|browser)"|"theme_color"\s*:`),
				},
				{
					Path: "/manifest.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"start_url"\s*:|"display"\s*:\s*"(?:standalone|fullscreen|minimal-ui|browser)"|"icons"\s*:\s*\[[^\]]*"src"`),
				},
			},
		},
		{
			Vendor: "OWASP / CycloneDX", Product: "SBOM document (CycloneDX/SPDX)",
			Category: CategoryGeneric, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/.well-known/sbom",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"bomFormat"\s*:\s*"CycloneDX"|"specVersion"\s*:|"SPDXID"\s*:\s*"SPDXRef-|spdxVersion`),
				},
				{
					Path: "/sbom.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"bomFormat"\s*:\s*"CycloneDX"|"SPDXID"\s*:\s*"SPDXRef-|spdxVersion`),
				},
				{
					Path: "/sbom",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"bomFormat"\s*:\s*"CycloneDX"|"SPDXID"\s*:\s*"SPDXRef-`),
				},
			},
		},
		{
			Vendor: "IETF", Product: "WebFinger / host-meta (RFC 7033 / 6415)",
			Category: CategoryFediverse, Confidence: ConfidenceHigh,
			Probes: []Probe{
				{
					Path: "/.well-known/host-meta",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`<XRD\b|xmlns="http://docs\.oasis-open\.org/ns/xri/xrd|<Link\s+rel="lrdd"`),
				},
				{
					Path: "/.well-known/host-meta.json",
					ExpectedStatus: []int{200},
					BodyRegex: regexp.MustCompile(`"links"\s*:\s*\[[^\]]*"rel"\s*:\s*"lrdd"|"template"\s*:\s*"[^"]+webfinger`),
				},
			},
		},
		{
			Vendor: "IETF", Product: "RFC 9728 OAuth Protected Resource Metadata",
			Category: CategoryAuth, Confidence: ConfidenceMedium,
			Probes: []Probe{{
				Path: "/.well-known/oauth-protected-resource",
				ExpectedStatus: []int{200},
				BodyRegex: regexp.MustCompile(`"resource"\s*:\s*"https?://|"authorization_servers"\s*:\s*\[|"bearer_methods_supported"\s*:`),
			}},
		},
	}
}
