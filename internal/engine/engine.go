package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/vulnertrack/kite-collector/internal/audit"
	"github.com/vulnertrack/kite-collector/internal/classifier"
	"github.com/vulnertrack/kite-collector/internal/config"
	"github.com/vulnertrack/kite-collector/internal/dedup"
	"github.com/vulnertrack/kite-collector/internal/discovery"
	"github.com/vulnertrack/kite-collector/internal/discovery/agent/software"
	"github.com/vulnertrack/kite-collector/internal/emitter"
	"github.com/vulnertrack/kite-collector/internal/metrics"
	"github.com/vulnertrack/kite-collector/internal/model"
	"github.com/vulnertrack/kite-collector/internal/policy"
	"github.com/vulnertrack/kite-collector/internal/posture"
	"github.com/vulnertrack/kite-collector/internal/store"
)

type Engine struct {
	store        store.Store
	registry     *discovery.Registry
	deduplicator *dedup.Deduplicator
	classifier   *classifier.Classifier
	emitter      emitter.Emitter
	policy       *policy.Engine
	metrics      *metrics.Metrics
}

// RunOptions carries provenance and pre-allocated identity for a scan.
//
// The zero value preserves the legacy CLI-path behaviour: the engine mints
// its own UUID v7, inserts the scan_runs row itself, and stores no trigger
// metadata. Callers that need to surface the scan ID before the engine
// finishes (for example the HTTP scan coordinator, which returns 202
// Accepted immediately) set ScanID to a pre-allocated value and are
// responsible for inserting the scan_runs row themselves; in that case the
// engine skips its own CreateScanRun call.
type RunOptions struct {
	// TriggerSource is the provenance tag recorded on the ScanRun row
	// when the engine creates it. Empty defaults to "cli". Ignored when
	// ScanID is non-zero (the caller already wrote the row).
	TriggerSource string

	// TriggeredBy identifies the caller (OS user, mTLS CN, or API-key
	// label). Ignored when ScanID is non-zero.
	TriggeredBy string

	// ScanID pre-allocates the scan run UUID. When non-zero the caller
	// must have already persisted the scan_runs row; the engine will not
	// create it and will only update the row at completion. When zero the
	// engine mints a fresh UUID v7 and creates the row itself.
	ScanID uuid.UUID
}

// sourceEnvVars maps discovery source names to the environment variables
// that supply their credentials. Values are injected into the per-source
// config map so connectors read them via cfg["key"]. Only non-empty env
// vars are applied; missing vars result in graceful skip inside each
// connector's Discover method.
var sourceEnvVars = map[string]map[string]string{ //#nosec G101 -- values are env var names, not credentials
	"intune": {
		"tenant_id":     "KITE_INTUNE_TENANT_ID",
		"client_id":     "KITE_INTUNE_CLIENT_ID",
		"client_secret": "KITE_INTUNE_CLIENT_SECRET", // #nosec G101 -- env var name, not a credential
	},
	"jamf": {
		"api_url":  "KITE_JAMF_API_URL",
		"username": "KITE_JAMF_USERNAME",
		"password": "KITE_JAMF_PASSWORD", // #nosec G101 -- env var name, not a credential
	},
	"sccm": {
		"api_url":  "KITE_SCCM_API_URL",
		"username": "KITE_SCCM_USERNAME",
		"password": "KITE_SCCM_PASSWORD", // #nosec G101 -- env var name, not a credential
	},
	"netbox": {
		"api_url": "KITE_NETBOX_API_URL",
		"token":   "KITE_NETBOX_TOKEN", // #nosec G101 -- env var name, not a credential
	},
	"servicenow": {
		"instance_url": "KITE_SERVICENOW_INSTANCE_URL",
		"username":     "KITE_SERVICENOW_USERNAME",
		"password":     "KITE_SERVICENOW_PASSWORD",
		"table":        "KITE_SERVICENOW_TABLE",
	},
}

func New(
	st store.Store,
	reg *discovery.Registry,
	dd *dedup.Deduplicator,
	cls *classifier.Classifier,
	em emitter.Emitter,
	pol *policy.Engine,
	met *metrics.Metrics,
) *Engine {
	return &Engine{
		store:        st,
		registry:     reg,
		deduplicator: dd,
		classifier:   cls,
		emitter:      em,
		policy:       pol,
		metrics:      met,
	}
}

// Run is the CLI-entry-point shim for RunWithOptions. It mints a fresh
// scan ID, creates the ScanRun row, and records a trigger_source of "cli".
func (e *Engine) Run(ctx context.Context, cfg *config.Config) (*model.ScanResult, error) {
	return e.RunWithOptions(ctx, cfg, RunOptions{})
}

// RunWithOptions runs the scan pipeline. When opts.ScanID is non-zero the
// caller owns the scan_runs row and the engine only issues UPDATE; when it
// is the zero UUID the engine mints one and records the initial row.
func (e *Engine) RunWithOptions(ctx context.Context, cfg *config.Config, opts RunOptions) (*model.ScanResult, error) {
	// Apply scan deadline — all scan work uses scanCtx; persistence uses
	// the original ctx so results are saved even when the deadline fires.
	scanCtx, cancel := context.WithTimeout(ctx, cfg.ScanDeadlineDuration())
	defer cancel()

	scanID := opts.ScanID
	engineOwnsRow := scanID == uuid.Nil
	if engineOwnsRow {
		scanID = uuid.Must(uuid.NewV7())

		scopeJSON, _ := json.Marshal(cfg.Discovery.Sources)
		sourceNames := make([]string, 0, len(cfg.Discovery.Sources))
		for name := range cfg.Discovery.Sources {
			sourceNames = append(sourceNames, name)
		}
		sourcesJSON, _ := json.Marshal(sourceNames)

		triggerSource := opts.TriggerSource
		if triggerSource == "" {
			triggerSource = "cli"
		}

		scanRun := model.ScanRun{
			ID:               scanID,
			StartedAt:        time.Now().UTC(),
			Status:           model.ScanStatusRunning,
			ScopeConfig:      string(scopeJSON),
			DiscoverySources: string(sourcesJSON),
			TriggerSource:    triggerSource,
			TriggeredBy:      opts.TriggeredBy,
		}
		if err := e.store.CreateScanRun(ctx, scanRun); err != nil {
			return nil, fmt.Errorf("create scan run: %w", err)
		}
	}

	configs := make(map[string]map[string]any)
	for name, src := range cfg.Discovery.Sources {
		m := map[string]any{
			"scope":              src.Scope,
			"paths":              src.Paths,
			"max_depth":          src.MaxDepth,
			"tcp_ports":          src.TCPPorts,
			"timeout":            src.Timeout,
			"max_concurrent":     src.MaxConcurrent,
			"collect_software":   src.CollectSoftware,
			"collect_interfaces": src.CollectInterfaces,
			"host":               src.Host,
			"endpoint":           src.Endpoint,
			"site":               src.Site,
			"community":          src.Community,
		}
		// Bind MDM/CMDB credential environment variables into the
		// config map so connectors receive them via the standard
		// cfg parameter. Credentials never appear in config files.
		for key, envVar := range sourceEnvVars[name] {
			if val := os.Getenv(envVar); val != "" {
				m[key] = val
			}
		}
		configs[name] = m
	}

	slog.Info("engine: starting discovery", "scan_id", scanID)
	discovered, err := e.registry.DiscoverAll(scanCtx, configs)
	if err != nil {
		if scanCtx.Err() == context.DeadlineExceeded {
			slog.Warn("engine: scan deadline exceeded during discovery",
				"scan_id", scanID,
				"partial_assets", len(discovered),
			)
			// Fall through — process whatever was discovered.
			// Metric is incremented in the final status check.
		} else {
			failResult := model.ScanResult{
				Status:     string(model.ScanStatusFailed),
				ErrorCount: 1,
			}
			_ = e.store.CompleteScanRun(ctx, scanID, failResult)
			return nil, fmt.Errorf("discovery: %w", err)
		}
	}
	slog.Info("engine: discovery complete", "raw_assets", len(discovered))

	dedupResult, err := e.deduplicator.Deduplicate(ctx, discovered)
	if err != nil {
		return nil, fmt.Errorf("deduplicate: %w", err)
	}

	assets := e.classifier.ClassifyAll(dedupResult.Assets)

	inserted, updated, err := e.store.UpsertAssets(ctx, assets)
	if err != nil {
		return nil, fmt.Errorf("upsert assets: %w", err)
	}
	slog.Info("engine: persisted assets", "inserted", inserted, "updated", updated)

	// Collect and persist installed software for the agent asset.
	// Skip if scan deadline already exceeded.
	var softwareCount, softwareErrors int
	if scanCtx.Err() == nil {
		if agentCfg, ok := configs["agent"]; ok {
			if cs, ok := agentCfg["collect_software"].(bool); ok && cs {
				if agentID := findAgentAssetID(assets); agentID != uuid.Nil {
					swReg := software.NewRegistry()
					swResult := swReg.Collect(scanCtx)
					softwareCount = len(swResult.Items)
					if len(swResult.Items) > 0 {
						for i := range swResult.Items {
							swResult.Items[i].AssetID = agentID
						}
						if swErr := e.store.UpsertSoftware(ctx, agentID, swResult.Items); swErr != nil {
							slog.Error("engine: failed to persist software",
								"error", swErr, "asset_id", agentID, "count", len(swResult.Items))
							softwareErrors++
						} else {
							slog.Info("engine: persisted software",
								"asset_id", agentID,
								"count", len(swResult.Items),
								"parse_errors", swResult.TotalErrors(),
							)
						}
					}
					if swResult.HasErrors() {
						logSoftwareParseErrors(swResult.Errs)
					}
				}
			}
		}
	}

	// Configuration audit phase: run enabled auditors on the agent asset.
	// Skip if scan deadline already exceeded.
	var findingsCount, postureCount int
	if scanCtx.Err() == nil && cfg.Audit.Enabled {
		if agentID := findAgentAssetID(assets); agentID != uuid.Nil {
			var agentAsset model.Asset
			for _, a := range assets {
				if a.ID == agentID {
					agentAsset = a
					break
				}
			}

			auditReg := audit.NewRegistry()
			if cfg.Audit.SSH.Enabled {
				auditReg.Register(audit.NewSSH(cfg.Audit.SSH.ConfigPath))
			}
			if cfg.Audit.Firewall.Enabled {
				auditReg.Register(audit.NewFirewall())
			}
			if cfg.Audit.Kernel.Enabled {
				auditReg.Register(audit.NewKernel())
			}
			if cfg.Audit.Permissions.Enabled {
				auditReg.Register(audit.NewPermissions(cfg.Audit.Permissions.Paths))
			}
			if cfg.Audit.Service.Enabled {
				auditReg.Register(audit.NewService(cfg.Audit.Service.CriticalPorts))
			}

			findings, auditErr := auditReg.AuditAll(scanCtx, agentAsset)
			if auditErr != nil {
				slog.Warn("engine: audit phase failed", "error", auditErr)
			}
			if len(findings) > 0 {
				for i := range findings {
					findings[i].ScanRunID = scanID
				}
				if fErr := e.store.InsertFindings(ctx, findings); fErr != nil {
					slog.Error("engine: failed to persist findings", "error", fErr, "count", len(findings))
				} else {
					findingsCount = len(findings)
					slog.Info("engine: audit complete", "findings", findingsCount)
					e.recordFindingMetrics(findings)
				}

				// Posture analysis: evaluate CWE→CAPEC mappings.
				if cfg.Posture.Enabled {
					assessments := posture.Evaluate(findings, agentID, scanID)
					if len(assessments) > 0 {
						if pErr := e.store.InsertPostureAssessments(ctx, assessments); pErr != nil {
							slog.Error("engine: failed to persist posture assessments",
								"error", pErr, "count", len(assessments))
						} else {
							postureCount = len(assessments)
							slog.Info("engine: posture analysis complete", "assessments", postureCount)
						}
					}
				}
			}
		}
	}

	// Code audit phase: run SCA and secrets auditors on all repository assets.
	// Skip if scan deadline already exceeded.
	if scanCtx.Err() == nil && cfg.Audit.Enabled {
		scaTimeout := cfg.Audit.SCA.ParseTimeout()
		codeAuditReg := audit.NewRegistry()
		if cfg.Audit.SCA.Enabled {
			codeAuditReg.Register(audit.NewSCA(scaTimeout))
		}
		if cfg.Audit.Secrets.Enabled {
			codeAuditReg.Register(audit.NewSecrets())
		}

		for _, a := range assets {
			if a.AssetType != model.AssetTypeRepository {
				continue
			}
			codeFindings, auditErr := codeAuditReg.AuditAll(scanCtx, a)
			if auditErr != nil {
				slog.Warn("engine: code audit failed", "asset_id", a.ID, "error", auditErr)
				continue
			}
			if len(codeFindings) == 0 {
				continue
			}
			for i := range codeFindings {
				codeFindings[i].ScanRunID = scanID
			}
			if fErr := e.store.InsertFindings(ctx, codeFindings); fErr != nil {
				slog.Error("engine: failed to persist code findings",
					"error", fErr, "asset_id", a.ID, "count", len(codeFindings))
			} else {
				findingsCount += len(codeFindings)
				slog.Info("engine: code audit complete",
					"asset_id", a.ID,
					"hostname", a.Hostname,
					"findings", len(codeFindings),
				)
				e.recordFindingMetrics(codeFindings)
			}
		}
	}

	// Stale asset detection and event generation — skip heavy work if
	// the scan deadline already fired.
	var staleAssets []model.Asset
	var events []model.AssetEvent

	if scanCtx.Err() == nil {
		staleAssets, err = e.store.GetStaleAssets(ctx, cfg.StaleThresholdDuration())
		if err != nil {
			slog.Warn("engine: failed to detect stale assets", "error", err)
			staleAssets = nil
		}
	}

	for i := range assets {
		var evtType model.EventType
		if assets[i].FirstSeenAt.Equal(assets[i].LastSeenAt) {
			evtType = model.EventAssetDiscovered
		} else {
			evtType = model.EventAssetUpdated
		}
		severity := e.policy.EvaluateSeverity(assets[i])
		if assets[i].IsAuthorized == model.AuthorizationUnauthorized {
			evtType = model.EventUnauthorizedAssetDetected
		} else if assets[i].IsManaged == model.ManagedUnmanaged {
			evtType = model.EventUnmanagedAssetDetected
		}
		evt := model.AssetEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: evtType,
			ScanRunID: scanID,
			Severity:  severity,
			Timestamp: time.Now().UTC(),
			Details:   model.BuildEventDetails(assets[i], evtType),
		}
		evt.FromAsset(assets[i])
		events = append(events, evt)
	}

	for i := range staleAssets {
		evt := model.AssetEvent{
			ID:        uuid.Must(uuid.NewV7()),
			EventType: model.EventAssetNotSeen,
			ScanRunID: scanID,
			Severity:  e.policy.EvaluateSeverity(staleAssets[i]),
			Timestamp: time.Now().UTC(),
			Details:   model.BuildEventDetails(staleAssets[i], model.EventAssetNotSeen),
		}
		evt.FromAsset(staleAssets[i])
		events = append(events, evt)
	}

	if len(events) > 0 {
		if err := e.store.InsertEvents(ctx, events); err != nil {
			slog.Warn("engine: failed to persist events", "error", err)
		}
		if err := e.emitter.EmitBatch(ctx, events); err != nil {
			slog.Warn("engine: failed to emit events", "error", err)
		}
	}

	if e.metrics != nil {
		e.metrics.StaleAssets.Set(float64(len(staleAssets)))
	}

	allAssets, _ := e.store.ListAssets(ctx, store.AssetFilter{})
	totalKnown := len(allAssets)
	coveragePct := 0.0
	if totalKnown > 0 {
		coveragePct = float64(len(assets)) / float64(totalKnown) * 100.0
	}

	scanStatus := model.ScanStatusCompleted
	var errorCount int
	if scanCtx.Err() == context.DeadlineExceeded {
		scanStatus = model.ScanStatusTimedOut
		errorCount = 1
		if e.metrics != nil {
			e.metrics.ScanDeadlineExceeded.Inc()
		}
		// Record runtime incident for the deadline breach.
		_ = e.store.InsertRuntimeIncident(ctx, model.RuntimeIncident{
			ID:           uuid.Must(uuid.NewV7()),
			IncidentType: model.IncidentTimeoutExceeded,
			Component:    "engine",
			ErrorMessage: fmt.Sprintf("scan deadline exceeded (%s)", cfg.ScanDeadlineDuration()),
			ScanRunID:    &scanID,
			Severity:     string(model.SeverityHigh),
			Recovered:    true,
			ErrorCode:    "KITE-E013",
			CreatedAt:    time.Now().UTC(),
		})
	}

	result := &model.ScanResult{
		Status:          string(scanStatus),
		TotalAssets:     totalKnown,
		NewAssets:       dedupResult.NewCount,
		UpdatedAssets:   dedupResult.UpdatedCount,
		StaleAssets:     len(staleAssets),
		EventsEmitted:   len(events),
		SoftwareCount:   softwareCount,
		SoftwareErrors:  softwareErrors,
		FindingsCount:   findingsCount,
		PostureCount:    postureCount,
		ErrorCount:      errorCount,
		CoveragePercent: coveragePct,
	}

	if err := e.store.CompleteScanRun(ctx, scanID, *result); err != nil {
		slog.Warn("engine: failed to complete scan run", "error", err)
	}

	slog.Info("engine: scan complete",
		"total", result.TotalAssets,
		"new", result.NewAssets,
		"updated", result.UpdatedAssets,
		"stale", result.StaleAssets,
		"events", result.EventsEmitted,
		"status", result.Status,
	)

	return result, nil
}

// findAgentAssetID returns the ID of the first asset with DiscoverySource "agent".
func findAgentAssetID(assets []model.Asset) uuid.UUID {
	for _, a := range assets {
		if a.DiscoverySource == "agent" {
			return a.ID
		}
	}
	return uuid.Nil
}

// maxParseErrorLogs caps how many individual software parse errors are
// logged per scan run so a malformed package-manager output cannot flood
// the journal. The remainder is summarised in a single "truncated" line.
const maxParseErrorLogs = 20

// maxRawLineLog truncates each raw_line attribute so a multi-kilobyte JSON
// blob doesn't blow up the log destination.
const maxRawLineLog = 256

// logSoftwareParseErrors emits one Warn record per software collector parse
// error so operators can see exactly which line of which package manager's
// output failed. Lines beyond maxParseErrorLogs are collapsed into a single
// summary record. The log destination already carries run_id via the root
// logger configured in cmd/kite-collector/main.go.
func logSoftwareParseErrors(errs []software.CollectError) {
	limit := len(errs)
	if limit > maxParseErrorLogs {
		limit = maxParseErrorLogs
	}
	for i := 0; i < limit; i++ {
		e := errs[i]
		raw := e.RawLine
		if len(raw) > maxRawLineLog {
			raw = raw[:maxRawLineLog] + "…"
		}
		slog.Warn("engine: software parse error",
			"collector", e.Collector,
			"line", e.Line,
			"error", e.Err,
			"raw_line", raw,
		)
	}
	if len(errs) > maxParseErrorLogs {
		slog.Warn("engine: software parse errors truncated",
			"shown", maxParseErrorLogs,
			"total", len(errs),
		)
	}
}

// recordFindingMetrics updates the open-findings gauge, cumulative counter,
// and finding-age histogram for a batch of findings.
func (e *Engine) recordFindingMetrics(findings []model.ConfigFinding) {
	if e.metrics == nil {
		return
	}
	now := time.Now().UTC()
	for _, f := range findings {
		sev := string(f.Severity)
		aud := f.Auditor
		e.metrics.FindingsOpen.WithLabelValues(sev, aud).Inc()
		e.metrics.FindingsTotal.WithLabelValues(sev, aud).Inc()
		if !f.FirstSeenAt.IsZero() {
			ageHours := now.Sub(f.FirstSeenAt).Hours()
			e.metrics.FindingAgeHours.WithLabelValues(sev, aud).Observe(ageHours)
		}
	}
}
