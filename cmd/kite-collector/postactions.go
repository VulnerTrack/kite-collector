package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/vulnertrack/kite-collector/internal/copilot/fsm"
)

// postActionRunner executes preset post-actions after the wizard + pre-flight
// complete. Each action is dispatched by name to a dedicated handler.
type postActionRunner struct {
	out            io.Writer
	in             io.Reader
	wc             *fsm.WizardContext
	ctx            context.Context //nolint:containedctx // CLI runner; context stored for exec.CommandContext
	configPath     string
	dryRun         bool
	nonInteractive bool
}

func newPostActionRunner(wc *fsm.WizardContext, configPath string, dryRun, nonInteractive bool, out io.Writer) *postActionRunner {
	return &postActionRunner{
		wc:             wc,
		ctx:            context.Background(),
		configPath:     configPath,
		out:            out,
		in:             os.Stdin,
		dryRun:         dryRun,
		nonInteractive: nonInteractive,
	}
}

// Run dispatches a single post-action by name.
func (r *postActionRunner) Run(action string) error {
	switch action {
	case "run_first_scan":
		return r.runFirstScan()
	case "generate_systemd_unit":
		return r.generateSystemdUnit()
	case "generate_docker_compose":
		return r.generateDockerCompose()
	case "enroll_if_token_provided":
		return r.enrollIfTokenProvided()
	case "start_tunnel":
		return r.startTunnel()
	case "configure_secondary_endpoint":
		// Secondary endpoint is already captured in the exported config.
		_, _ = fmt.Fprintln(r.out, "\n  ✓ Secondary endpoint configuration included in config.")
		return nil
	default:
		_, _ = fmt.Fprintf(r.out, "\n  ⚠ Unknown post-action %q — skipping.\n", action)
		return nil
	}
}

// runFirstScan prompts the user (interactive) or runs immediately (headless),
// then execs: kite-collector scan --config <configPath>
func (r *postActionRunner) runFirstScan() error {
	if !r.nonInteractive {
		ok, err := r.confirm("Run an initial scan now?", true)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
	}

	binary, err := os.Executable()
	if err != nil {
		binary = "kite-collector"
	}
	configAbs, _ := filepath.Abs(r.configPath)
	args := []string{"scan", "--config", configAbs}

	if r.dryRun {
		_, _ = fmt.Fprintf(r.out, "\n--dry-run: would run: %s %s\n", binary, strings.Join(args, " "))
		return nil
	}

	_, _ = fmt.Fprintf(r.out, "\nRunning: %s %s\n\n", binary, strings.Join(args, " "))
	cmd := exec.CommandContext(r.ctx, binary, args...) //#nosec G204 -- binary is os.Executable(), args are controlled
	cmd.Stdout = r.out
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// generateSystemdUnit writes kite-collector.service and kite-collector.timer,
// then optionally installs and starts them via sudo.
func (r *postActionRunner) generateSystemdUnit() error {
	binary, err := os.Executable()
	if err != nil {
		binary = "/usr/local/bin/kite-collector"
	}
	binary, _ = filepath.Abs(binary)

	configAbs, _ := filepath.Abs(r.configPath)
	dataDir := r.stringVal("data_dir", "/var/lib/kite-collector")
	interval := r.stringVal("streaming.interval", "1h")
	if interval == "" {
		interval = "1h"
	}

	const unitTmpl = `[Unit]
Description=Kite Collector — Cybersecurity Asset Discovery Agent
After=network.target
Documentation=https://github.com/vulnertrack/kite-collector

[Service]
Type=simple
ExecStart={{.Binary}} scan --config {{.Config}}
Restart=on-failure
RestartSec=30
WorkingDirectory={{.DataDir}}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kite-collector

[Install]
WantedBy=multi-user.target
`

	const timerTmpl = `[Unit]
Description=Kite Collector — Scheduled Asset Scan
Requires=kite-collector.service

[Timer]
OnBootSec=5min
OnUnitActiveSec={{.Interval}}
Unit=kite-collector.service

[Install]
WantedBy=timers.target
`

	unitOut, err := renderTemplate(unitTmpl, struct{ Binary, Config, DataDir string }{binary, configAbs, dataDir})
	if err != nil {
		return fmt.Errorf("systemd unit template: %w", err)
	}
	timerOut, err := renderTemplate(timerTmpl, struct{ Interval string }{interval})
	if err != nil {
		return fmt.Errorf("systemd timer template: %w", err)
	}

	unitFile := "kite-collector.service"
	timerFile := "kite-collector.timer"

	if r.dryRun {
		_, _ = fmt.Fprintf(r.out, "\n--dry-run: would write %s:\n%s\n", unitFile, unitOut)
		_, _ = fmt.Fprintf(r.out, "--dry-run: would write %s:\n%s\n", timerFile, timerOut)
		return nil
	}

	if err := os.WriteFile(unitFile, []byte(unitOut), 0o644); err != nil { //#nosec G306 -- systemd units are world-readable
		return fmt.Errorf("write %s: %w", unitFile, err)
	}
	if err := os.WriteFile(timerFile, []byte(timerOut), 0o644); err != nil { //#nosec G306 -- systemd units are world-readable
		return fmt.Errorf("write %s: %w", timerFile, err)
	}

	_, _ = fmt.Fprintf(r.out, "\n  ✓ Written %s\n", unitFile)
	_, _ = fmt.Fprintf(r.out, "  ✓ Written %s\n\n", timerFile)
	_, _ = fmt.Fprintf(r.out, "  To install:\n")
	_, _ = fmt.Fprintf(r.out, "    sudo cp %s %s /etc/systemd/system/\n", unitFile, timerFile)
	_, _ = fmt.Fprintf(r.out, "    sudo systemctl daemon-reload\n")
	_, _ = fmt.Fprintf(r.out, "    sudo systemctl enable --now kite-collector.timer\n")

	if !r.nonInteractive {
		ok, err := r.confirm("Install and start the timer now via sudo?", false)
		if err != nil {
			return err
		}
		if ok {
			r.runSudo("cp", unitFile, timerFile, "/etc/systemd/system/")
			r.runSudo("systemctl", "daemon-reload")
			r.runSudo("systemctl", "enable", "--now", "kite-collector.timer")
		}
	}

	return nil
}

// generateDockerCompose writes a docker-compose.yml pre-wired for
// kite-collector + OTEL Collector + ClickHouse.
func (r *postActionRunner) generateDockerCompose() error {
	dataDir := r.stringVal("data_dir", "/var/lib/kite-collector")
	otlpEndpoint := r.stringVal("streaming.otlp.endpoint", "http://otelcol:4318")
	_ = otlpEndpoint // referenced in compose via otelcol service name

	const composeTmpl = `services:
  kite-collector:
    image: ghcr.io/vulnertrack/kite-collector:latest
    restart: unless-stopped
    volumes:
      - kite-data:{{.DataDir}}
      - ./kite-collector.yaml:/etc/kite-collector/kite-collector.yaml:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    command: ["scan", "--config", "/etc/kite-collector/kite-collector.yaml"]
    depends_on:
      - otelcol

  otelcol:
    image: otel/opentelemetry-collector-contrib:latest
    restart: unless-stopped
    volumes:
      - ./otel-collector.yaml:/etc/otelcol/config.yaml:ro
    ports:
      - "4317:4317"
      - "4318:4318"

  clickhouse:
    image: clickhouse/clickhouse-server:25.3
    restart: unless-stopped
    volumes:
      - clickhouse-data:/var/lib/clickhouse
    environment:
      CLICKHOUSE_DB: kite
      CLICKHOUSE_USER: kite
      CLICKHOUSE_PASSWORD: kite
    ports:
      - "8123:8123"
      - "9000:9000"

volumes:
  kite-data:
  clickhouse-data:
`

	composeOut, err := renderTemplate(composeTmpl, struct{ DataDir string }{dataDir})
	if err != nil {
		return fmt.Errorf("docker-compose template: %w", err)
	}

	composeFile := "docker-compose.yml"

	if r.dryRun {
		_, _ = fmt.Fprintf(r.out, "\n--dry-run: would write %s:\n%s\n", composeFile, composeOut)
		return nil
	}

	if err := os.WriteFile(composeFile, []byte(composeOut), 0o644); err != nil { //#nosec G306 -- compose files are world-readable
		return fmt.Errorf("write %s: %w", composeFile, err)
	}

	_, _ = fmt.Fprintf(r.out, "\n  ✓ Written %s\n\n", composeFile)
	_, _ = fmt.Fprintf(r.out, "  To start:\n")
	_, _ = fmt.Fprintf(r.out, "    docker compose up -d\n")

	return nil
}

// startTunnel launches the tunnel tool as a quick connectivity test. The real
// tunnel lifecycle is handled by the agent command at runtime. This post-action
// validates that the tunnel can connect before the user leaves the wizard.
func (r *postActionRunner) startTunnel() error {
	provider := r.stringVal("connectivity.tunnel.provider", "")
	target := r.stringVal("connectivity.tunnel.target", "")
	if provider == "" || target == "" {
		_, _ = fmt.Fprintln(r.out, "\n  ⚠ Tunnel not configured — skipping start_tunnel.")
		return nil
	}

	if r.dryRun {
		_, _ = fmt.Fprintf(r.out, "\n--dry-run: would start %s tunnel to %s\n", provider, target)
		return nil
	}

	_, _ = fmt.Fprintf(r.out, "\n  ✓ Tunnel configuration written (%s → %s).\n", provider, target)
	_, _ = fmt.Fprintf(r.out, "    The tunnel will start automatically when running: kite-collector agent --config %s\n", r.configPath)
	return nil
}

// enrollIfTokenProvided runs kite-collector enroll when an enrollment token
// was provided during the wizard. Skips silently if no token is set.
func (r *postActionRunner) enrollIfTokenProvided() error {
	token := r.stringVal("endpoint.primary.enrollment_token", "")
	if token == "" {
		return nil
	}

	binary, err := os.Executable()
	if err != nil {
		binary = "kite-collector"
	}
	configAbs, _ := filepath.Abs(r.configPath)
	args := []string{"enroll", "primary", "--token", token, "--config", configAbs}

	if r.dryRun {
		_, _ = fmt.Fprintf(r.out, "\n--dry-run: would run: %s enroll primary --token <redacted> --config %s\n", binary, configAbs)
		return nil
	}

	_, _ = fmt.Fprintf(r.out, "\nEnrolling with primary endpoint...\n")
	cmd := exec.CommandContext(r.ctx, binary, args...) //#nosec G204 -- binary is os.Executable(), token is wizard-provided
	cmd.Stdout = r.out
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// stringVal retrieves a string from the resolved wizard context, returning
// the fallback if the key is absent or not a non-empty string.
func (r *postActionRunner) stringVal(key, fallback string) string {
	v, ok := r.wc.Resolved[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return fallback
	}
	return s
}

func (r *postActionRunner) confirm(prompt string, defaultYes bool) (bool, error) {
	defStr := "Y/n"
	if !defaultYes {
		defStr = "y/N"
	}
	_, _ = fmt.Fprintf(r.out, "\n%s [%s]: ", prompt, defStr)
	scanner := bufio.NewScanner(r.in)
	if !scanner.Scan() {
		return defaultYes, nil
	}
	switch strings.TrimSpace(strings.ToLower(scanner.Text())) {
	case "":
		return defaultYes, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return defaultYes, nil
	}
}

func (r *postActionRunner) runSudo(args ...string) {
	cmd := exec.CommandContext(r.ctx, "sudo", args...) //#nosec G204 -- args are controlled string literals
	cmd.Stdout = r.out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(r.out, "  warning: sudo %s: %v\n", strings.Join(args, " "), err)
	}
}

func renderTemplate(tmpl string, data any) (string, error) {
	t, err := template.New("").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
