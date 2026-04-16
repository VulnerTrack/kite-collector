package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	var (
		certsDir   string
		binaryDir  string
		systemdDir string
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Install kite and register the streaming systemd service",
		Long: `Install the kite binary and register kite-stream.service.

Must be run as root (sudo ./kite-collector install).

What it does:
  1. Copies this binary to {binary-dir}/kite
  2. Creates {certs-dir}/   (certificate store)
  3. Writes kite-stream.service to {systemd-dir}
  4. Runs systemctl daemon-reload

After install, three commands become available:

  kite enroll --agent-code <code> --token <token>   ← one-time PKI enrollment
  kite check                                          ← verify OTLP connectivity
  sudo systemctl enable --now kite-stream             ← start continuous streaming`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInstall(cmd, certsDir, binaryDir, systemdDir, dryRun)
		},
	}

	cmd.Flags().StringVar(&certsDir, "certs-dir", "/var/lib/kite-collector",
		"certificate store path used by the stream service")
	cmd.Flags().StringVar(&binaryDir, "binary-dir", "/usr/local/bin",
		"directory to install the kite binary")
	cmd.Flags().StringVar(&systemdDir, "systemd-dir", "/etc/systemd/system",
		"directory for the systemd unit file")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false,
		"print what would be written without making changes")

	return cmd
}

func runInstall(cmd *cobra.Command, certsDir, binaryDir, systemdDir string, dryRun bool) error {
	out := cmd.OutOrStdout()

	src, err := os.Executable()
	if err != nil {
		src = "kite-collector"
	}
	src, _ = filepath.Abs(src)
	kiteBin := filepath.Join(binaryDir, "kite")
	unitPath := filepath.Join(systemdDir, "kite-stream.service")
	unitContent := buildStreamUnit(kiteBin, certsDir)

	if dryRun {
		_, _ = fmt.Fprintln(out, "-- dry-run: no files will be written --")
		_, _ = fmt.Fprintf(out, "  copy   %s → %s\n", src, kiteBin)
		_, _ = fmt.Fprintf(out, "  mkdir  %s\n", certsDir)
		_, _ = fmt.Fprintf(out, "  write  %s\n\n%s\n", unitPath, unitContent)
		return nil
	}

	_, _ = fmt.Fprintln(out)

	// 1. Install binary.
	if err := installBinary(src, kiteBin); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	_, _ = fmt.Fprintf(out, "  ✓  %s\n", kiteBin)

	// 2. Create certificate store directory.
	if err := os.MkdirAll(certsDir, 0o750); err != nil {
		return fmt.Errorf("create certs dir %s: %w", certsDir, err)
	}

	// 3. Write systemd unit.
	if err := os.WriteFile(unitPath, []byte(unitContent), 0o644); err != nil { //#nosec G306 -- systemd units are world-readable
		return fmt.Errorf("write %s: %w", unitPath, err)
	}
	_, _ = fmt.Fprintf(out, "  ✓  %s\n", unitPath)

	// 4. Reload daemon.
	if err := exec.CommandContext(cmd.Context(), "systemctl", "daemon-reload").Run(); err != nil { //#nosec G204 -- args are fixed literals
		_, _ = fmt.Fprintf(out, "  ⚠  systemctl daemon-reload: %v\n", err)
	} else {
		_, _ = fmt.Fprintln(out, "  ✓  systemctl daemon-reload")
	}

	// Next steps.
	_, _ = fmt.Fprintf(out, `
Next steps:

  1. Enroll this agent (one-time):
       %s enroll --agent-code <code> --token <token>

  2. Verify OTLP connectivity:
       %s check

  3. Start continuous streaming:
       sudo systemctl enable --now kite-stream
       journalctl -fu kite-stream

`, kiteBin, kiteBin)

	return nil
}

// ---------------------------------------------------------------------------
// Systemd unit template
// ---------------------------------------------------------------------------

func buildStreamUnit(binary, certsDir string) string {
	return fmt.Sprintf(`[Unit]
Description=Kite Collector — Continuous Asset Discovery
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s agent --stream --certs-dir %s
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kite-stream

[Install]
WantedBy=multi-user.target
`, binary, certsDir)
}

// ---------------------------------------------------------------------------
// Binary copy helper
// ---------------------------------------------------------------------------

// installBinary copies src to dst atomically (write to dst.tmp, rename).
// No-ops when src and dst are the same path.
func installBinary(src, dst string) error {
	if src == dst {
		return nil
	}

	in, err := os.Open(src) //#nosec G304 -- src is os.Executable()
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755) //#nosec G306 -- binary must be executable
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
