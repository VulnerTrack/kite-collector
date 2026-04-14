package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Status represents the current state of a tunnel instance.
type Status string

const (
	StatusStarting     Status = "starting"
	StatusConnected    Status = "connected"
	StatusDisconnected Status = "disconnected"
	StatusFailed       Status = "failed"
)

// TunnelInstance represents a running tunnel subprocess.
type TunnelInstance struct {
	Provider        ProviderName `json:"provider"`
	Target          string       `json:"target"`
	TunnelURL       string       `json:"tunnel_url,omitempty"`
	StartedAt       time.Time    `json:"started_at"`
	LastConnectedAt time.Time    `json:"last_connected_at,omitempty"`
	Status          Status       `json:"status"`
	EntityID        uuid.UUID    `json:"entity_id"`
	PID             int          `json:"pid,omitempty"`
	RestartCount    uint32       `json:"restart_count"`
	LocalPort       uint16       `json:"local_port"`
}

// ManagerConfig holds the tunnel manager configuration.
type ManagerConfig struct {
	Provider     ProviderName
	Target       string // remote endpoint (e.g., "ingest.vulnertrack.io:443")
	AuthTokenEnv string // env var name containing auth token
	ExtraArgs    []string
	BackoffBase  time.Duration
	BackoffMax   time.Duration
	RestartMax   int    // 0 = unlimited
	LocalPort    uint16
	Enabled      bool // master toggle
}

// Manager manages the lifecycle of a tunnel subprocess: start, monitor,
// restart with exponential backoff, and stop on context cancellation.
type Manager struct {
	logger   *slog.Logger
	instance *TunnelInstance
	cancel   context.CancelFunc
	cmd      *exec.Cmd
	cfg      ManagerConfig
	mu       sync.Mutex
	stopped  bool
}

// NewManager creates a tunnel manager. The tunnel is not started until
// Start() is called.
func NewManager(cfg ManagerConfig, logger *slog.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		logger: logger.With("component", "tunnel"),
	}
}

// Start begins the tunnel subprocess and monitor goroutine. It blocks until
// the tunnel is healthy or the initial health check fails. Returns the local
// address (localhost:port) that downstream code should use, or an error if
// the tunnel could not be started.
//
// Tunnel failure is non-fatal for the agent — the caller should log a warning
// and continue without the tunnel if Start returns an error.
func (m *Manager) Start(ctx context.Context) (string, error) {
	if !m.cfg.Enabled {
		return "", nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	tunnelCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel

	m.instance = &TunnelInstance{
		EntityID:  uuid.Must(uuid.NewV7()),
		Provider:  m.cfg.Provider,
		Target:    m.cfg.Target,
		LocalPort: m.cfg.LocalPort,
		Status:    StatusStarting,
		StartedAt: time.Now(),
	}

	if err := m.startProcess(tunnelCtx); err != nil {
		m.instance.Status = StatusFailed
		return "", fmt.Errorf("start tunnel: %w", err)
	}

	// Wait for the tunnel to become healthy.
	localAddr := fmt.Sprintf("localhost:%d", m.cfg.LocalPort)
	if err := m.waitHealthy(tunnelCtx, localAddr); err != nil {
		m.logger.Warn("tunnel not healthy after start, continuing without tunnel",
			"error", err,
			"provider", m.cfg.Provider,
		)
		m.instance.Status = StatusDisconnected
		// Start monitor anyway — it will retry.
		go m.monitor(tunnelCtx)
		return "", err
	}

	m.instance.Status = StatusConnected
	m.instance.LastConnectedAt = time.Now()
	m.logger.Info("tunnel healthy",
		"provider", m.cfg.Provider,
		"local_addr", localAddr,
		"target", m.cfg.Target,
		"pid", m.instance.PID,
	)

	go m.monitor(tunnelCtx)

	return localAddr, nil
}

// Stop terminates the tunnel subprocess and waits for cleanup.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopped = true
	if m.cancel != nil {
		m.cancel()
	}
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
	}
	if m.instance != nil {
		m.instance.Status = StatusDisconnected
	}
	m.logger.Info("tunnel stopped")
}

// Instance returns the current tunnel instance state (snapshot).
func (m *Manager) Instance() *TunnelInstance {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.instance == nil {
		return nil
	}
	// Return a copy without the mutex.
	return &TunnelInstance{
		EntityID:        m.instance.EntityID,
		Provider:        m.instance.Provider,
		Target:          m.instance.Target,
		TunnelURL:       m.instance.TunnelURL,
		Status:          m.instance.Status,
		StartedAt:       m.instance.StartedAt,
		LastConnectedAt: m.instance.LastConnectedAt,
		LocalPort:       m.instance.LocalPort,
		PID:             m.instance.PID,
		RestartCount:    m.instance.RestartCount,
	}
}

// startProcess builds and starts the tunnel subprocess.
func (m *Manager) startProcess(ctx context.Context) error {
	args := BuildCommand(m.cfg.Provider, m.cfg.Target, m.cfg.LocalPort, m.cfg.AuthTokenEnv, m.cfg.ExtraArgs)
	if len(args) == 0 {
		return fmt.Errorf("unsupported tunnel provider: %s", m.cfg.Provider)
	}

	binary := args[0]
	path, err := exec.LookPath(binary)
	if err != nil {
		return fmt.Errorf("tunnel binary %q not found in PATH: %w", binary, err)
	}

	m.cmd = exec.CommandContext(ctx, path, args[1:]...) //#nosec G204 -- path from LookPath, args from BuildCommand
	m.cmd.Env = m.cmd.Environ()

	// Capture stdout/stderr to structured log.
	stdout, _ := m.cmd.StdoutPipe()
	stderr, _ := m.cmd.StderrPipe()

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("exec tunnel: %w", err)
	}

	m.instance.PID = m.cmd.Process.Pid
	m.logger.Info("tunnel subprocess started",
		"provider", m.cfg.Provider,
		"pid", m.instance.PID,
		"binary", path,
	)

	go m.logOutput("stdout", stdout)
	go m.logOutput("stderr", stderr)

	return nil
}

// logOutput reads from r line-by-line and logs each line with component=tunnel.
func (m *Manager) logOutput(stream string, r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			m.logger.Debug("tunnel output",
				"stream", stream,
				"provider", m.cfg.Provider,
				"line", string(buf[:n]),
			)
		}
		if err != nil {
			return
		}
	}
}

// waitHealthy probes the local tunnel port with TCP until it responds or
// the timeout is reached (5s timeout, 3 retries, 1s between retries).
func (m *Manager) waitHealthy(ctx context.Context, addr string) error {
	const (
		maxRetries   = 3
		retryDelay   = time.Second
		dialTimeout  = 5 * time.Second
	)

	for attempt := range maxRetries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return nil
		}

		m.logger.Debug("tunnel health probe failed",
			"addr", addr,
			"attempt", attempt+1,
			"error", err,
		)

		if attempt < maxRetries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(retryDelay):
			}
		}
	}
	return fmt.Errorf("tunnel at %s not healthy after %d probes", addr, maxRetries)
}

// monitor watches the tunnel subprocess and restarts it on failure with
// exponential backoff. Runs as a goroutine.
func (m *Manager) monitor(ctx context.Context) {
	for {
		if m.cmd != nil {
			_ = m.cmd.Wait()
		}

		m.mu.Lock()
		if m.stopped {
			m.mu.Unlock()
			return
		}

		m.instance.Status = StatusDisconnected
		m.instance.RestartCount++
		restartCount := m.instance.RestartCount

		if m.cfg.RestartMax > 0 && int(restartCount) > m.cfg.RestartMax {
			m.instance.Status = StatusFailed
			m.logger.Error("tunnel restart limit reached, giving up",
				"provider", m.cfg.Provider,
				"restart_count", restartCount,
				"restart_max", m.cfg.RestartMax,
			)
			m.mu.Unlock()
			return
		}
		m.mu.Unlock()

		// Exponential backoff: base * 2^(n-1), capped at max.
		delay := m.backoff(restartCount)
		m.logger.Warn("tunnel subprocess exited, restarting",
			"provider", m.cfg.Provider,
			"restart_count", restartCount,
			"backoff", delay,
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		m.mu.Lock()
		if m.stopped {
			m.mu.Unlock()
			return
		}

		if err := m.startProcess(ctx); err != nil {
			m.logger.Error("tunnel restart failed",
				"provider", m.cfg.Provider,
				"error", err,
			)
			m.mu.Unlock()
			continue
		}

		localAddr := fmt.Sprintf("localhost:%d", m.cfg.LocalPort)
		if err := m.waitHealthy(ctx, localAddr); err != nil {
			m.logger.Warn("tunnel not healthy after restart", "error", err)
			m.mu.Unlock()
			continue
		}

		m.instance.Status = StatusConnected
		m.instance.LastConnectedAt = time.Now()
		m.logger.Info("tunnel reconnected",
			"provider", m.cfg.Provider,
			"restart_count", restartCount,
			"pid", m.instance.PID,
		)
		m.mu.Unlock()
	}
}

// backoff calculates exponential backoff: base * 2^(n-1), capped at max.
func (m *Manager) backoff(restartCount uint32) time.Duration {
	base := m.cfg.BackoffBase
	if base == 0 {
		base = 5 * time.Second
	}
	maxDelay := m.cfg.BackoffMax
	if maxDelay == 0 {
		maxDelay = 5 * time.Minute
	}

	exp := math.Pow(2, float64(restartCount-1))
	delay := time.Duration(float64(base) * exp)
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}
