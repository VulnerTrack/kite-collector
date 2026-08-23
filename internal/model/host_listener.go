package model

import (
	"time"

	"github.com/google/uuid"
)

// HostListener is one LISTEN socket observed on a machine, mirroring the
// host_listeners table. Service / ServiceVersion are populated by the
// fingerprintx recogniser when service fingerprinting is enabled; they are
// empty for an unrecognised port.
type HostListener struct {
	LastSeenAt     time.Time
	CollectedAt    time.Time
	ID             uuid.UUID
	MachineID      uuid.UUID
	Protocol       string // tcp | tcp6 | udp | udp6
	BindAddress    string
	Exposure       string // internet | lan | loopback | unknown
	ProcessName    string
	Exe            string
	Username       string
	Service        string
	ServiceVersion string
	Port           uint16
	PID            int32
}
