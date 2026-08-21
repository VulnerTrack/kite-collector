package discovery

import "errors"

// ErrNotConfigured marks a source error that means "this source has
// nothing to act on": required credentials, endpoints, or scope are
// absent. Sources wrap their missing-configuration errors with it
// (fmt.Errorf("…: %w", discovery.ErrNotConfigured)) so the registry
// can tell a deliberately-inactive source apart from a broken one.
//
// The distinction matters operationally: a fleet ships with every
// source registered but only a few configured, so treating "no
// credentials" as a failure buries real failures under a constant WARN
// floor, feeds the circuit breaker with noise, and marks heartbeats
// unhealthy for sources that are behaving exactly as configured.
var ErrNotConfigured = errors.New("source not configured")
