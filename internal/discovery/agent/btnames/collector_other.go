//go:build !linux

package btnames

import "context"

// stubCollector is the no-op implementation for platforms where we
// haven't yet implemented native Bluetooth paired-device extraction.
// macOS would parse `/Library/Preferences/com.apple.Bluetooth.plist`
// (binary plist) or shell out to `system_profiler SPBluetoothDataType
// -xml`; Windows would walk
// `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices`.
// Both pathways carry meaningful complexity (plist parsing / registry
// access) that warrants its own follow-up scope.
type stubCollector struct{}

// NewCollector returns a Collector that returns an empty inventory.
// Tracked under task #170 for follow-up scope.
func NewCollector() Collector { return stubCollector{} }

func (stubCollector) Name() string { return "btnames-stub" }

func (stubCollector) Collect(_ context.Context) ([]Row, error) {
	return nil, nil
}
