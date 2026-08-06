//go:build !linux && !darwin && !windows

package dashboard

func defaultGatewayIPv4(_, _ string) string { return "" }
