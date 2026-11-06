//go:build !windows
// +build !windows

package main

// The legacy agent is Windows-only; other platforms run its parser tests.
func openLegacyBrowser(string) {}
