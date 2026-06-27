//go:build windows

package winargtradingview

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
