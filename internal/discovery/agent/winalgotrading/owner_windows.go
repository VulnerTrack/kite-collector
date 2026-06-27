//go:build windows

package winalgotrading

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
