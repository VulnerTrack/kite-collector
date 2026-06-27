//go:build windows

package winarghomebroker

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
