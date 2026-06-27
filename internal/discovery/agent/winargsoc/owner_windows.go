//go:build windows

package winargsoc

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
