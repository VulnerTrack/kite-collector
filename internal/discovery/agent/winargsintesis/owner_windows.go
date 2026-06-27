//go:build windows

package winargsintesis

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
