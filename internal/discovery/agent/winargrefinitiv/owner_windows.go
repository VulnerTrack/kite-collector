//go:build windows

package winargrefinitiv

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
