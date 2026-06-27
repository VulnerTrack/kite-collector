//go:build windows

package winargtt

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
