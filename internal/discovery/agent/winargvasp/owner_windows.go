//go:build windows

package winargvasp

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
