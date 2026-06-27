//go:build windows

package winargpybacktest

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
