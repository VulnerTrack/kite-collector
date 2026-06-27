//go:build windows

package winargmt

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
