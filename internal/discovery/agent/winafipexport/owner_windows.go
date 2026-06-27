//go:build windows

package winafipexport

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
