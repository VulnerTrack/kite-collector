//go:build windows

package winargsierra

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
