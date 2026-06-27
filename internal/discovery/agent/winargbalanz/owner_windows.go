//go:build windows

package winargbalanz

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
