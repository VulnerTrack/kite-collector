//go:build windows

package winargacdi

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
