//go:build windows

package winsamexports

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
