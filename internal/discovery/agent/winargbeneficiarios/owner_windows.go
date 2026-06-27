//go:build windows

package winargbeneficiarios

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
