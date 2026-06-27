//go:build windows

package winargamibroker

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
