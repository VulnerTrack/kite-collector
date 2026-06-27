//go:build windows

package winargpyhomebroker

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
