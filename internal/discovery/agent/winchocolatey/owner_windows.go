//go:build windows

package winchocolatey

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
