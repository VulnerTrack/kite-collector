//go:build windows

package winafipsuss

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
