//go:build windows

package winbcracomunic

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
