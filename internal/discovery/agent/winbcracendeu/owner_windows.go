//go:build windows

package winbcracendeu

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
