//go:build windows

package winafippadron

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
