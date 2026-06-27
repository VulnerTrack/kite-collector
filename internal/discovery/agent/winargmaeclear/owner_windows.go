//go:build windows

package winargmaeclear

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
