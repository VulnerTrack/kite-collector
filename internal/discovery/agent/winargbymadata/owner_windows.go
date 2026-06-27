//go:build windows

package winargbymadata

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
