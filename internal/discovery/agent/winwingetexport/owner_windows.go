//go:build windows

package winwingetexport

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
