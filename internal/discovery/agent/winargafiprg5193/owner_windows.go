//go:build windows

package winargafiprg5193

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
