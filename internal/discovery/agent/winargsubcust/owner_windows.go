//go:build windows

package winargsubcust

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
