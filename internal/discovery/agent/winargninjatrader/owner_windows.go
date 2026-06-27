//go:build windows

package winargninjatrader

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
