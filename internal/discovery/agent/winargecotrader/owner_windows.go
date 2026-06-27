//go:build windows

package winargecotrader

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
