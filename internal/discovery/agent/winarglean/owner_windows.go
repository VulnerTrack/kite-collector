//go:build windows

package winarglean

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
