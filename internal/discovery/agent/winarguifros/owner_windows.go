//go:build windows

package winarguifros

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
