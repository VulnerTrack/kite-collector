//go:build windows

package winargtesoro

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
