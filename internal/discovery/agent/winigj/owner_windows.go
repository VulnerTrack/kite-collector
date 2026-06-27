//go:build windows

package winigj

import "os"

func ownerUID(_ os.FileInfo) int { return 0 }
