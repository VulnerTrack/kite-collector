package sqlite

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// suspectPathFragments are case-insensitive substrings that strongly
// indicate the DB path lives under a cloud-sync, file-sync, or virtual
// drive folder. SQLite ancillary files (WAL, SHM, journals) are deleted
// and recreated on every commit; sync agents racing those operations
// produce SQLITE_IOERR_DELETE_NOENT (extended code 5898) and similar
// transient I/O errors.
var suspectPathFragments = []string{
	"/dropbox/",
	"/onedrive/",
	"/icloud drive/",
	"/icloud/",
	"/icloud~",
	"/icloud-",
	"/icloud_",
	"/icloud-drive/",
	"/icloud drive",
	"/icloud_drive/",
	"/library/mobile documents/",
	"/sync/",
	"/syncthing/",
	"/syncfolder/",
	"/box sync/",
	"/box/",
	"/pcloud/",
	"/pcloud drive/",
	"/pcloud-drive/",
	"/pclouddrive/",
	"/mega/",
	"/megasync/",
	"/google drive/",
	"/googledrive/",
	"/yandex.disk/",
	"/yandexdisk/",
	"/nextcloud/",
	"/owncloud/",
	"/seafile/",
	"/icloud drive (archive)/",
}

// suspectFSTypes are filesystem types reported in /proc/self/mountinfo
// that should not host the SQLite database. NFS/CIFS/SMB don't honour
// POSIX file locking the way SQLite expects; FUSE drivers vary.
var suspectFSTypes = map[string]string{
	"nfs":   "NFS network share",
	"nfs4":  "NFS network share",
	"cifs":  "CIFS/SMB network share",
	"smbfs": "SMB network share",
	"smb":   "SMB network share",
	"smb2":  "SMB network share",
	"smb3":  "SMB network share",
	"fuse":  "FUSE-mounted filesystem (often a sync/cloud driver)",
}

// WarnIfPathIsSuspect emits a slog.Warn when dbPath looks like it lives
// on a cloud-sync folder, network share, or other filesystem known to
// break SQLite's exclusive-access assumptions. It never refuses to start
// — operators may have specific reasons for unusual layouts.
func WarnIfPathIsSuspect(logger *slog.Logger, dbPath string) {
	if logger == nil {
		logger = slog.Default()
	}
	if dbPath == "" {
		return
	}

	abs, err := filepath.Abs(dbPath)
	if err != nil {
		abs = dbPath
	}
	// Resolve symlinks if the file (or its parent) exists, so we catch
	// folders symlinked into a sync directory.
	resolved := abs
	if r, rErr := filepath.EvalSymlinks(filepath.Dir(abs)); rErr == nil {
		resolved = filepath.Join(r, filepath.Base(abs))
	}

	lower := strings.ToLower(resolved)
	// Normalise separators so the heuristics work on Windows too.
	lower = strings.ReplaceAll(lower, "\\", "/")

	for _, frag := range suspectPathFragments {
		if strings.Contains(lower, frag) {
			logger.Warn("kite-collector: db_path is on a sync/network volume — SQLite needs exclusive local FS access",
				"db_path", dbPath,
				"resolved_path", resolved,
				"matched", strings.TrimSuffix(strings.TrimPrefix(frag, "/"), "/"),
				"hint", "move the DB to a local drive (e.g., ~/.local/share/kite-collector or /var/lib/kite-collector)")
			return
		}
	}

	// UNC / SMB share on Windows ("\\server\share\...").
	if runtime.GOOS == "windows" && (strings.HasPrefix(dbPath, `\\`) || strings.HasPrefix(dbPath, `//`)) {
		logger.Warn("kite-collector: db_path is on a UNC/SMB share — SQLite needs exclusive local FS access",
			"db_path", dbPath,
			"hint", "move the DB to a local drive (e.g., %LOCALAPPDATA%\\kite-collector)")
		return
	}

	// Filesystem-type check is Linux-only — /proc/self/mountinfo is the
	// authoritative source. macOS and Windows expose the equivalent via
	// statfs(2)/GetVolumeInformation, which would require platform-
	// specific syscalls; the path-fragment heuristic above already
	// covers the common cloud-sync cases on those OSes.
	if runtime.GOOS != "linux" {
		return
	}
	if fsType, mountPoint, ok := lookupMountFSType(resolved); ok {
		if hint, bad := suspectFSTypes[strings.ToLower(fsType)]; bad {
			logger.Warn("kite-collector: db_path is on a non-local filesystem — SQLite needs exclusive local FS access",
				"db_path", dbPath,
				"resolved_path", resolved,
				"mount_point", mountPoint,
				"fs_type", fsType,
				"reason", hint,
				"hint", "move the DB to a local ext4/xfs/btrfs drive (e.g., /var/lib/kite-collector)")
		}
	}
}

// lookupMountFSType returns the filesystem type and mount point that
// contains absPath, by scanning /proc/self/mountinfo and selecting the
// longest mount-point prefix match. ok is false if the file cannot be
// read or no match is found.
func lookupMountFSType(absPath string) (fsType, mountPoint string, ok bool) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", "", false
	}
	defer func() { _ = f.Close() }()

	var bestMount, bestFS string
	scanner := bufio.NewScanner(f)
	// Some kernels emit very long mountinfo lines; bump the buffer.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		// mountinfo format:
		//   ID PARENT MAJ:MIN ROOT MOUNT_POINT OPTS - FS_TYPE SOURCE SUPER_OPTS
		// We need MOUNT_POINT (field 5) and FS_TYPE (field after the lone "-").
		fields := strings.Fields(scanner.Text())
		if len(fields) < 9 {
			continue
		}
		mp := fields[4]
		// Locate the "-" separator.
		sep := -1
		for i := 5; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+1 >= len(fields) {
			continue
		}
		fs := fields[sep+1]

		if !strings.HasPrefix(absPath, mp) {
			continue
		}
		// Require either exact match or a path-separator boundary so
		// "/data" doesn't match "/data2".
		if mp != "/" && len(absPath) > len(mp) && absPath[len(mp)] != '/' {
			continue
		}
		if len(mp) > len(bestMount) {
			bestMount = mp
			bestFS = fs
		}
	}
	if bestMount == "" {
		return "", "", false
	}
	return bestFS, bestMount, true
}
