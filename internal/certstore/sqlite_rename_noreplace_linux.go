//go:build linux && !js

package certstore

import "golang.org/x/sys/unix"

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
}
