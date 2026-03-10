//go:build darwin && !js

package certstore

import "golang.org/x/sys/unix"

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	return unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
}
