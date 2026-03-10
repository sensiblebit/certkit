//go:build darwin && !js

package certstore

import "golang.org/x/sys/unix"

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	err := unix.RenamexNp(oldPath, newPath, unix.RENAME_EXCL)
	if err == nil {
		return nil
	}
	if err == unix.ENOSYS || err == unix.EINVAL || err == unix.EOPNOTSUPP || err == unix.ENOTSUP {
		return errSQLiteNoReplaceRenameUnsupported
	}
	return err
}
