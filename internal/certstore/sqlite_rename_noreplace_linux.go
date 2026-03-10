//go:build linux && !js

package certstore

import "golang.org/x/sys/unix"

func renameSQLiteFileNoReplace(oldPath, newPath string) error {
	err := unix.Renameat2(unix.AT_FDCWD, oldPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}
	if err == unix.ENOSYS || err == unix.EINVAL || err == unix.EOPNOTSUPP || err == unix.ENOTSUP {
		return errSQLiteNoReplaceRenameUnsupported
	}
	return err
}
