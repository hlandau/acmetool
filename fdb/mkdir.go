package fdb

import (
	"os"
	"syscall"
)

// Like os.MkdirAll but new components created have the given UID and GID.
func mkdirAllWithOwner(absPath string, perm os.FileMode, uid, gid int) error {
	// From os/path.go.
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := os.Stat(absPath)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: absPath, Err: syscall.ENOTDIR}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(absPath)
	for i > 0 && os.IsPathSeparator(absPath[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(absPath[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent
		err = mkdirAllWithOwner(absPath[0:j-1], perm, uid, gid)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = os.Mkdir(absPath, perm)
	if err != nil {
		// Handle arguments like "foo/." by double-checking that directory
		// doesn't exist.
		dir, err1 := os.Lstat(absPath)
		if err1 == nil && dir.IsDir() {
			return nil
		}

		return err
	}

	if uid >= 0 || gid >= 0 {
		if uid < 0 {
			uid = os.Getuid()
		}
		if gid < 0 {
			gid = os.Getgid()
		}
		err = os.Lchown(absPath, uid, gid) // ignore errors in case we aren't root
		log.Errore(err, "cannot chown ", absPath)
	}

	return nil
}
