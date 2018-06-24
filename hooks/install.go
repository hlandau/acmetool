package hooks

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

// Given a set of hook directories, returns whether a hook with the given name exists in any of them.
func Exists(hookDirs []string, hookName string) bool {
	for _, hookDir := range hookDirs {
		_, err := os.Stat(filepath.Join(hookDir, hookName))
		if err == nil {
			return true
		}
	}
	return false
}

// Installs a hook in the hooks directory. If the file already exists, it is
// not overwritten unless it contains the string "#!acmetool-managed!#" in its
// first 4096 bytes.
func Replace(hookDirs []string, name, data string) error {
	if len(hookDirs) == 0 {
		hookDirs = DefaultPaths
	}
	if len(hookDirs) == 0 {
		return fmt.Errorf("no hooks directory configured")
	}

	// Find the directory in the filesystem which has the most parent components
	// of it already created.
	hookDirectory, err := preferredHookDir(hookDirs)
	if err != nil {
		return err
	}

	filename := filepath.Join(hookDirectory, name)

	isManaged, err := isManagedFile(filename)
	if os.IsNotExist(err) || (err == nil && isManaged) {
		return writeHook(filename, data)
	}

	return err
}

func preferredHookDir(hookDirs []string) (hookDirectory string, err error) {
	bestLA := 255
	for _, dir := range hookDirs {
		var la int
		la, err = levelsAbsent(dir)
		if err != nil {
			return
		}

		if la < bestLA {
			hookDirectory = dir
			bestLA = la
		}
	}
	if hookDirectory == "" {
		hookDirectory = hookDirs[0]
	}

	return
}

func levelsAbsent(dir string) (int, error) {
	for i := 0; dir != "." && dir != "/"; i++ {
		_, err := os.Stat(dir)
		if err == nil {
			return i, nil
		}

		dir = filepath.Join(dir, "..")
	}

	return 255, fmt.Errorf("cannot find a level which exists")
}

func writeHook(filename, data string) error {
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return nil
	}

	defer f.Close()
	f.Write([]byte(data))

	return nil
}

func isManagedFile(filename string) (bool, error) {
	f, err := os.Open(filename)
	if err != nil {
		return false, err
	}

	defer f.Close()
	b := make([]byte, 4096)
	n, _ := f.Read(b)
	b = b[0:n]
	return bytes.Index(b, []byte("#!acmetool-managed!#")) >= 0, nil
}
