package hooks

import (
	"bytes"
	"os"
	"path/filepath"
)

// Installs a hook in the hooks directory. If the file already exists, it is
// not overwritten unless it contains the string "#!acmetool-managed!#" in its
// first 4096 bytes.
func Replace(hookDirectory, name, data string) error {
	if hookDirectory == "" {
		hookDirectory = DefaultPath
	}

	filename := filepath.Join(hookDirectory, name)

	isManaged, err := isManagedFile(filename)
	if os.IsNotExist(err) || (err == nil && isManaged) {
		return writeHook(filename, data)
	}

	return err
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
