package storage

import (
	"fmt"
	"github.com/hlandau/acme/fdb"
	"strings"
)

func (s *Store) loadWebrootPaths() {
	webrootPath, _ := fdb.String(s.db.Collection("conf").Open("webroot-path")) // ignore errors
	webrootPath = strings.TrimSpace(webrootPath)
	webrootPaths := strings.Split(webrootPath, "\n")
	for i := range webrootPaths {
		webrootPaths[i] = strings.TrimSpace(webrootPaths[i])
	}

	if len(webrootPaths) == 1 && webrootPaths[0] == "" {
		webrootPaths = nil
	}

	s.webrootPaths = webrootPaths
}

func (s *Store) loadRSAKeySize() {
	s.preferredRSAKeySize = 2048
	n, err := fdb.Uint(s.db.Collection("conf"), "rsa-key-size", 31)
	if err != nil {
		return
	}

	s.preferredRSAKeySize = int(n)

	if nn := clampRSAKeySize(int(n)); nn != int(n) {
		log.Warnf("An RSA key size of %d is not supported; must have 2048 <= size <= 4096; clamping at %d", n, nn)
	}
}

func clampRSAKeySize(sz int) int {
	if sz < 2048 {
		return 2048
	}
	if sz > 4096 {
		return 4096
	}
	return sz
}

// Get the preferred webroot paths.
func (s *Store) WebrootPaths() []string {
	return s.webrootPaths
}

// Set the preferred webroot paths.
func (s *Store) SetWebrootPaths(paths []string) error {
	confc := s.db.Collection("conf")

	err := fdb.WriteBytes(confc, "webroot-path", []byte(strings.Join(paths, "\n")))
	if err != nil {
		return err
	}

	s.webrootPaths = paths
	return nil
}

// Gets the preferred RSA key size, in bits.
func (s *Store) PreferredRSAKeySize() int {
	return s.preferredRSAKeySize
}

// Set the preferred RSA key size. The size is not validated here, as it is
// clamped later and a higher preferred size may become available in future
// releases.
func (s *Store) SetPreferredRSAKeySize(keySize int) error {
	err := fdb.WriteBytes(s.db.Collection("conf"), "rsa-key-size", []byte(fmt.Sprintf("%d", keySize)))
	if err != nil {
		return err
	}

	s.preferredRSAKeySize = keySize
	return nil
}
