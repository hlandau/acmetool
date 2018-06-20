package storage

import (
	"crypto/elliptic"
	"github.com/hlandau/acmetool/fdb"
	"strings"
)

// Legacy Configuration

func (s *fdbStore) loadWebrootPaths() {
	if len(s.defaultTarget.Request.Challenge.WebrootPaths) != 0 {
		// Path list in default target file takes precedence.
		return
	}

	webrootPath, _ := fdb.String(s.db.Collection("conf").Open("webroot-path")) // ignore errors
	webrootPath = strings.TrimSpace(webrootPath)
	webrootPaths := strings.Split(webrootPath, "\n")
	for i := range webrootPaths {
		webrootPaths[i] = strings.TrimSpace(webrootPaths[i])
	}

	if len(webrootPaths) == 1 && webrootPaths[0] == "" {
		webrootPaths = nil
	}

	s.defaultTarget.Request.Challenge.WebrootPaths = webrootPaths
}

func (s *fdbStore) loadRSAKeySize() {
	if s.defaultTarget.Request.Key.RSASize != 0 {
		// setting in default target file takes precedence
		return
	}

	n, err := fdb.Uint(s.db.Collection("conf"), "rsa-key-size", 31)
	if err != nil {
		return
	}

	s.defaultTarget.Request.Key.RSASize = int(n)

	if nn := clampRSAKeySize(int(n)); nn != int(n) {
		log.Warnf("An RSA key size of %d is not supported; must have %d <= size <= %d; clamping at %d", n, minRSASize, maxRSASize, nn)
	}
}

// Key Parameters

const (
	minRSASize     = 2048
	defaultRSASize = 2048
	maxRSASize     = 4096
)

func clampRSAKeySize(sz int) int {
	if sz == 0 {
		return defaultRSASize
	}
	if sz < minRSASize {
		return minRSASize
	}
	if sz > maxRSASize {
		return maxRSASize
	}
	return sz
}

const defaultCurve = "nistp256"

// Make sure the curve name is valid and use a default curve name. "clamp" is
// not the sanest name here but is consistent with clampRSAKeySize.
func clampECDSACurve(curveName string) string {
	switch curveName {
	case "nistp256", "nistp384", "nistp521":
		return curveName
	default:
		return defaultCurve
	}
}

func getECDSACurve(curveName string) elliptic.Curve {
	switch clampECDSACurve(curveName) {
	case "nistp256":
		return elliptic.P256()
	case "nistp384":
		return elliptic.P384()
	case "nistp521":
		return elliptic.P521()
	default:
		return nil
	}
}
