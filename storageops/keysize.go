package storageops

import "crypto/elliptic"

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
