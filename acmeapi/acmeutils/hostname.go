package acmeutils

import (
	"fmt"
	"golang.org/x/net/idna"
	"regexp"
	"strings"
)

var reHostname = regexp.MustCompilePOSIX(`^([a-z0-9_-]+\.)*[a-z0-9_-]+$`)

// Normalizes the hostname given. If the hostname is not valid, returns "" and
// an error.
func NormalizeHostname(name string) (string, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	name, err := idna.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("IDN error: %#v: %v", name, err)
	}

	if !reHostname.MatchString(name) {
		return "", fmt.Errorf("invalid hostname: %#v", name)
	}

	return name, nil
}

// Returns true iff the given string is a valid hostname.
func ValidateHostname(name string) bool {
	_, err := NormalizeHostname(name)
	return err == nil
}
