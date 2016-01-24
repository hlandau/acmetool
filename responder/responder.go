// Package responder implements the various ACME challenge types.
package responder

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hlandau/acme/interaction"
	"github.com/hlandau/xlog"
	"github.com/square/go-jose"
)

// Log site.
var log, Log = xlog.New("acme.responder")

// A Responder implements a challenge type.
//
// After successfully instantiating a responder, you should call Start.
//
// You should then use the return values of Validation() and
// ValidationSigningKey() to submit the challenge response.
//
// Once the challenge has been completed, as determined by polling, you must
// call Stop. If RequestDetectedChan() is non-nil, it provides a hint as to
// when polling may be fruitful.
type Responder interface {
	// Become ready to be interrogated by the ACME server.
	Start(interactor interaction.Interactor) error

	// Stop responding to any queries by the ACME server.
	Stop() error

	// This channel is sent to when a request to the responder is detected,
	// which may indicates completion of the challenge is imminent.
	//
	// Returning nil indicates that request detection is not supported.
	RequestDetectedChan() <-chan struct{}

	// Return the validation object the signature for which was delivered. If
	// nil is returned, no validation object is submitted.
	Validation() json.RawMessage

	// Key which must sign validation object. If nil, account key is used.
	ValidationSigningKey() crypto.PrivateKey
}

// Used to instantiate a responder.
type Config struct {
	// Information about the challenge to be completed.

	Type       string            // The responder type to be used. e.g. "http-01".
	AccountKey crypto.PrivateKey // The account private key.
	Token      string            // The challenge token.

	N int // "tls-sni-01": Number of iterations.

	// "http-01", "proofOfPossession": The hostname being verified. May be used
	// for pre-initiation self-testing. Optional. Required for
	// proofOfPossession.
	Hostname string

	// "proofOfPossession": The certificates which are acceptable. Each entry is
	// a DER X.509 certificate.
	AcceptableCertificates [][]byte

	ChallengeConfig ChallengeConfig
}

// Information used to complete challenges, other than information provided by
// the ACME server.
type ChallengeConfig struct {
	// "http-01": The http responder may attempt to place challenges in these
	// locations. Optional.
	WebPaths []string

	// "http-01": The http responder may attempt to listen on these addresses.
	// Optional.
	HTTPPorts []string

	// "proofOfPossession": Function which returns the private key for a given
	// public key.  This may be called multiple times for a given challenge as
	// multiple public keys may be permitted. If a private key for the given
	// public key cannot be found, return nil and do not return an error.
	// Returning an error short circuits.
	//
	// If not specified, proofOfPossession challenges always fail.
	PriorKeyFunc PriorKeyFunc

	StartHookFunc HookFunc
	StopHookFunc  HookFunc
}

// Returns the private key corresponding to the given public key, if it can be
// found. If a corresponding private key cannot be found, return nil; do not
// return an error. Returning an error short circuits.
type PriorKeyFunc func(crypto.PublicKey) (crypto.PrivateKey, error)

type HookFunc func(challengeInfo interface{}) error

var responderTypes = map[string]func(Config) (Responder, error){}

// Try and instantiate a responder using the given configuration.
func New(rcfg Config) (Responder, error) {
	f, ok := responderTypes[rcfg.Type]
	if !ok {
		return nil, fmt.Errorf("challenge type not supported")
	}

	return f(rcfg)
}

// Register a responder type. Allows types other than those innately supported
// by this package to be supported. Overrides any previously registered
// responder of the same type.
func RegisterResponder(typeName string, createFunc func(Config) (Responder, error)) {
	responderTypes[typeName] = createFunc
}

func b64enc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashBytes(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func hashBytesHex(b []byte) string {
	return hex.EncodeToString(hashBytes(b))
}

func (rcfg *Config) keyAuthorization() (string, error) {
	k := jose.JsonWebKey{Key: rcfg.AccountKey}
	thumbprint, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return rcfg.Token + "." + b64enc(thumbprint), nil
}

func (rcfg *Config) responseJSON(challengeType string) ([]byte, error) {
	ka, err := rcfg.keyAuthorization()
	if err != nil {
		return nil, err
	}

	info := map[string]interface{}{
		"resource":         "challenge",
		"type":             challengeType,
		"keyAuthorization": ka,
	}

	bb, err := json.Marshal(&info)
	if err != nil {
		return nil, err
	}

	return bb, nil
}

// © 2015—2016 Hugo Landau <hlandau@devever.net>    MIT License
