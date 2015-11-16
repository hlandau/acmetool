// Package responder implements the various ACME challenge types.
package responder

import "strings"
import "crypto"
import "fmt"
import "encoding/json"
import "github.com/square/go-jose"
import "encoding/base64"
import "encoding/hex"
import "crypto/sha256"
import "github.com/hlandau/acme/interaction"
import "github.com/hlandau/xlog"

var log, Log = xlog.New("acme.responder")

// A Responder implements a challenge type.
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
}

// Used to instantiate a responder.
type Config struct {
	// The responder type to be used. "simpleHttp".
	Type string

	// The account private key.
	AccountKey crypto.PrivateKey

	// The challenge token.
	Token string

	// "tls-sni-01": Number of iterations.
	N int

	// The hostname being verified. May be used for pre-initiation self-testing. Optional.
	Hostname string

	// The http responder may attempt to place challenges here and perform
	// self-testing if it is unable to listen on port 80. Optional.
	WebPath string
}

var responderTypes = map[string]func(Config) (Responder, error){}

func New(rcfg Config) (Responder, error) {
	f, ok := responderTypes[rcfg.Type]
	if !ok {
		return nil, fmt.Errorf("challenge type not supported")
	}

	return f(rcfg)
}

func RegisterResponder(typeName string, createFunc func(Config) (Responder, error)) {
	responderTypes[typeName] = createFunc
}

func b64enc(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
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

	/*	signer, err := jose.NewSigner(jose.RS256, rcfg.AccountKey)
		if err != nil {
			return nil, err
		}*/

	bb, err := json.Marshal(&info)
	if err != nil {
		return nil, err
	}

	/*	ws, err := signer.Sign(bb)
		if err != nil {
			return nil, err
		}*/

	return bb, nil
	//return []byte(ws.FullSerialize()), nil
}
