package acmeutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"gopkg.in/square/go-jose.v1"
	"math/big"
	"time"
)

// Calculates the base64 thumbprint of a public or private key. Returns an
// error if the key is of an unknown type.
func Base64Thumbprint(key interface{}) (string, error) {
	k := jose.JsonWebKey{Key: key}
	thumbprint, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return b64enc(thumbprint), nil
}

// Calculates a key authorization using the given account public or private key
// and the token to prefix.
func KeyAuthorization(accountKey interface{}, token string) (string, error) {
	thumbprint, err := Base64Thumbprint(accountKey)
	if err != nil {
		return "", err
	}

	return token + "." + thumbprint, nil
}

// Calculates a key authorization which is then hashed and base64 encoded as is
// required for the DNS challenge.
func DNSKeyAuthorization(accountKey interface{}, token string) (string, error) {
	ka, err := KeyAuthorization(accountKey, token)
	if err != nil {
		return "", err
	}

	return b64enc(sha256Bytes([]byte(ka))), nil
}

// Determines the hostname which must appear in a TLS-SNI challenge
// certificate.
func TLSSNIHostname(accountKey interface{}, token string) (string, error) {
	ka, err := KeyAuthorization(accountKey, token)
	if err != nil {
		return "", err
	}

	kaHex := sha256BytesHex([]byte(ka))
	return kaHex[0:32] + "." + kaHex[32:64] + ".acme.invalid", nil
}

// Creates a self-signed certificate and matching private key suitable for
// responding to a TLS-SNI challenge. hostname should be a hostname returned by
// TLSSNIHostname.
func CreateTLSSNICertificate(hostname string) (certDER []byte, privateKey crypto.PrivateKey, err error) {
	crt := x509.Certificate{
		Subject: pkix.Name{
			CommonName: hostname,
		},
		Issuer: pkix.Name{
			CommonName: hostname,
		},
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}

	certDER, err = x509.CreateCertificate(rand.Reader, &crt, &crt, &pk.PublicKey, pk)
	privateKey = pk
	return
}

// Returns JSON suitable as a generic challenge initiation response to the ACME
// server. You pass this to RespondToChallenge as a json.RawMessage. Suitable
// for most, but not all, challenge types.
func ChallengeResponseJSON(accountKey interface{}, token, challengeType string) ([]byte, error) {
	ka, err := KeyAuthorization(accountKey, token)
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

func sha256Bytes(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func sha256BytesHex(b []byte) string {
	return hex.EncodeToString(sha256Bytes(b))
}

func b64enc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
