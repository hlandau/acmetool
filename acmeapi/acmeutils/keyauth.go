package acmeutils

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"github.com/square/go-jose"
)

func Base64Thumbprint(key crypto.PrivateKey) (string, error) {
	k := jose.JsonWebKey{Key: key}
	thumbprint, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}

	return b64enc(thumbprint), nil
}

func KeyAuthorization(accountKey crypto.PrivateKey, token string) (string, error) {
	thumbprint, err := Base64Thumbprint(accountKey)
	if err != nil {
		return "", err
	}

	return token + "." + thumbprint, nil
}

func ChallengeResponseJSON(accountKey crypto.PrivateKey, token, challengeType string) ([]byte, error) {
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

func b64enc(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
