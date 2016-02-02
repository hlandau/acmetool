package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Make sure the determineKeyIDFromKey and determineKeyIDFromPublicKey
// functions produce the same result.
func TestKeyID(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	keyID, err := determineKeyIDFromKey(pk)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	keyID2, err := DetermineKeyIDFromPublicKey(&pk.PublicKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if keyID != keyID2 {
		t.Fatalf("key ID mismatch: %#v != %#v", keyID, keyID2)
	}
}
