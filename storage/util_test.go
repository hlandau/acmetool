package storage

import "testing"
import "crypto/rsa"
import "crypto/rand"

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

	keyID2, err := determineKeyIDFromPublicKey(&pk.PublicKey)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	if keyID != keyID2 {
		t.Fatalf("key ID mismatch: %#v != %#v", keyID, keyID2)
	}
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
