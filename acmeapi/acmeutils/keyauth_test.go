package acmeutils

import "testing"

func TestKeyAuthorization(t *testing.T) {
	pk, err := LoadPrivateKey([]byte(testKey))
	if err != nil {
		t.Fatal()
	}

	ka, err := KeyAuthorization(pk, "foo")
	if err != nil {
		t.Fatal()
	}

	if ka != "foo.UOn6kBbQDrwoTc2BcjGS1_JeF5rDIVYrZmBhs5bgXWo" {
		t.Fatal()
	}

	pk, err = LoadPrivateKey([]byte(testECKey))
	if err != nil {
		t.Fatal()
	}

	ka, err = KeyAuthorization(pk, "foo")
	if err != nil {
		t.Fatal()
	}

	if ka != "foo.S8MUz-12EEFgpVWWfDpvolnpTkuD9yVV6qHdzFuJyj8" {
		t.Fatalf("%v", ka)
	}
}
