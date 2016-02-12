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

	ka, err = DNSKeyAuthorization(pk, "foo")
	if err != nil {
		t.Fatal()
	}

	if ka != "efdLQjp7LK3TpMZ4b5UsX-vVaexjtxTNfn1M3Shfqjo" {
		t.Fatalf("#v", ka)
	}

	hostname, err := TLSSNIHostname(pk, "foo")
	if err != nil {
		t.Fatal()
	}

	if hostname != "79f74b423a7b2cadd3a4c6786f952c5f.ebd569ec63b714cd7e7d4cdd285faa3a.acme.invalid" {
		t.Fatalf("%#v", hostname)
	}

	_, _, err = CreateTLSSNICertificate(hostname)
	if err != nil {
		t.Fatal()
	}
}
