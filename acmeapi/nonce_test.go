package acmeapi

import "testing"

func TestNonce(t *testing.T) {
	ns := nonceSource{}
	ns.AddNonce("my-nonce")
	n, err := ns.Nonce()
	if err != nil {
		t.Fatal()
	}
	if n != "my-nonce" {
		t.Fatal()
	}

	n, err = ns.Nonce()
	if err == nil {
		t.Fatal()
	}

	ns.GetNonceFunc = func() (string, error) {
		return "nonce2", nil
	}

	n, err = ns.Nonce()
	if err != nil {
		t.Fatal()
	}
	if n != "nonce2" {
		t.Fatal()
	}
}
