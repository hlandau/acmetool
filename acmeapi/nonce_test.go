package acmeapi

import (
	"golang.org/x/net/context"
	"testing"
)

func TestNonce(t *testing.T) {
	ns := nonceSource{}
	ns.AddNonce("my-nonce")
	nsc := ns.WithContext(context.TODO())
	n, err := nsc.Nonce()
	if err != nil {
		t.Fatal()
	}
	if n != "my-nonce" {
		t.Fatal()
	}

	n, err = nsc.Nonce()
	if err == nil {
		t.Fatal()
	}

	ns.GetNonceFunc = func(ctx context.Context) error {
		ns.AddNonce("nonce2")
		return nil
	}

	n, err = nsc.Nonce()
	if err != nil {
		t.Fatal()
	}
	if n != "nonce2" {
		t.Fatal()
	}
}
