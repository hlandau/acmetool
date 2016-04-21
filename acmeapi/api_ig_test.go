// +build integration

package acmeapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"golang.org/x/net/context"
	"testing"
)

func testAPIWithKey(t *testing.T, pk crypto.PrivateKey) {
	cl := Client{
		DirectoryURL: "http://127.0.0.1:4000/directory",
	}
	cl.AccountKey = pk
	agreementURIs := map[string]struct{}{
		"http://boulder:4000/terms/v1": {},
	}
	reg := &Registration{
		ContactURIs: []string{
			"mailto:nobody@localhost",
		},
	}

	err := cl.AgreeRegistration(reg, agreementURIs, context.TODO())
	if err != nil {
		t.Fatalf("couldn't upsert registration: %v", err)
	}

	auth, err := cl.NewAuthorization("dom1.acmetool-test.devever.net", context.TODO())
	if err != nil {
		t.Fatalf("couldn't create authorization: %v", err)
	}

	err = cl.WaitLoadAuthorization(auth, context.TODO())
	if err != nil {
		t.Fatalf("couldn't load authorization")
	}

	err = cl.WaitLoadChallenge(auth.Challenges[0], context.TODO())
	if err != nil {
		t.Fatalf("couldn't load challenge")
	}

	// TODO
	//cl.RespondToChallenge
	//cl.RequestCertificate
}

func TestAPIIntegration(t *testing.T) {
	TestingAllowHTTP = true

	rsaPK, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("couldn't generate RSA key: %v", err)
	}

	testAPIWithKey(t, rsaPK)

	ecdsaPK, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("couldn't generate ECDSA key: %v", err)
	}

	testAPIWithKey(t, ecdsaPK)
}
