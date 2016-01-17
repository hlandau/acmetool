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
	cl.AccountInfo.AccountKey = pk
	cl.AccountInfo.AgreementURIs = map[string]struct{}{
		"http://127.0.0.1:4001/terms/v1": {},
	}
	cl.AccountInfo.ContactURIs = []string{
		"mailto:nobody@localhost",
	}

	err := cl.AgreeRegistration(context.TODO())
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

func TestAPI(t *testing.T) {
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

// © 2015—2016 Hugo Landau <hlandau@devever.net>    MIT License
