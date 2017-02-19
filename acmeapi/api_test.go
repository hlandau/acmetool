package acmeapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/hlandau/goutils/test"
	"github.com/hlandau/xlog"
	"gopkg.in/square/go-jose.v1"
	"golang.org/x/net/context"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestAPI(t *testing.T) {
	Log.SetSeverity(xlog.SevDebug)

	mt := test.HTTPMockTransport{}

	cl := &Client{
		HTTPClient: &http.Client{
			Transport: &mt,
		},
	}

	issuedNonces := map[string]struct{}{}
	issueNonce := func() string {
		var b [8]byte
		_, err := rand.Read(b[:])
		if err != nil {
			panic(err)
		}

		s := fmt.Sprintf("nonce-%s", hex.EncodeToString(b[:]))
		issuedNonces[s] = struct{}{}
		return s
	}

	checkNonce := func(rw http.ResponseWriter, req *http.Request) bool {
		b, err := ioutil.ReadAll(req.Body)
		if err != nil {
			log.Fatalf("cannot read body: %v", err)
		}

		jws, err := jose.ParseSigned(string(b))
		if err != nil {
			log.Fatalf("malformed request body: %v", err)
		}

		if len(jws.Signatures) != 1 {
			log.Fatalf("wrong number of signatures: %v", err)
		}

		n := jws.Signatures[0].Header.Nonce

		_, ok := issuedNonces[n]
		if !ok {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(400)
			rw.Write([]byte(`{"type":"bad-nonce","message":"Bad nonce."}`))
			t.Logf("invalid nonce: %#v", n)
			t.Fail()
			return false
		}
		delete(issuedNonces, n)
		return true
	}

	// Load Certificate

	mt.Add("boulder.test/acme/cert/some-certificate", &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/pkix-cert"},
			"Link":         []string{"</acme/issuer-cert>; rel=\"up\""},
		},
	}, []byte("cert-data"))

	mt.Add("boulder.test/acme/issuer-cert", &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/pkix-cert"},
			"Link":         []string{"</acme/root-cert>; rel=\"up\""},
		},
	}, []byte("issuer-cert-data"))

	mt.Add("boulder.test/acme/root-cert", &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/pkix-cert"},
			//"Replay-Nonce": []string{"some-nonce-root"},
		},
	}, []byte("root-cert-data"))

	crt := &Certificate{
		URI: "https://boulder.test/acme/cert/some-certificate",
	}

	correctCrt := *crt
	err := cl.WaitForCertificate(crt, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	someCrt := *crt
	correctCrt.Certificate = []byte("cert-data")
	correctCrt.ExtraCertificates = [][]byte{
		[]byte("issuer-cert-data"),
		[]byte("root-cert-data"),
	}

	crt.retryAt = time.Time{}
	if !reflect.DeepEqual(&correctCrt, crt) {
		t.Fatalf("%v != %v", &correctCrt, crt)
	}

	// Load Authorization

	mt.Add("boulder.test/acme/authz/some-authz", &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}, []byte(`{"challenges":[
    {
      "type": "http-01",
      "uri": "https://boulder.test/acme/challenge/some-challenge"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "example.com"
  },
  "status": "pending",
  "expires": "2015-01-01T18:26:57Z"
  }`))

	az := &Authorization{
		URI: "https://boulder.test/acme/authz/some-authz",
	}

	correctAZ := *az
	correctAZ.Combinations = [][]int{[]int{0}}
	correctAZ.Identifier.Type = "dns"
	correctAZ.Identifier.Value = "example.com"
	correctAZ.Status = "pending"
	correctAZ.Expires = time.Date(2015, 1, 1, 18, 26, 57, 0, time.UTC)
	correctAZ.Challenges = []*Challenge{
		{
			Type: "http-01",
			URI:  "https://boulder.test/acme/challenge/some-challenge",
		},
	}

	err = cl.WaitLoadAuthorization(az, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	az.retryAt = time.Time{}
	if !reflect.DeepEqual(&correctAZ, az) {
		t.Fatal("%v != %v", &correctAZ, az)
	}

	// Load Challenge

	mt.Add("boulder.test/acme/challenge/some-challenge", &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}, []byte(`{
    "type": "http-01"
  }`))

	ch := &Challenge{
		URI: "https://boulder.test/acme/challenge/some-challenge",
	}
	err = cl.WaitLoadChallenge(ch, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Request Certificate

	mt.AddHandlerFunc("boulder.test/directory", func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Replay-Nonce", issueNonce())
		rw.WriteHeader(200)
		rw.Write([]byte(`{
      "new-reg": "https://boulder.test/acme/new-reg",
      "new-cert": "https://boulder.test/acme/new-cert",
      "new-authz": "https://boulder.test/acme/new-authz",
      "revoke-cert": "https://boulder.test/acme/revoke-cert"
    }`))
	})

	mt.AddHandlerFunc("boulder.test/acme/new-cert", func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Location", "https://boulder.test/acme/cert/some-certificate")
		rw.WriteHeader(201)
	})

	epk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cl.AccountKey = epk

	cl.DirectoryURL = "https://boulder.test/directory"
	crt, err = cl.RequestCertificate([]byte("csr"), context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = cl.LoadCertificate(crt, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	crt.CSR = nil
	crt.Resource = ""
	crt.retryAt = someCrt.retryAt
	if !reflect.DeepEqual(&someCrt, crt) {
		t.Fatalf("mismatch %#v\n\n%#v", &someCrt, crt)
	}

	t.Logf("%v", crt)

	// Upsert Registration

	mt.AddHandlerFunc("boulder.test/acme/new-reg", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			t.Fatal()
		}
		if !checkNonce(rw, req) {
			return
		}

		rw.Header().Set("Location", "https://boulder.test/acme/reg/1")
		rw.Header().Set("Replay-Nonce", issueNonce())
		rw.WriteHeader(409)
	})

	mt.AddHandlerFunc("boulder.test/acme/reg/1", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			t.Fatal()
		}
		if !checkNonce(rw, req) {
			return
		}

		rw.Header().Set("Replay-Nonce", issueNonce())
		rw.Header().Set("Content-Type", "application/json")
		rw.Header().Set("Link", "<urn:some:boulder:terms/of/service>; rel=\"terms-of-service\"")
		rw.WriteHeader(200)
		rw.Write([]byte(`{}`))
	})

	reg := &Registration{}
	err = cl.AgreeRegistration(reg, nil, context.TODO())
	ae, ok := err.(*AgreementError)
	if !ok || ae.URI != "urn:some:boulder:terms/of/service" {
		t.Fatalf("expected agreement error")
	}

	agreementURIs := map[string]struct{}{
		"urn:some:boulder:terms/of/service": struct{}{},
	}
	err = cl.AgreeRegistration(reg, agreementURIs, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	// New Authorization
	e503Count := 0
	total503 := 3

	mt.AddHandlerFunc("boulder.test/acme/new-authz", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			t.Fatal()
		}
		if !checkNonce(rw, req) {
			return
		}

		rw.Header().Set("Content-Type", "application/json")

		if e503Count < total503 {
			rw.WriteHeader(503)
			rw.Write([]byte(`{"type":"urn:acme:error:serverInternal","detail":"Down"}`))
			e503Count++
			return
		}

		rw.Header().Set("Location", "https://boulder.test/acme/authz/1")
		rw.Header().Set("Replay-Nonce", issueNonce())
		rw.WriteHeader(201)
		rw.Write([]byte(`{
  "challenges": [
    {
      "type": "http-01",
      "uri": "https://boulder.test/acme/challenge/some-challenge2"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "example.com"
  },
  "status": "pending",
  "expires": "2015-01-01T18:26:57Z"
}`))

	})

	mt.AddHandlerFunc("boulder.test/acme/challenge/some-challenge2", func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Replay-Nonce", issueNonce())
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(200)
		rw.Write([]byte(`{}`))
	})

	for i := 0; i < total503; i++ {
		az, err = cl.NewAuthorization("example.com", context.TODO())
		if err == nil {
			t.Fatalf("no error when expected")
		}
	}

	az, err = cl.NewAuthorization("example.com", context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = cl.RespondToChallenge(az.Challenges[0], json.RawMessage(`{}`), nil, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}

	mt.AddHandlerFunc("boulder.test/acme/revoke-cert", func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			t.Fatal()
		}
		if !checkNonce(rw, req) {
			return
		}

		rw.Header().Set("Replay-Nonce", issueNonce())
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(200)
		rw.Write([]byte(`{}`))
	})

	err = cl.Revoke([]byte("revoke-der"), nil, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}
}
