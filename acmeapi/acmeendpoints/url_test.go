package acmeendpoints

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeutils"
	"github.com/hlandau/goutils/test"
	"golang.org/x/net/context"
	"math/big"
	"net/http"
	"testing"
)

const leStagingTestCert = `
-----BEGIN CERTIFICATE-----
MIIE6DCCA9CgAwIBAgITAPo8NeGtZ2xhrKoeMR+onLNgFzANBgkqhkiG9w0BAQsF
ADAfMR0wGwYDVQQDDBRoYXBweSBoYWNrZXIgZmFrZSBDQTAeFw0xNjAxMTcxNjAz
MDBaFw0xNjA0MTYxNjAzMDBaMB4xHDAaBgNVBAMTE2FxMS5saGguZGV2ZXZlci5u
ZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTP6pFjvAzkVohGaGH
hIJ746SGTdw2cjDfqZimiBc1Yrjl1AFlLfHHLZ7Uyt3b7EYlYao6P6Vx9wKigCI+
vaeAudlZNerJa8fWNJXf4eqYoYH7vf+xnZP7TYUmiWLSGES9p8QBRCHwWPycP7mm
X4kneqo/oF/asQnOmUy0hi2VyCCT/XQ93ApN5pHz8dg7A3OtOGlHXd38rJ3uBJ0N
JXM6Dx5Oj833nDaa2ndkBxq5m0SLnOimE5GsqX7bWNfllMeZXqH5/3E25cgh2YTR
6JBDLqpzO9ZvFOOWcOVk0QG+zfXhHVx++6I6fs36p3/+DN58WB/JP4CLV3JvC6cE
NyuvAgMBAAGjggIcMIICGDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNB3WkfIcwYM
bXABE4q5k3/o1vNHMB8GA1UdIwQYMBaAFPt4TxL5YBWDLJ8XfzQZsy426kGJMHgG
CCsGAQUFBwEBBGwwajAzBggrBgEFBQcwAYYnaHR0cDovL29jc3Auc3RhZ2luZy14
MS5sZXRzZW5jcnlwdC5vcmcvMDMGCCsGAQUFBzAChidodHRwOi8vY2VydC5zdGFn
aW5nLXgxLmxldHNlbmNyeXB0Lm9yZy8wHgYDVR0RBBcwFYITYXExLmxoaC5kZXZl
dmVyLm5ldDCB/gYDVR0gBIH2MIHzMAgGBmeBDAECATCB5gYLKwYBBAGC3xMBAQEw
gdYwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIGrBggr
BgEFBQcCAjCBngyBm1RoaXMgQ2VydGlmaWNhdGUgbWF5IG9ubHkgYmUgcmVsaWVk
IHVwb24gYnkgUmVseWluZyBQYXJ0aWVzIGFuZCBvbmx5IGluIGFjY29yZGFuY2Ug
d2l0aCB0aGUgQ2VydGlmaWNhdGUgUG9saWN5IGZvdW5kIGF0IGh0dHBzOi8vbGV0
c2VuY3J5cHQub3JnL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQABcut7
1jVicQnHvSkQgY1CRiGSmlHyOyEKimNtCuyaAVwm3cavV/wpGTDFnePyNds4cst/
8BcL0QaKLmE1an/oeGmfs0U8maiKbL69Yun0qTNTKOaqJP/iitwAbliQ3TzO2kOZ
+a2RkPKx0/zYlZb0GzhfIwHE4Qd7/P0qLphu2UaaEpzBnRlT1F9k+cGe4DZYb4XL
BZHnOmXeZrhfPeeTw4VYAEtZ7fpwRhirBjshU8kRbO7KgZh4Id+v26FQpBE3eMQ2
CWV8q8XThKcX3OaMOkLOIB2xZA7Fpj3JoDcsLPEKn5sxVgkxfjs03glTWd839qcE
YAC6drs6Fev1cVa9
-----END CERTIFICATE-----`

const leLiveTestCert = `
-----BEGIN CERTIFICATE-----
MIIFCzCCA/OgAwIBAgISAaoIVMlVWnr9Vfrj+Ak2new4MA0GCSqGSIb3DQEBCwUA
MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMTAeFw0xNjAxMTEwNDQ0MDBaFw0x
NjA0MTAwNDQ0MDBaMBYxFDASBgNVBAMTC2RldmV2ZXIubmV0MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEArBzKQy0inr2oheVRuCDS2prucTF+8xQW66WP
D5ZNzoypPFB9uvFSJN1QzMeq7fdLGWn3QIFj9HlntYxI7Sy47nFeciHG2lN7zfGL
Lex0vREZ21ST3IfUuD/LogkAMqgjcymBiMdrO5hcPf0OIkboBe96BrBAKXTFVlme
guwkdexNjedlFQ4egtzKZ2YrJXR4z9VOW0qaRNqk+9zvjLGG2mIay+NN0aTHomOk
Ow+y8bFFJ9wrkMtn+/IwP1uIbyMEgF2qmKnB/G6H/Qdq52IBF1rCC5xlpWNB0w/3
aJd512AqC5WFC/yFy8ksFS7EjIhQeyqBx1unyaz13C3yrRimbwIDAQABo4ICHTCC
AhkwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQY0ADTmNDEDmrqY45CJCJdwvHp7DAf
BgNVHSMEGDAWgBSoSmpjBH3duubRObemRWXv86jsoTBwBggrBgEFBQcBAQRkMGIw
LwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmludC14MS5sZXRzZW5jcnlwdC5vcmcv
MC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDEubGV0c2VuY3J5cHQub3Jn
LzAnBgNVHREEIDAeggtkZXZldmVyLm5ldIIPd3d3LmRldmV2ZXIubmV0MIH+BgNV
HSAEgfYwgfMwCAYGZ4EMAQIBMIHmBgsrBgEEAYLfEwEBATCB1jAmBggrBgEFBQcC
ARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwgasGCCsGAQUFBwICMIGeDIGb
VGhpcyBDZXJ0aWZpY2F0ZSBtYXkgb25seSBiZSByZWxpZWQgdXBvbiBieSBSZWx5
aW5nIFBhcnRpZXMgYW5kIG9ubHkgaW4gYWNjb3JkYW5jZSB3aXRoIHRoZSBDZXJ0
aWZpY2F0ZSBQb2xpY3kgZm91bmQgYXQgaHR0cHM6Ly9sZXRzZW5jcnlwdC5vcmcv
cmVwb3NpdG9yeS8wDQYJKoZIhvcNAQELBQADggEBAHcD+3AjdbfZylPHFYyYSIWk
no90p+rWZwh3sDnWC5KzZ8jm7uMynCvr7NK0BBxIzuqlWQ0vjKq41KFkTA+GllS/
a4/1XnzrKIJ8udX698Ofsn6HEqxoT0/sAQhxGChrXDRl33QDowqquHWh8HGXx1ke
jV1U4H69KjWYRNx7EN2kbik4GDznwOGpkAUPFCiW2g40zs8Lw4+RiTGPHNELzm7c
TMAyWtPi4eJpMz87jYxv+jB6a4Zy5gAdEySejtGwerhGrrmntkliR8MKZQ6Lisd8
h6xyLde4iNUiXtPOr9I87FBLC1U2AnP+GldAKYB3PO1qPHy6u/a15Xg34FrD8SM=
-----END CERTIFICATE-----`

type urlTestCase struct {
	Cert     string
	Endpoint *Endpoint
}

var urlTestCases = []*urlTestCase{
	{
		Cert:     leStagingTestCert,
		Endpoint: &LetsEncryptStaging,
	},
	{
		Cert:     leLiveTestCert,
		Endpoint: &LetsEncryptLive,
	},
}

func TestURL(t *testing.T) {
	_, err := ByDirectoryURL("https://unknown/directory")
	if err != ErrNotFound {
		t.Fail()
	}

	for _, tc := range urlTestCases {
		e, err := ByDirectoryURL(tc.Endpoint.DirectoryURL)
		if err != nil {
			t.Fatalf("cannot get by directory URL")
		}

		if e != tc.Endpoint {
			t.Fatalf("got wrong endpoint: %v != %v", e, tc.Endpoint)
		}

		certs, err := acmeutils.LoadCertificates([]byte(tc.Cert))
		if err != nil {
			t.Fatalf("cannot load test certificate")
		}

		c0, err := x509.ParseCertificate(certs[0])
		if err != nil {
			t.Fatalf("cannot parse certificate")
		}

		cl := acmeapi.Client{}
		e, certURL, err := CertificateToEndpointURL(&cl, c0, context.TODO())
		if err != nil {
			t.Fatalf("cannot map certificate to endpoint")
		}

		e2, err := CertificateToEndpoint(&cl, c0, context.TODO())
		if e2 != e {
			t.Fatalf("mismatch")
		}

		if e != tc.Endpoint {
			t.Fatalf("certificate mapped to wrong endpoint: %v != %v", e, tc.Endpoint)
		}

		dURL, err := CertificateURLToDirectoryURL(certURL)
		if err != nil {
			t.Fatalf("cannot map certificate URL to directory URL: %v", err)
		}

		if dURL != e.DirectoryURL {
			t.Fatalf("directory URL mismatch: %v != %v", dURL, e.DirectoryURL)
		}
	}
}

func TestGuess(t *testing.T) {
	crt := &x509.Certificate{
		OCSPServer: []string{
			"https://example.com/",
		},
		SerialNumber: big.NewInt(0xdeadb33f),
	}

	endp, certain, err := CertificateToEndpoints(crt)
	if err != ErrNotFound || endp != nil || certain {
		t.Fail()
	}

	e, err := CreateByDirectoryURL("https://unknown-boulder.test/directory")
	if err != nil {
		t.Fail()
	}

	RegisterEndpoint(e)

	e2, err := CreateByDirectoryURL("https://unknown-boulder.test/directory")
	if e2 != e || err != nil {
		t.Fatal()
	}

	e3, err := CreateByDirectoryURL("https://unknown-boulder3.test/")
	if err != nil {
		t.Fatal()
	}

	RegisterEndpoint(e3)

	e4, err := CreateByDirectoryURL("https://unknown-boulder4.test/directory")
	if err != nil {
		t.Fatal()
	}

	RegisterEndpoint(e4)

	du, err := CertificateURLToDirectoryURL("https://unknown-boulder.test/acme/cert/deadb33f")
	if err != nil {
		t.Fatal()
	}
	if du != e.DirectoryURL {
		t.Fatal()
	}

	du, err = CertificateURLToDirectoryURL("https://other-boulder.test/acme/cert/deadb33f")
	if err != ErrNotFound {
		t.Fatal()
	}

	endp, certain, err = CertificateToEndpoints(crt)
	if err != nil || certain || len(endp) != 3 {
		t.Fatal()
	}
	if endp[0] != e || endp[1] != e3 {
		t.Fail()
	}

	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	crtb, err := x509.CreateCertificate(rand.Reader, crt, crt, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	crtb2 := make([]byte, len(crtb))
	copy(crtb2, crtb)
	mt := test.HTTPMockTransport{}
	mt.Add("unknown-boulder4.test/acme/cert/0000000000000000000000000000deadb33f", &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/pkix-cert"},
		},
	}, crtb2)
	crt, _ = x509.ParseCertificate(crtb)
	cl := &acmeapi.Client{
		HTTPClient: &http.Client{
			Transport: &mt,
		},
	}
	_, cURL, err := CertificateToEndpointURL(cl, crt, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cURL != "https://unknown-boulder4.test/acme/cert/0000000000000000000000000000deadb33f" {
		t.Fatalf("curl %v", cURL)
	}
	mt.Clear()
	mt.Add("unknown-boulder.test/acme/cert/0000000000000000000000000000deadb33f", &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/pkix-cert"},
		},
	}, crtb2)
	_, cURL, err = CertificateToEndpointURL(cl, crt, context.TODO())
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cURL != "https://unknown-boulder.test/acme/cert/0000000000000000000000000000deadb33f" {
		t.Fatalf("curl %v", cURL)
	}
	crtb2[5] ^= 1
	_, cURL, err = CertificateToEndpointURL(cl, crt, context.TODO())
	if err == nil {
		t.Fatal()
	}
	mt.Clear()
	_, cURL, err = CertificateToEndpointURL(cl, crt, context.TODO())
	if err == nil {
		t.Fatal()
	}
}
