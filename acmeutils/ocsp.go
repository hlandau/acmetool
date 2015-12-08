package acmeutils

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
)

// Checks OCSP for a certificate. The immediate issuer must be specified. If
// the HTTP client is nil, the default client is used. If the certificate does
// not support OCSP, (nil, nil) is returned.  Uses HTTP GET rather than POST.
// The response is verified. The caller must check the response status.
func CheckOCSP(httpClient *http.Client, crt, issuer *x509.Certificate) (*ocsp.Response, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	if len(crt.OCSPServer) == 0 {
		return nil, nil
	}

	b, err := ocsp.CreateRequest(crt, issuer, nil)
	if err != nil {
		return nil, err
	}

	b64 := base64.StdEncoding.EncodeToString(b)
	path := crt.OCSPServer[0] + "/" + b64

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/ocsp-response")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("OCSP response has status %#v", res.Status)
	}

	if res.Header.Get("Content-Type") != "application/ocsp-response" {
		return nil, fmt.Errorf("response to OCSP request had unexpected content type")
	}

	resb, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return ocsp.ParseResponse(resb, issuer)
}
