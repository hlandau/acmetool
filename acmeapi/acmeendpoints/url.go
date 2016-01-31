package acmeendpoints

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/xlog"
	"golang.org/x/net/context"
	"net/url"
	"regexp"
)

var log, Log = xlog.New("acme.endpoints")

// Returned when no matching endpoint can be found.
var ErrNotFound = errors.New("no corresponding endpoint found")

// Finds an endpoint with the given directory URL. If no such endpoint is
// found, returns ErrNotFound.
func ByDirectoryURL(directoryURL string) (*Endpoint, error) {
	for _, e := range endpoints {
		if directoryURL == e.DirectoryURL {
			return e, nil
		}
	}

	return nil, ErrNotFound
}

// If an endpoint exists with the given directory URL, returns it.
//
// Otherwise, tries to create a new endpoint for the directory URL.  Where
// possible, endpoint parameters are guessed. Currently boulder is supported.
// Non-boulder based endpoints will not have any parameters set other than the
// directory URL, which means some operations on the endpoint will not succeed.
//
// It is acceptable to change the fields of the returned endpoint.
// By default, the title of the endpoint is the directory URL.
func CreateByDirectoryURL(directoryURL string) (*Endpoint, error) {
	e, err := ByDirectoryURL(directoryURL)
	if err == nil {
		return e, nil
	}

	// Make a code for the endpoint by hashing the directory URL...
	h := sha256.New()
	h.Write([]byte(directoryURL))
	code := fmt.Sprintf("Temp%08x", h.Sum(nil)[0:4])

	e = &Endpoint{
		Title:        directoryURL,
		DirectoryURL: directoryURL,
		Code:         code,
	}

	guessParameters(e)

	return e, nil
}

func guessParameters(e *Endpoint) {
	u, err := url.Parse(e.DirectoryURL)
	if err != nil {
		return
	}

	// not boulder
	if u.Path != "/directory" {
		return
	}

	if e.CertificateURLRegexp == "" {
		e.CertificateURLRegexp = "^https://" + regexp.QuoteMeta(u.Host) + "/acme/cert/.*$"
	}

	if e.CertificateURLTemplate == "" {
		e.CertificateURLTemplate = "https://" + u.Host + "/acme/cert/{{.Certificate.SerialNumber|printf \"%036x\"}}"
	}
}

// Given an URL to a certificate, tries to determine the directory URL.
func CertificateURLToDirectoryURL(certificateURL string) (string, error) {
	for _, e := range endpoints {
		e.init()

		if e.certificateURLRegexp != nil && e.certificateURLRegexp.MatchString(certificateURL) {
			return e.DirectoryURL, nil
		}
	}

	return "", ErrNotFound
}

// Given a certificate in DER form, tries to determine the set of endpoints
// which may have issued the certificate. certain is true if the returned
// endpoint definitely issued the certificate, in which case len(endpoints) ==
// 1 (but len(endpoints) == 1 does not necessarily imply certainty).
func CertificateToEndpoints(cert *x509.Certificate) (endp []*Endpoint, certain bool, err error) {
	var unknownEndpoints []*Endpoint

	for _, e := range endpoints {
		e.init()

		if e.ocspURLRegexp == nil {
			unknownEndpoints = append(unknownEndpoints, e)
		}

		log.Debugf("cert has OCSP %v", cert.OCSPServer)
		for _, ocspServer := range cert.OCSPServer {
			log.Debugf("%v %v", e, ocspServer)
			if e.ocspURLRegexp != nil && e.ocspURLRegexp.MatchString(ocspServer) {
				return []*Endpoint{e}, true, nil
			}
		}
	}

	if len(unknownEndpoints) > 0 {
		return unknownEndpoints, false, nil
	}

	log.Debugf("cannot find any endpoints for certificate")
	return nil, false, ErrNotFound
}

// Given a certificate, tries to determine the certificate URL and definite endpoint.
func CertificateToEndpointURL(cl *acmeapi.Client, cert *x509.Certificate, ctx context.Context) (*Endpoint, string, error) {
	es, certain, err := CertificateToEndpoints(cert)
	if err != nil {
		return nil, "", err
	}

	for _, e := range es {
		if e.certificateURLTemplate == nil {
			continue
		}

		var b bytes.Buffer
		err = e.certificateURLTemplate.Execute(&b, map[string]interface{}{
			"Certificate": cert,
		})
		if err != nil {
			return nil, "", err
		}

		u := b.String()
		if !certain {
			// Check that this is the right endpoint via an HTTP request.
			acrt := acmeapi.Certificate{
				URI: u,
			}

			err := cl.LoadCertificate(&acrt, ctx)
			if err != nil {
				continue
			}

			// check that the certificate DER matches
			if !bytes.Equal(acrt.Certificate, cert.Raw) {
				continue
			}
		}

		return e, u, nil
	}

	return nil, "", ErrNotFound
}

// Given a certificate, tries to determine the definite endpoint.
func CertificateToEndpoint(cl *acmeapi.Client, cert *x509.Certificate, ctx context.Context) (*Endpoint, error) {
	e, _, err := CertificateToEndpointURL(cl, cert, ctx)
	return e, err
}
