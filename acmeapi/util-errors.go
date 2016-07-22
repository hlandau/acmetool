package acmeapi

import (
	"fmt"
	denet "github.com/hlandau/goutils/net"
	"io/ioutil"
	"net/http"
)

// Error returned when the account agreement URI does not match the currently required
// agreement URI.
type AgreementError struct {
	URI string // The required agreement URI.
}

func (e *AgreementError) Error() string {
	return fmt.Sprintf("Registration requires agreement with the following agreement: %#v", e.URI)
}

// Error returned when an HTTP request results in a valid response, but which
// has an unexpected failure status code. Used so that the response can still
// be examined if desired.
type HTTPError struct {
	// The HTTP response.
	Res *http.Response

	// If the response had an application/problem+json response body, this is
	// that JSON data.
	ProblemBody string
}

// Summarises the response status, headers, and the JSON problem body if
// available.
func (he *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error: %v\n%v\n%v", he.Res.Status, he.Res.Header, he.ProblemBody)
}

func newHTTPError(res *http.Response) error {
	he := &HTTPError{
		Res: res,
	}
	if res.Header.Get("Content-Type") == "application/problem+json" {
		defer res.Body.Close()
		b, err := ioutil.ReadAll(denet.LimitReader(res.Body, 1*1024*1024))
		if err == nil {
			he.ProblemBody = string(b)
		}
	}
	return he
}
