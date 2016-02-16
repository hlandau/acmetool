package acmeapi

import (
	"fmt"
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

// Internal type for representing error HTTP responses. Used so that the
// response can still be examined if desired.
type HttpError struct {
	Res         *http.Response
	ProblemBody string
}

func (he *HttpError) Error() string {
	return fmt.Sprintf("HTTP error: %v\n%v\n%v", he.Res.Status, he.Res.Header, he.ProblemBody)
}

func newHTTPError(res *http.Response) error {
	he := &HttpError{
		Res: res,
	}
	if res.Header.Get("Content-Type") == "application/problem+json" {
		defer res.Body.Close()
		b, err := ioutil.ReadAll(res.Body)
		if err == nil {
			he.ProblemBody = string(b)
		}
	}
	return he
}
