package acmeapi

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	denet "github.com/hlandau/goutils/net"
	jose "gopkg.in/square/go-jose.v1"
)

// Represents an account registration.
type Registration struct {
	URI      string `json:"-"`        // The URI of the registration.
	Resource string `json:"resource"` // must be "new-reg" or "reg"

	Key *jose.JsonWebKey `json:"key,omitempty"` // Account Key

	ContactURIs  []string `json:"contact,omitempty"`   // Contact URIs
	AgreementURI string   `json:"agreement,omitempty"` // ToS URI

	AuthorizationsURL string `json:"authorizations,omitempty"`
	CertificatesURL   string `json:"certificates,omitempty"`

	// This is not actually part of the registration, but it
	// is provided when loading a registration for convenience
	// as it is returned in the HTTP headers. It is the URI
	// of the current agreement required.
	LatestAgreementURI string `json:"-"`
}

// Represents an error that may have happened.
// https://tools.ietf.org/html/draft-ietf-appsawg-http-problem-00
type ProblemDetails struct {
	Type       string `json:"type,omitempty"`
	Detail     string `json:"detail,omitempty"`
	HTTPStatus int    `json:"status,omitempty"`
}

// Represents a single validation attempt.
type ValidationRecord struct {
	Authorities       []string `json:",omitempty"`
	URL               string   `json:"url,omitempty"`
	Hostname          string   `json:"hostname"`
	Port              string   `json:"port"`
	AddressesResolved []net.IP `json:"addressesResolved"`
	AddressUsed       net.IP   `json:"addressUsed"`
	AddressesTried    []net.IP `json:"addressesTried"`
}

// Represents a Challenge which is part of an Authorization.
type Challenge struct {
	URI      string `json:"uri"`      // The URI of the challenge.
	Resource string `json:"resource"` // "challenge"

	Type      string    `json:"type"`
	Status    Status    `json:"status,omitempty"`
	Validated time.Time `json:"validated,omitempty"` // RFC 3339
	Token     string    `json:"token"`

	// proofOfPossession
	Certs []denet.Base64up `json:"certs,omitempty"`

	Error                    *ProblemDetails    `json:"error,omitempty"`
	ProvidedKeyAuthorization string             `json:"keyAuthorization,omitempty"`
	ValidationRecord         []ValidationRecord `json:"validationRecord,omitempty"`

	retryAt time.Time
}

// Represents an authorization. You can construct an authorization from only
// the URI; the authorization information will be fetched automatically.
type Authorization struct {
	URI      string `json:"-"`        // The URI of the authorization.
	Resource string `json:"resource"` // must be "new-authz" or "authz"

	Identifier   Identifier   `json:"identifier"`
	Status       Status       `json:"status,omitempty"`
	Expires      time.Time    `json:"expires,omitempty"` // RFC 3339 (ISO 8601)
	Challenges   []*Challenge `json:"challenges,omitempty"`
	Combinations [][]int      `json:"combinations,omitempty"`

	retryAt time.Time
}

// Represents a certificate which has been, or is about to be, issued.
type Certificate struct {
	URI      string `json:"-"`        // The URI of the certificate.
	Resource string `json:"resource"` // "new-cert"

	// The certificate data. DER.
	Certificate []byte `json:"-"`

	// Any required extra certificates, in DER form in the correct order.
	ExtraCertificates [][]byte `json:"-"`

	// DER. Consumers of this API will find that this is always nil; it is
	// used internally when submitting certificate requests.
	CSR denet.Base64up `json:"csr"`

	retryAt time.Time
}

// Represents an identifier for which an authorization is desired.
type Identifier struct {
	Type  string `json:"type"`  // must be "dns"
	Value string `json:"value"` // dns: a hostname.
}

// Represents the status of an authorization or challenge.
type Status string

const (
	StatusUnknown    Status = "unknown"    // Non-final state...
	StatusPending           = "pending"    // Non-final state.
	StatusProcessing        = "processing" // Non-final state.
	StatusValid             = "valid"      // Final state.
	StatusInvalid           = "invalid"    // Final state.
	StatusRevoked           = "revoked"    // Final state.
)

// Returns true iff the status is a valid status.
func (s Status) Valid() bool {
	switch s {
	case "unknown", "pending", "processing", "valid", "invalid", "revoked":
		return true
	default:
		return false
	}
}

// Returns true iff the status is a final status.
func (s Status) Final() bool {
	switch s {
	case "valid", "invalid", "revoked":
		return true
	default:
		return false
	}
}

// Implements encoding/json.Unmarshaler.
func (s *Status) UnmarshalJSON(data []byte) error {
	var ss string
	err := json.Unmarshal(data, &ss)
	if err != nil {
		return err
	}

	if !Status(ss).Valid() {
		return fmt.Errorf("not a valid status: %#v", ss)
	}

	*s = Status(ss)
	return nil
}
