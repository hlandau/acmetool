package acmeapi

import "fmt"
import "io"
import "io/ioutil"
import "strings"
import "net/url"
import "crypto"
import "net/http"
import "github.com/square/go-jose"
import "sync"
import "encoding/json"
import "time"
import "strconv"
import "github.com/peterhellberg/link"
import "github.com/hlandau/xlog"
import denet "github.com/hlandau/degoutils/net"
import "golang.org/x/net/context"

var log, Log = xlog.NewQuiet("acme.api")

const LEStagingURL = "https://acme-staging.api.letsencrypt.org/directory"
const LELiveURL = "https://acme-v01.api.letsencrypt.org/directory"

var DefaultBaseURL = LEStagingURL

type directoryInfo struct {
	NewReg     string `json:"new-reg"`
	RecoverReg string `json:"recover-reg"`
	NewAuthz   string `json:"new-authz"`
	NewCert    string `json:"new-cert"`
	RevokeCert string `json:"revoke-cert"`
}

type regInfo struct {
	Resource string `json:"resource"` // must be "new-reg" or "reg"

	Contact []string         `json:"contact,omitempty"`
	Key     *jose.JsonWebKey `json:"key,omitempty"`

	AgreementURI      string `json:"agreement,omitempty"`
	AuthorizationsURI string `json:"authorizations,omitempty"`
	CertificatesURI   string `json:"certificates,omitempty"`
}

type revokeReq struct {
	Resource    string         `json:"resource"` // "revoke-cert"
	Certificate denet.Base64up `json:"certificate"`
}

// Represents an identifier for which an authorization is desired.
type Identifier struct {
	Type  string `json:"type"`  // must be "dns"
	Value string `json:"value"` // dns: a hostname.
}

// Represents the status of an authorization or challenge.
type Status string

const (
	StatusUnknown    Status = "unknown"
	StatusPending           = "pending"
	StatusProcessing        = "processing"
	StatusValid             = "valid"
	StatusInvalid           = "invalid"
	StatusRevoked           = "revoked"
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

// Represents a Challenge which is part of an Authorization.
type Challenge struct {
	URI      string `json:"uri"`      // The URI of the challenge.
	Resource string `json:"resource"` // "challenge"

	Type      string    `json:"type"`
	Status    Status    `json:"status,omitempty"`
	Validated time.Time `json:"validated,omitempty"` // RFC 3339
	Token     string    `json:"token"`

	// tls-sni-01
	N int `json:"n,omitempty"`

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
}

// Represents a certificate which has been, or is about to be, issued.
type Certificate struct {
	URI      string `json:"-"`        // The URI of the certificate.
	Resource string `json:"resource"` // "new-cert"

	CSR         denet.Base64up `json:"csr"` // DER.
	Certificate []byte         `json:"-"`   // DER.

	// Any required extra certificates, in the correct order.
	ExtraCertificates [][]byte `json:"-"` // DER.

	retryAt time.Time
}

// Client for making ACME API calls.
//
// You must set at least AccountKey.
type Client struct {
	AccountInfo struct {
		// Account private key.
		AccountKey crypto.PrivateKey

		// Set of agreement URIs to accept.
		AgreementURIs map[string]struct{}

		// Registration URI, if found. You can set this if known, which will save a
		// round trip in some cases.
		RegistrationURI string

		// Contact URIs. These will be used when registering or when updating a
		// registration.
		ContactURIs []string
	}

	// The ACME server directory URL. Defaults to DefaultBaseURL.
	BaseURL string

	// Uses http.DefaultClient if nil.
	HTTPClient *http.Client

	dir         *directoryInfo
	nonceSource nonceSource
	initOnce    sync.Once
}

// Error returned when the account agreement URI does not match the currently required
// agreement URI.
type AgreementError struct {
	URI string // The required agreement URI.
}

func (e *AgreementError) Error() string {
	return fmt.Sprintf("Registration requires agreement with the following agreement: %#v", e.URI)
}

type httpError struct {
	Res         *http.Response
	ProblemBody string
}

func (he *httpError) Error() string {
	return fmt.Sprintf("HTTP error: %v\n%v\n%v", he.Res.Status, he.Res.Header, he.ProblemBody)
}

func newHTTPError(res *http.Response) error {
	he := &httpError{
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

func (c *Client) doReq(method, url string, v, r interface{}) (*http.Response, error) {
	if !validURL(url) {
		return nil, fmt.Errorf("invalid URL: %#v", url)
	}

	var rdr io.Reader
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}

		if c.AccountInfo.AccountKey == nil {
			return nil, fmt.Errorf("account key must be specified")
		}

		signer, err := jose.NewSigner(jose.RS256, c.AccountInfo.AccountKey)
		if err != nil {
			return nil, err
		}

		signer.SetNonceSource(&c.nonceSource)

		sig, err := signer.Sign(b)
		if err != nil {
			return nil, err
		}

		s := sig.FullSerialize()
		if err != nil {
			return nil, err
		}

		rdr = strings.NewReader(s)
	}

	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "acmetool")
	req.Header.Set("Accept", "application/json")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	cl := c.HTTPClient
	if cl == nil {
		cl = http.DefaultClient
	}

	log.Debugf("request: %s", url)
	res, err := cl.Do(req)
	log.Debugf("response: %v %v", res, err)
	if err != nil {
		return nil, err
	}

	if n := res.Header.Get("Replay-Nonce"); n != "" {
		c.nonceSource.AddNonce(n)
	}

	if res.StatusCode >= 400 && res.StatusCode < 600 {
		defer res.Body.Close()
		return res, newHTTPError(res)
	}

	if r != nil {
		defer res.Body.Close()
		if ct := res.Header.Get("Content-Type"); ct != "application/json" {
			return res, fmt.Errorf("unexpected content type: %#v", ct)
		}

		err = json.NewDecoder(res.Body).Decode(r)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func ValidURL(u string) bool {
	return validURL(u)
}

func validURL(u string) bool {
	ur, err := url.Parse(u)
	return err == nil && ur.Scheme == "https"
}

func parseRetryAfter(h http.Header) (t time.Time, ok bool) {
	v := h.Get("Retry-After")
	if v == "" {
		return time.Time{}, false
	}

	n, err := strconv.ParseUint(v, 10, 31)
	if err != nil {
		t, err = time.Parse(time.RFC1123, v)
		if err != nil {
			return time.Time{}, false
		}

		return t, true
	}

	return time.Now().Add(time.Duration(n) * time.Second), true
}

func retryAtDefault(h http.Header, d time.Duration) time.Time {
	t, ok := parseRetryAfter(h)
	if ok {
		return t
	} else {
		return time.Now().Add(d)
	}
}

func (c *Client) getDirectory() (*directoryInfo, error) {
	if c.dir != nil {
		return c.dir, nil
	}

	if c.BaseURL == "" {
		c.BaseURL = DefaultBaseURL
	}

	_, err := c.doReq("GET", c.BaseURL, nil, &c.dir)
	if err != nil {
		return nil, err
	}

	if !validURL(c.dir.NewReg) || !validURL(c.dir.NewAuthz) || !validURL(c.dir.NewCert) {
		c.dir = nil
		return nil, fmt.Errorf("directory does not provide required endpoints")
	}

	return c.dir, nil
}

// API Methods

// Find the registration URI, by registering a new account if necessary.
func (c *Client) getRegistrationURI() (string, error) {
	if c.AccountInfo.RegistrationURI != "" {
		return c.AccountInfo.RegistrationURI, nil
	}

	di, err := c.getDirectory()
	if err != nil {
		return "", err
	}

	reqInfo := regInfo{
		Resource: "new-reg",
		Contact:  c.AccountInfo.ContactURIs,
	}

	var resInfo *regInfo
	res, err := c.doReq("POST", di.NewReg, &reqInfo, &resInfo)
	if res == nil {
		return "", err
	} else if res.StatusCode == 201 || res.StatusCode == 409 {
		loc := res.Header.Get("Location")
		if !validURL(loc) {
			return "", fmt.Errorf("invalid URL: %#v", loc)
		}

		c.AccountInfo.RegistrationURI = loc
	} else if err != nil {
		return "", err
	} else {
		return "", fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}

	return c.AccountInfo.RegistrationURI, nil
}

// Registers a new account or updates an existing account.
//
// The ContactURIs specified will be set.
//
// If a new agreement is required and it is set in AgreementURIs, it will be
// agreed to automatically. Otherwise AgreementError will be returned.
func (c *Client) UpsertRegistration() error {
	regURI, err := c.getRegistrationURI()
	if err != nil {
		return err
	}

	reqInfo := regInfo{
		Resource: "reg",
		Contact:  c.AccountInfo.ContactURIs,
	}

	var resInfo *regInfo
	res, err := c.doReq("POST", regURI, &reqInfo, &resInfo)
	if err != nil {
		return err
	}

	lg := link.ParseResponse(res)
	if tosLink, ok := lg["terms-of-service"]; ok {
		if resInfo.AgreementURI != tosLink.URI {
			_, ok := c.AccountInfo.AgreementURIs[tosLink.URI]
			if !ok {
				return &AgreementError{tosLink.URI}
			}

			reqInfo.AgreementURI = tosLink.URI
			_, err = c.doReq("POST", regURI, &reqInfo, &resInfo)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Load or reload the details of an authorization via the URI.
func (c *Client) LoadAuthorization(az *Authorization) error {
	az.Combinations = nil

	_, err := c.doReq("GET", az.URI, nil, az)
	if err != nil {
		return err
	}

	err = az.validate()
	if err != nil {
		return err
	}

	return nil
}

func (az *Authorization) validate() error {
	/*if az.Resource != "authz" {
		return fmt.Errorf("invalid resource field")
	}*/

	if len(az.Challenges) == 0 {
		return fmt.Errorf("no challenges offered")
	}

	if az.Combinations == nil {
		var is []int
		for i := 0; i < len(az.Challenges); i++ {
			is = append(is, i)
		}
		az.Combinations = append(az.Combinations, is)
	}

	for _, c := range az.Combinations {
		for _, i := range c {
			if i >= len(az.Challenges) {
				return fmt.Errorf("one or more combinations are malformed")
			}
		}
	}

	return nil
}

// Load or reload the details of a challenge via the URI.
func (c *Client) LoadChallenge(ch *Challenge) error {
	res, err := c.doReq("GET", ch.URI, nil, ch)
	if err != nil {
		return err
	}

	err = ch.validate()
	if err != nil {
		return err
	}

	ch.retryAt = retryAtDefault(res.Header, 10*time.Second)
	return nil
}

// Like LoadChallenge, but waits the retry time if this is not the first
// attempt to load this challenge. To be used when polling.
func (c *Client) WaitLoadChallenge(ch *Challenge, ctx context.Context) error {
	err := waitUntil(ch.retryAt, ctx)
	if err != nil {
		return err
	}

	return c.LoadChallenge(ch)
}

func (ch *Challenge) validate() error {
	/*if ch.Resource != "challenge" {
		return fmt.Errorf("invalid resource field")
	}*/

	return nil
}

// Create a new authorization for the given hostname.
func (c *Client) NewAuthorization(hostname string) (*Authorization, error) {
	di, err := c.getDirectory()
	if err != nil {
		return nil, err
	}

	az := &Authorization{
		Resource: "new-authz",
		Identifier: Identifier{
			Type:  "dns",
			Value: hostname,
		},
	}

	res, err := c.doReq("POST", di.NewAuthz, az, az)
	if err != nil {
		return nil, err
	}

	loc := res.Header.Get("Location")
	if res.StatusCode != 201 || !validURL(loc) {
		return nil, fmt.Errorf("expected status code 201 and valid Location header: %#v", res)
	}

	az.URI = loc

	err = az.validate()
	if err != nil {
		return nil, err
	}

	return az, nil
}

// Submit a challenge response. Only the challenge URI is required.
func (c *Client) RespondToChallenge(ch *Challenge, response json.RawMessage) error {
	_, err := c.doReq("POST", ch.URI, &response, c)
	if err != nil {
		return err
	}

	return nil
}

// Request a certificate using a CSR in DER form.
func (c *Client) RequestCertificate(csrDER []byte) (*Certificate, error) {
	di, err := c.getDirectory()
	if err != nil {
		return nil, err
	}

	crt := &Certificate{
		Resource: "new-cert",
		CSR:      csrDER,
	}

	res, err := c.doReq("POST", di.NewCert, crt, nil)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	if res.StatusCode != 201 {
		return nil, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}

	loc := res.Header.Get("Location")
	if !validURL(loc) {
		return nil, fmt.Errorf("invalid URI: %#v", loc)
	}

	crt.URI = loc

	err = c.loadCertificate(crt, res)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

// Load or reload a certificate.
//
// Returns nil if the certificate is not yet ready, but the Certificate field
// will remain nil.
func (c *Client) LoadCertificate(crt *Certificate) error {
	res, err := c.doReq("GET", crt.URI, nil, nil)
	if err != nil {
		return err
	}

	return c.loadCertificate(crt, res)
}

func (c *Client) loadCertificate(crt *Certificate, res *http.Response) error {
	defer res.Body.Close()
	ct := res.Header.Get("Content-Type")
	if ct == "application/pkix-cert" {
		der, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}

		crt.Certificate = der
		err = c.loadExtraCertificates(crt, res)
		if err != nil {
			return err
		}

	} else if res.StatusCode == 200 {
		return fmt.Errorf("Certificate returned with unexpected type: %v", ct)
	}

	crt.retryAt = retryAtDefault(res.Header, 10*time.Second)
	return nil
}

func (c *Client) loadExtraCertificates(crt *Certificate, res *http.Response) error {
	crt.ExtraCertificates = nil

	for {
		var err error

		lg := link.ParseResponse(res)
		up, ok := lg["up"]
		if !ok {
			return nil
		}

		crtURI, _ := url.Parse(crt.URI)
		upURI, _ := url.Parse(up.URI)
		if crtURI == nil || upURI == nil {
			return fmt.Errorf("invalid URI")
		}
		upURI = crtURI.ResolveReference(upURI)

		res, err = c.doReq("GET", upURI.String(), nil, nil)
		if err != nil {
			return err
		}

		defer res.Body.Close()
		ct := res.Header.Get("Content-Type")
		if ct != "application/pkix-cert" {
			return fmt.Errorf("unexpected certificate type: %v", ct)
		}

		der, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return err
		}

		res.Body.Close()
		crt.ExtraCertificates = append(crt.ExtraCertificates, der)
	}
}

var closedChannel = make(chan time.Time)

func init() {
	close(closedChannel)
}

// Wait for a pending certificate to be issued. If the certificate has already
// been issued, this is a no-op. Only the URI is required. May be cancelled using
// the context.
func (c *Client) WaitForCertificate(crt *Certificate, ctx context.Context) error {
	for {
		if len(crt.Certificate) > 0 {
			return nil
		}

		err := waitUntil(crt.retryAt, ctx)
		if err != nil {
			return err
		}

		err = c.LoadCertificate(crt)
		if err != nil {
			return err
		}
	}
}

// Wait until time t. If t is before the current time, returns immediately.
// Cancellable via ctx, in which case err is passed through. Otherwise returns
// nil.
func waitUntil(t time.Time, ctx context.Context) error {
	var ch <-chan time.Time
	ch = closedChannel
	now := time.Now()
	if t.After(now) {
		ch = time.After(t.Sub(now))
	}

	// make sure ctx.Done() is checked here even when we are using closedChannel,
	// as select doesn't guarantee any particular priority.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}

	return nil
}

// Revoke the given certificate.
func (c *Client) Revoke(certificateDER []byte) error {
	di, err := c.getDirectory()
	if err != nil {
		return err
	}

	req := &revokeReq{
		Resource:    "revoke-cert",
		Certificate: certificateDER,
	}

	res, err := c.doReq("POST", di.RevokeCert, req, nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}
