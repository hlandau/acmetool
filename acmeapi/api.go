// Package acmeapi provides an API for accessing ACME servers.
//
// Some methods provided correspond exactly to ACME calls, such as
// NewAuthorization, RespondToChallenge, RequestCertificate or Revoke. Others,
// such as UpsertRegistration, LoadCertificate or WaitForCertificate,
// automatically compose requests to provide a simplified interface.
//
// For example, LoadCertificate obtains the issuing certificate chain as well.
// WaitForCertificate polls until a certificate is available.
// UpsertRegistration determines automatically whether an account key is
// already registered and registers it if it is not.
//
// All methods take Contexts so as to support cancellation and timeouts.
//
// If you have an URI for an authorization, challenge or certificate, you
// can load it by constructing such an object and setting the URI field,
// then calling the appropriate Load function. (The unexported fields in these
// structures are used to track Retry-After times for the WaitLoad* functions and
// are not a barrier to you constructing these objects.)
//
// The following additional packages are likely to be of interest:
//
//   https://godoc.org/github.com/hlandau/acme/acmeapi/acmeendpoints  Known providers
//   https://godoc.org/github.com/hlandau/acme/acmeapi/acmeutils      Certificate loading utilities
//
package acmeapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"gopkg.in/square/go-jose.v1"

	denet "github.com/hlandau/goutils/net"
	"github.com/peterhellberg/link"
	"golang.org/x/net/context"
	"golang.org/x/net/context/ctxhttp"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"encoding/json"
	"fmt"
	"github.com/hlandau/xlog"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Log site.
var log, Log = xlog.NewQuiet("acme.api")

type directoryInfo struct {
	NewReg     string `json:"new-reg"`
	RecoverReg string `json:"recover-reg"`
	NewAuthz   string `json:"new-authz"`
	NewCert    string `json:"new-cert"`
	RevokeCert string `json:"revoke-cert"`
}

type revokeReq struct {
	Resource    string         `json:"resource"` // "revoke-cert"
	Certificate denet.Base64up `json:"certificate"`
}

// Returns true if the URL given is (potentially) a valid ACME resource URL.
//
// The URL must be an HTTPS URL.
func ValidURL(u string) bool {
	ur, err := url.Parse(u)
	return err == nil && (ur.Scheme == "https" || (TestingAllowHTTP && ur.Scheme == "http"))
}

// Internal use only. All ACME URLs must use "https" and not "http". However,
// for testing purposes, if this is set, "http" URLs will be allowed. This is
// useful for testing when a test ACME server doesn't have SSL configured.
var TestingAllowHTTP = false

// Client for making ACME API calls.
//
// You must set at least AccountKey and DirectoryURL.
type Client struct {
	// Account private key. Required.
	AccountKey crypto.PrivateKey

	// The ACME server directory URL. Required. (However, you can omit this if
	// you only use the client to load existing resources at known URLs.)
	DirectoryURL string

	// Uses http.DefaultClient if nil.
	HTTPClient *http.Client

	dir            *directoryInfo
	nonceSource    nonceSource
	nonceReentrant int
	initOnce       sync.Once
}

// You should set this to a string identifying the code invoking this library.
// Optional.
var UserAgent string

func (c *Client) doReq(method, url string, v, r interface{}, ctx context.Context) (*http.Response, error) {
	return c.doReqEx(method, url, nil, v, r, ctx)
}

func algorithmFromKey(key crypto.PrivateKey) (jose.SignatureAlgorithm, error) {
	switch v := key.(type) {
	case *rsa.PrivateKey:
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		name := v.Curve.Params().Name
		switch name {
		case "P-256":
			return jose.ES256, nil
		case "P-384":
			return jose.ES384, nil
		case "P-521":
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", name)
		}
	default:
		return "", fmt.Errorf("unsupported private key type: %T", key)
	}
}

func (c *Client) obtainNewNonce(ctx context.Context) error {
	if c.nonceReentrant > 0 {
		panic("nonce reentrancy - this should never happen")
	}
	c.nonceReentrant++
	defer func() { c.nonceReentrant-- }()

	_, err := c.forceGetDirectory(ctx)
	return err
}

func (c *Client) doReqEx(method, url string, key crypto.PrivateKey, v, r interface{}, ctx context.Context) (*http.Response, error) {
	if !ValidURL(url) {
		return nil, fmt.Errorf("invalid URL: %#v", url)
	}

	if key == nil {
		key = c.AccountKey
	}

	c.nonceSource.GetNonceFunc = c.obtainNewNonce

	var rdr io.Reader
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}

		if key == nil {
			return nil, fmt.Errorf("account key must be specified")
		}

		kalg, err := algorithmFromKey(key)
		if err != nil {
			return nil, err
		}

		signer, err := jose.NewSigner(kalg, key)
		if err != nil {
			return nil, err
		}

		signer.SetNonceSource(c.nonceSource.WithContext(ctx))

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

	req.Header.Set("Accept", "application/json")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}

	log.Debugf("request: %s", url)
	res, err := c.doReqActual(req, ctx)
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

func (c *Client) doReqActual(req *http.Request, ctx context.Context) (*http.Response, error) {
	req.Header.Set("User-Agent", userAgent(UserAgent))
	return ctxhttp.Do(ctx, c.HTTPClient, req)
}

func (c *Client) forceGetDirectory(ctx context.Context) (*directoryInfo, error) {
	if c.DirectoryURL == "" {
		return nil, fmt.Errorf("must specify a directory URL")
	}

	_, err := c.doReq("GET", c.DirectoryURL, nil, &c.dir, ctx)
	if err != nil {
		return nil, err
	}

	if !ValidURL(c.dir.NewReg) || !ValidURL(c.dir.NewAuthz) || !ValidURL(c.dir.NewCert) {
		c.dir = nil
		return nil, fmt.Errorf("directory does not provide required endpoints")
	}

	return c.dir, nil
}

func (c *Client) getDirectory(ctx context.Context) (*directoryInfo, error) {
	if c.dir != nil {
		return c.dir, nil
	}

	return c.forceGetDirectory(ctx)
}

// API Methods

var newRegCodes = []int{201, 409}
var updateRegCodes = []int{200, 202}

func isStatusCode(res *http.Response, codes []int) bool {
	for _, c := range codes {
		if c == res.StatusCode {
			return true
		}
	}
	return false
}

// Loads an existing registration. If reg.URI is set, then that registration is
// updated, and the operation fails if the registration does not exist.
// Otherwise, the registration is created if it does not exist or updated if it
// does and the URI is returned.
//
// Note that this operation requires an account key, since the registration is
// private data requiring authentication to access.
func (c *Client) UpsertRegistration(reg *Registration, ctx context.Context) error {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return err
	}

	// Determine whether we need to get the registration URI.
	endp := reg.URI
	resource := "reg"
	expectCode := updateRegCodes
	if endp == "" {
		endp = di.NewReg
		resource = "new-reg"
		expectCode = newRegCodes
	}

	// Make request.
	reg.Resource = resource
	res, err := c.doReq("POST", endp, reg, reg, ctx)
	if res == nil {
		return err
	}

	// Get TOS URI.
	lg := link.ParseResponse(res)
	if tosLink, ok := lg["terms-of-service"]; ok {
		reg.LatestAgreementURI = tosLink.URI
	}

	// Ensure status code is an expected value.
	if !isStatusCode(res, expectCode) {
		if err != nil {
			return err
		}

		return fmt.Errorf("unexpected status code: %d: %v", res.StatusCode, endp)
	}

	// Process registration URI.
	loc := res.Header.Get("Location")
	switch {
	case resource == "reg":
		// Updating existing registration, so we already have the URL and
		// shouldn't be redirected anywhere.
		if loc != "" {
			return fmt.Errorf("unexpected Location header: %q", loc)
		}
	case !ValidURL(loc):
		return fmt.Errorf("invalid URL: %q", loc)
	default:
		// Save the registration URL.
		reg.URI = loc
	}

	// If conflict occurred, need to issue the request again to update fields.
	if res.StatusCode == 409 {
		return c.UpsertRegistration(reg, ctx)
	}

	return nil
}

// This is a higher-level account registration method built on
// UpsertRegistration. If a new agreement is required and its URI
// is set in agreementURIs, it will be agreed to automatically. Otherwise
// AgreementError will be returned.
func (c *Client) AgreeRegistration(reg *Registration, agreementURIs map[string]struct{}, ctx context.Context) error {
	err := c.UpsertRegistration(reg, ctx)
	if err != nil {
		return err
	}

	if reg.LatestAgreementURI != reg.AgreementURI {
		_, ok := agreementURIs[reg.LatestAgreementURI]
		if !ok {
			return &AgreementError{reg.LatestAgreementURI}
		}

		reg.AgreementURI = reg.LatestAgreementURI
		err = c.UpsertRegistration(reg, ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

// Load or reload the details of an authorization via the URI.
//
// You can load an authorization from only the URI by creating an Authorization
// with the URI set and then calling this.
func (c *Client) LoadAuthorization(az *Authorization, ctx context.Context) error {
	az.Combinations = nil

	res, err := c.doReq("GET", az.URI, nil, az, ctx)
	if err != nil {
		return err
	}

	err = az.validate()
	if err != nil {
		return err
	}

	az.retryAt = retryAtDefault(res.Header, 10*time.Second)
	return nil
}

// Like LoadAuthorization, but waits the retry time if this is not the first
// attempt to load this authoization. To be used when polling.
func (c *Client) WaitLoadAuthorization(az *Authorization, ctx context.Context) error {
	err := waitUntil(az.retryAt, ctx)
	if err != nil {
		return err
	}

	return c.LoadAuthorization(az, ctx)
}

func (az *Authorization) validate() error {
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
//
// You can load a challenge from only the URI by creating a Challenge with the
// URI set and then calling this.
func (c *Client) LoadChallenge(ch *Challenge, ctx context.Context) error {
	res, err := c.doReq("GET", ch.URI, nil, ch, ctx)
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

	return c.LoadChallenge(ch, ctx)
}

// Create a new authorization for the given hostname.
func (c *Client) NewAuthorization(hostname string, ctx context.Context) (*Authorization, error) {
	di, err := c.getDirectory(ctx)
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

	res, err := c.doReq("POST", di.NewAuthz, az, az, ctx)
	if err != nil {
		return nil, err
	}

	loc := res.Header.Get("Location")
	if res.StatusCode != 201 || !ValidURL(loc) {
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
//
// The response message is signed with the given key.
//
// If responseKey is nil, the account key is used.
func (c *Client) RespondToChallenge(ch *Challenge, response json.RawMessage, responseKey crypto.PrivateKey, ctx context.Context) error {
	_, err := c.doReqEx("POST", ch.URI, responseKey, &response, c, ctx)
	if err != nil {
		return err
	}

	return nil
}

// Request a certificate using a CSR in DER form.
func (c *Client) RequestCertificate(csrDER []byte, ctx context.Context) (*Certificate, error) {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return nil, err
	}

	crt := &Certificate{
		Resource: "new-cert",
		CSR:      csrDER,
	}

	res, err := c.doReq("POST", di.NewCert, crt, nil, ctx)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	if res.StatusCode != 201 {
		return nil, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}

	loc := res.Header.Get("Location")
	if !ValidURL(loc) {
		return nil, fmt.Errorf("invalid URI: %#v", loc)
	}

	crt.URI = loc

	err = c.loadCertificate(crt, res, ctx)
	if err != nil {
		return nil, err
	}

	return crt, nil
}

// Load or reload a certificate.
//
// You can load a certificate from its URI by creating a Certificate with the
// URI set and then calling this.
//
// Returns nil if the certificate is not yet ready, but the Certificate field
// will remain nil.
func (c *Client) LoadCertificate(crt *Certificate, ctx context.Context) error {
	res, err := c.doReq("GET", crt.URI, nil, nil, ctx)
	if err != nil {
		return err
	}

	return c.loadCertificate(crt, res, ctx)
}

func (c *Client) loadCertificate(crt *Certificate, res *http.Response, ctx context.Context) error {
	defer res.Body.Close()
	ct := res.Header.Get("Content-Type")
	if ct == "application/pkix-cert" {
		der, err := ioutil.ReadAll(denet.LimitReader(res.Body, 1*1024*1024))
		if err != nil {
			return err
		}

		crt.Certificate = der
		err = c.loadExtraCertificates(crt, res, ctx)
		if err != nil {
			return err
		}

	} else if res.StatusCode == 200 {
		return fmt.Errorf("Certificate returned with unexpected type: %v", ct)
	}

	crt.retryAt = retryAtDefault(res.Header, 10*time.Second)
	return nil
}

func (c *Client) loadExtraCertificates(crt *Certificate, res *http.Response, ctx context.Context) error {
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

		res, err = c.doReq("GET", upURI.String(), nil, nil, ctx)
		if err != nil {
			return err
		}

		defer res.Body.Close()
		ct := res.Header.Get("Content-Type")
		if ct != "application/pkix-cert" {
			return fmt.Errorf("unexpected certificate type: %v", ct)
		}

		der, err := ioutil.ReadAll(denet.LimitReader(res.Body, 1*1024*1024))
		if err != nil {
			return err
		}

		res.Body.Close()
		crt.ExtraCertificates = append(crt.ExtraCertificates, der)
	}
}

// Like LoadCertificate, but waits the retry time if this is not the first
// attempt to load this certificate. To be used when polling.
//
// You will almost certainly want WaitForCertificate instead of this.
func (c *Client) WaitLoadCertificate(crt *Certificate, ctx context.Context) error {
	err := waitUntil(crt.retryAt, ctx)
	if err != nil {
		return err
	}

	return c.LoadCertificate(crt, ctx)
}

// Wait for a pending certificate to be issued. If the certificate has already
// been issued, this is a no-op. Only the URI is required. May be cancelled
// using the context.
func (c *Client) WaitForCertificate(crt *Certificate, ctx context.Context) error {
	for {
		if len(crt.Certificate) > 0 {
			return nil
		}

		err := c.WaitLoadCertificate(crt, ctx)
		if err != nil {
			return err
		}
	}
}

// Revoke the given certificate.
//
// The revocation key may be the key corresponding to the certificate. If it is
// nil, the account key is used; in this case, the account must be authorized
// for all identifiers in the certificate.
func (c *Client) Revoke(certificateDER []byte, revocationKey crypto.PrivateKey, ctx context.Context) error {
	di, err := c.getDirectory(ctx)
	if err != nil {
		return err
	}

	if di.RevokeCert == "" {
		return fmt.Errorf("endpoint does not support revocation")
	}

	req := &revokeReq{
		Resource:    "revoke-cert",
		Certificate: certificateDER,
	}

	res, err := c.doReqEx("POST", di.RevokeCert, revocationKey, req, nil, ctx)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	return nil
}

func userAgent(ua string) string {
	if ua != "" {
		ua += " "
	}

	return fmt.Sprintf("%sacmeapi Go-http-client/1.1 %s/%s", ua, runtime.GOOS, runtime.GOARCH)
}
