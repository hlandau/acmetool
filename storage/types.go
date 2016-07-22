package storage

import (
	"crypto"
	"encoding/base32"
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/jmhodges/clock"
	"github.com/satori/go.uuid"
	"strings"
	"time"
)

// Represents stored account data.
type Account struct {
	// N. Account private key.
	PrivateKey crypto.PrivateKey

	// N. Server directory URL.
	DirectoryURL string

	// Disposable. Authorizations.
	Authorizations map[string]*Authorization

	// ID: determined from DirectoryURL and PrivateKey.
	// Path: formed from ID.
	// Registration URL: can be recovered automatically.
}

// Returns the account ID (server URL/key ID).
func (a *Account) ID() string {
	accountID, err := determineAccountID(a.DirectoryURL, a.PrivateKey)
	log.Panice(err)

	return accountID
}

// Returns true iff the account is for a given provider URL.
func (a *Account) MatchesURL(p string) bool {
	return p == a.DirectoryURL
}

func (a *Account) String() string {
	return fmt.Sprintf("Account(%v)", a.ID())
}

// Represents an authorization.
type Authorization struct {
	// N. The authorized hostname.
	Name string

	// N. The authorization URL.
	URL string

	// D. Can be derived from the URL. The authorization expiry time.
	Expires time.Time
}

// Returns true iff the authorization is unexpired.
func (a *Authorization) IsValid(clock clock.Clock) bool {
	return clock.Now().Before(a.Expires)
}

// Represents the "satisfy" section of a target file.
type TargetSatisfy struct {
	// N. List of SANs required to satisfy this target. May include hostnames
	// (and maybe one day SRV-IDs). May include wildcard hostnames, but ACME
	// doesn't support those yet.
	Names []string `yaml:"names,omitempty"`

	// D. Reduced name set, after disjunction operation. Derived from Names.
	ReducedNames []string `yaml:"-"`
}

// Represents the "request" section of a target file.
type TargetRequest struct {
	// N/d. List of SANs to place on any obtained certificate. Defaults to the
	// names in the satisfy section.
	Names []string `yaml:"names,omitempty"`

	// Used to track whether Names was explicitly specified, for reserialization purposes.
	implicitNames bool

	// N. Currently, this is the provider directory URL. An account matching it
	// will be used. At some point, a way to specify a particular account should
	// probably be added.
	Provider string `yaml:"provider,omitempty"`

	// D. Account to use. The storage package does not set this; it is for the
	// convenience of consuming code. To be determined via Provider string.
	Account *Account `yaml:"-"`

	// Settings relating to the creation of new keys used to request
	// corresponding certificates.
	Key TargetRequestKey `yaml:"key,omitempty"`

	// Settings relating to the completion of challenges.
	Challenge TargetRequestChallenge `yaml:"challenge,omitempty"`

	// N. Request OCSP Must Staple in CSRs?
	OCSPMustStaple bool `yaml:"ocsp-must-staple,omitempty"`
}

// Settings for keys generated as part of certificate requests.
type TargetRequestKey struct {
	// N. Key type to use in making a request. "rsa" or "ecdsa". Default "rsa".
	Type string `yaml:"type,omitempty"`

	// N. RSA key size to use for new RSA keys. Defaults to 2048 bits.
	RSASize int `yaml:"rsa-size,omitempty"`

	// N. ECDSA curve. "nistp256" (default), "nistp384" or "nistp521".
	ECDSACurve string `yaml:"ecdsa-curve,omitempty"`

	// N. The key ID of an existing key to use for the purposes of making
	// requests. If not set, always generate a new key.
	ID string `yaml:"id,omitempty"`
}

func (k *TargetRequestKey) String() string {
	switch k.Type {
	case "", "rsa":
		return fmt.Sprintf("rsa-%d", clampRSAKeySize(k.RSASize))
	case "ecdsa":
		return fmt.Sprintf("ecdsa-%s", clampECDSACurve(k.ECDSACurve))
	default:
		return k.Type // ...
	}
}

// Settings relating to the completion of challenges.
type TargetRequestChallenge struct {
	// N. Webroot paths to use when completing challenges.
	WebrootPaths []string `yaml:"webroot-paths,omitempty"`

	// N. Ports to listen on when completing challenges.
	HTTPPorts []string `yaml:"http-ports,omitempty"`

	// N. Perform HTTP self-test? Defaults to true. Rarely needed. If disabled,
	// HTTP challenges will be performed without self-testing.
	HTTPSelfTest *bool `yaml:"http-self-test,omitempty"`

	// N. Environment variables to pass to hooks.
	Env map[string]string `yaml:"env,omitempty"`
	// N. Inherited environment variables. Used internally.
	InheritedEnv map[string]string `yaml:"-"`
}

// Represents a stored target descriptor.
type Target struct {
	// Specifies conditions which must be met.
	Satisfy TargetSatisfy `yaml:"satisfy,omitempty"`

	// Specifies parameters used when requesting certificates.
	Request TargetRequest `yaml:"request,omitempty"`

	// N. Priority. See state storage specification.
	Priority int `yaml:"priority,omitempty"`

	// LEGACY. Names to be satisfied. Moved to Satisfy.Names.
	LegacyNames []string `yaml:"names,omitempty"`

	// LEGACY. Provider URL to used. Moved to Request.Provider.
	LegacyProvider string `yaml:"provider,omitempty"`

	// Internal use. The filename under which the target is stored.
	Filename string `yaml:"-"`
}

func (t *Target) String() string {
	return fmt.Sprintf("Target(%s;%s;%d)", strings.Join(t.Satisfy.Names, ","), t.Request.Provider, t.Priority)
}

// Validates a target for basic sanity. Returns the first error found or nil.
func (t *Target) Validate() error {
	if t.Request.Provider != "" && !acmeapi.ValidURL(t.Request.Provider) {
		return fmt.Errorf("invalid provider URL: %q", t.Request.Provider)
	}

	return nil
}

func (tgt *Target) ensureFilename() {
	if tgt.Filename != "" {
		return
	}

	// Unfortunately we can't really check if the first hostname exists as a filename
	// and use another name instead as this would create all sorts of race conditions.
	// We have to use a random name.

	nprefix := ""
	if len(tgt.Satisfy.Names) > 0 {
		nprefix = tgt.Satisfy.Names[0] + "-"
	}

	b := uuid.NewV4().Bytes()
	str := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))

	tgt.Filename = nprefix + str
}

// Returns a copy of the target.
func (t *Target) Copy() *Target {
	// A Target contains no pointers to part of the target which should be copied.
	// i.e. all pointers point to other things not part of the copy. Thus we can
	// just copy the value. If Target is ever changed to reference any component
	// of itself via pointer, this must be changed!
	tt := *t
	tt.Request.Challenge.InheritedEnv = map[string]string{}
	for k, v := range t.Request.Challenge.InheritedEnv {
		tt.Request.Challenge.InheritedEnv[k] = v
	}
	for k, v := range t.Request.Challenge.Env {
		tt.Request.Challenge.InheritedEnv[k] = v
	}
	tt.Request.Challenge.Env = nil
	return &tt
}

// Returns a copy of the target, but zeroes any very specific fields
// like names.
func (t *Target) CopyGeneric() *Target {
	tt := t.Copy()
	tt.genericise()
	return tt
}

func (t *Target) genericise() {
	t.Satisfy.Names = nil
	t.Satisfy.ReducedNames = nil
	t.Request.Names = nil
	t.LegacyNames = nil
}

// Represents stored certificate information.
type Certificate struct {
	// N. URL from which the certificate can be retrieved.
	URL string

	// N. Whether this certificate should be revoked.
	RevocationDesired bool

	// N (for now). Whether this certificate has been revoked.
	Revoked bool

	// D. Certificate data retrieved from URL, plus chained certificates.
	// The end certificate comes first, the root last, etc.
	Certificates [][]byte

	// D. True if the certificate has been downloaded.
	Cached bool

	// D. The private key for the certificate.
	Key *Key

	// D. ID: formed from hash of certificate URL.
	// D. Path: formed from ID.
}

// Returns a string summary of the certificate.
func (c *Certificate) String() string {
	return fmt.Sprintf("Certificate(%v)", c.ID())
}

// Returns the certificate ID.
func (c *Certificate) ID() string {
	return determineCertificateID(c.URL)
}

// Represents a stored key.
type Key struct {
	// N. The key.
	PrivateKey crypto.PrivateKey

	// D. ID: Derived from the key itself.
	ID string

	// D. Path: formed from ID.
}

// Returns a string summary of the key.
func (k *Key) String() string {
	return fmt.Sprintf("Key(%v)", k.ID)
}
