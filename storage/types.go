package storage

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base32"
	"fmt"
	"github.com/gofrs/uuid"
	"gopkg.in/hlandau/acmeapi.v2"
	"strings"
)

// Represents stored account data.
type Account struct {
	// N. Account private key.
	PrivateKey crypto.PrivateKey

	// N. Server directory URL.
	DirectoryURL string

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

// Convert storage Account object to a new acmeapi.Account suitable for making
// requests.
func (a *Account) ToAPI() *acmeapi.Account {
	return &acmeapi.Account{
		PrivateKey: a.PrivateKey,
	}
}

// Represents the "satisfy" section of a target file.
type TargetSatisfy struct {
	// N. List of SANs required to satisfy this target. May include hostnames
	// (and maybe one day SRV-IDs). May include wildcard hostnames, but ACME
	// doesn't support those yet.
	Names []string `yaml:"names,omitempty"`

	// N. Renewal margin in days. Defaults to 30.
	Margin int `yaml:"margin,omitempty"`

	// D. Reduced name set, after disjunction operation. Derived from Names for
	// each label (or label "").
	//ReducedNamesByLabel map[string][]string `yaml:"-"`

	// N. Key configuration items which are required to satisfy a target.
	Key TargetSatisfyKey `yaml:"key,omitempty"`
}

// Represents the "satisfy": "key" section of a target file.
type TargetSatisfyKey struct {
	// N. Type of key to require. "" means do not require any specific type of
	// key.
	Type string `yaml:"type,omitempty"`
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

	// N. Priority. Controls symlink generation. See state storage specification.
	Priority int `yaml:"priority,omitempty"`

	// N. Label. Controls symlink generation. See state storage specification.
	Label string `yaml:"label,omitempty"`

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

func (t *Target) ensureFilename() {
	if t.Filename != "" {
		return
	}

	// Unfortunately we can't really check if the first hostname exists as a filename
	// and use another name instead as this would create all sorts of race conditions.
	// We have to use a random name.

	nprefix := ""
	if len(t.Satisfy.Names) > 0 {
		nprefix = t.Satisfy.Names[0] + "-"
	}

	b := uuid.Must(uuid.NewV4()).Bytes()
	str := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))

	t.Filename = nprefix + str
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
	//t.Satisfy.ReducedNamesByLabel = nil
	t.Request.Names = nil
	t.LegacyNames = nil
}

// Represents stored certificate information.
type Certificate struct {
	// N. URL to the order used to obtain the certificate. Not a direct URL to
	// the certificate blob.
	URL string

	// N. Whether this certificate should be revoked.
	RevocationDesired bool

	// N (for now). Whether this certificate has been revoked.
	Revoked bool

	// N. Now required due to need to support POST-as-GET. The account under
	// which the certificate was requested. nil if this is unknown due to being a
	// legacy certificate directory.
	Account *Account

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

// Returns the type name of the key ("rsa" or "ecdsa").
func (k *Key) Type() string {
	switch k.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return "rsa"
	case *ecdsa.PrivateKey:
		return "ecdsa"
	default:
		return ""
	}
}
