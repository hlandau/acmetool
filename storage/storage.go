// Package storage implements the state directory specification and operations
// upon it.
package storage

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"sort"
	"strings"
	"time"

	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeendpoints"
	"github.com/hlandau/acme/acmeapi/acmeutils"
	"github.com/hlandau/acme/fdb"
	"github.com/hlandau/acme/notify"
	"github.com/hlandau/acme/responder"
	"github.com/hlandau/acme/solver"
	"github.com/hlandau/xlog"
	"github.com/satori/go.uuid"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
)

var log, Log = xlog.New("acme.storage")

// Represents stored account data.
type Account struct {
	// N. Account private key.
	PrivateKey crypto.PrivateKey

	// N. Server directory URL.
	BaseURL string

	// Disposable. Authorizations.
	Authorizations map[string]*Authorization

	// ID: retrirved from BaseURL and PrivateKey.
	// Path: formed from ID.
	// Registration URL: can be recovered automatically.
}

// Returns the account ID (server URL/key ID).
func (a *Account) ID() string {
	accountID, err := determineAccountID(a.BaseURL, a.PrivateKey)
	log.Panice(err)

	return accountID
}

// Returns true iff the account is for a given provider URL.
func (a *Account) MatchesURL(p string) bool {
	return p == a.BaseURL
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
func (a *Authorization) IsValid() bool {
	return time.Now().Before(a.Expires)
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

	// D. Account to use, determined via Provider string.
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

// Returns a copy of the target.
func (t *Target) Copy() *Target {
	// A Target contains no pointers to part of the target which should be copied.
	// i.e. all pointers point to other things not part of the copy. Thus we can
	// just copy the value. If Target is ever changed to reference any component
	// of itself via pointer, this must be changed!
	tt := *t
	return &tt
}

// Returns a copy of the target, but zeroes any very specific fields
// like names.
func (t *Target) CopyGeneric() *Target {
	tt := t.Copy()
	tt.Satisfy.Names = nil
	tt.Satisfy.ReducedNames = nil
	tt.Request.Names = nil
	tt.LegacyNames = nil
	return tt
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

func (k *Key) String() string {
	return fmt.Sprintf("Key(%v)", k.ID)
}

// ACME client store.
type Store struct {
	db *fdb.DB

	path                  string
	referencedCerts       map[string]struct{}
	certs                 map[string]*Certificate // key: certificate ID
	accounts              map[string]*Account     // key: account ID
	keys                  map[string]*Key         // key: key ID
	targets               map[string]*Target      // key: target filename
	defaultTarget         *Target                 // from conf
	hostnameTargetMapping map[string]*Target
}

// The recommended path is the hardcoded, default, recommended path to be used
// for a system-wide state storage directory. It may vary by system and
// platform. On most POSIX-like systems, it is "/var/lib/acme". Specific builds
// might customise it.
var RecommendedPath string

func init() {
	// Allow the path to be overridden at build time.
	if RecommendedPath == "" {
		RecommendedPath = "/var/lib/acme"
	}
}

var storePermissions = []fdb.Permission{
	{Path: ".", DirMode: 0755, FileMode: 0644},
	{Path: "accounts", DirMode: 0700, FileMode: 0600},
	{Path: "desired", DirMode: 0755, FileMode: 0644},
	{Path: "live", DirMode: 0755, FileMode: 0644},
	{Path: "certs", DirMode: 0755, FileMode: 0644},
	{Path: "certs/*/haproxy", DirMode: 0700, FileMode: 0600}, // hack for HAProxy
	{Path: "keys", DirMode: 0700, FileMode: 0600},
	{Path: "conf", DirMode: 0755, FileMode: 0644},
	{Path: "tmp", DirMode: 0700, FileMode: 0600},
}

// Create a new client store using the given path.
func New(path string) (*Store, error) {
	if path == "" {
		path = RecommendedPath
	}

	db, err := fdb.Open(fdb.Config{
		Path:        path,
		Permissions: storePermissions,
	})
	if err != nil {
		return nil, err
	}

	s := &Store{
		db:   db,
		path: path,
	}

	err = s.load()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Store) load() error {
	err := s.loadAccounts()
	if err != nil {
		return err
	}

	err = s.loadKeys()
	if err != nil {
		return err
	}

	err = s.loadCerts()
	if err != nil {
		return err
	}

	err = s.loadTargets()
	if err != nil {
		return err
	}

	err = s.disjoinTargets()
	if err != nil {
		return err
	}

	err = s.linkTargets()
	if err != nil {
		return err
	}

	s.loadWebrootPaths()
	s.loadRSAKeySize()

	return nil
}

func (s *Store) loadAccounts() error {
	c := s.db.Collection("accounts")

	serverNames, err := c.List()
	if err != nil {
		return err
	}

	s.accounts = map[string]*Account{}
	for _, serverName := range serverNames {
		sc := c.Collection(serverName)

		accountNames, err := sc.List()
		if err != nil {
			return err
		}

		for _, accountName := range accountNames {
			ac := sc.Collection(accountName)

			err := s.validateAccount(serverName, accountName, ac)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Store) validateAccount(serverName, accountName string, c *fdb.Collection) error {
	f, err := c.Open("privkey")
	if err != nil {
		return err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	pk, err := acmeutils.LoadPrivateKey(b)
	if err != nil {
		return err
	}

	f.Close()

	baseURL, err := decodeAccountURLPart(serverName)
	if err != nil {
		return err
	}

	account := &Account{
		PrivateKey:     pk,
		BaseURL:        baseURL,
		Authorizations: map[string]*Authorization{},
	}

	accountID := account.ID()
	actualAccountID := serverName + "/" + accountName
	if accountID != actualAccountID {
		return fmt.Errorf("account ID mismatch: %#v != %#v", accountID, actualAccountID)
	}

	s.accounts[accountID] = account

	err = s.validateAuthorizations(account, c)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) validateAuthorizations(account *Account, c *fdb.Collection) error {
	ac := c.Collection("authorizations")

	auths, err := ac.List()
	if err != nil {
		return err
	}

	for _, auth := range auths {
		auc := ac.Collection(auth)
		err := s.validateAuthorization(account, auth, auc)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) validateAuthorization(account *Account, authName string, c *fdb.Collection) error {
	ss, err := fdb.String(c.Open("expiry"))
	if err != nil {
		return err
	}

	expiry, err := time.Parse(time.RFC3339, strings.TrimSpace(ss))
	if err != nil {
		return err
	}

	azURL, _ := fdb.String(c.Open("url"))
	if !acmeapi.ValidURL(azURL) {
		azURL = ""
	}

	az := &Authorization{
		Name:    authName,
		URL:     strings.TrimSpace(azURL),
		Expires: expiry,
	}

	account.Authorizations[authName] = az
	return nil
}

func (s *Store) loadKeys() error {
	s.keys = map[string]*Key{}

	c := s.db.Collection("keys")

	keyIDs, err := c.List()
	if err != nil {
		return err
	}

	for _, keyID := range keyIDs {
		kc := c.Collection(keyID)

		err := s.validateKey(keyID, kc)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) validateKey(keyID string, kc *fdb.Collection) error {
	f, err := kc.Open("privkey")
	if err != nil {
		return err
	}

	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	pk, err := acmeutils.LoadPrivateKey(b)
	if err != nil {
		return err
	}

	actualKeyID, err := determineKeyIDFromKey(pk)
	if err != nil {
		return err
	}

	if actualKeyID != keyID {
		return fmt.Errorf("key ID mismatch: %#v != %#v", keyID, actualKeyID)
	}

	k := &Key{
		ID:         actualKeyID,
		PrivateKey: pk,
	}

	s.keys[actualKeyID] = k

	return nil
}

func (s *Store) loadCerts() error {
	s.certs = map[string]*Certificate{}

	c := s.db.Collection("certs")

	certIDs, err := c.List()
	if err != nil {
		return err
	}

	for _, certID := range certIDs {
		kc := c.Collection(certID)

		err := s.validateCert(certID, kc)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) validateCert(certID string, c *fdb.Collection) error {
	ss, err := fdb.String(c.Open("url"))
	if err != nil {
		return err
	}

	ss = strings.TrimSpace(ss)
	if !acmeapi.ValidURL(ss) {
		return fmt.Errorf("certificate has invalid URI")
	}

	actualCertID := determineCertificateID(ss)
	if certID != actualCertID {
		return fmt.Errorf("cert ID mismatch: %#v != %#v", certID, actualCertID)
	}

	crt := &Certificate{
		URL:               ss,
		Certificates:      nil,
		Cached:            false,
		RevocationDesired: fdb.Exists(c, "revoke"),
		Revoked:           fdb.Exists(c, "revoked"),
	}

	fullchain, err := fdb.Bytes(c.Open("fullchain"))
	if err == nil {
		certs, err := acmeutils.LoadCertificates(fullchain)
		if err != nil {
			return err
		}

		xcrt, err := x509.ParseCertificate(certs[0])
		if err != nil {
			return err
		}

		keyID := determineKeyIDFromCert(xcrt)
		crt.Key = s.keys[keyID]

		if crt.Key != nil {
			err := c.WriteLink("privkey", fdb.Link{Target: "keys/" + keyID + "/privkey"})
			if err != nil {
				return err
			}
		}

		crt.Certificates = certs
		crt.Cached = true
	}

	// TODO: obtain derived data
	s.certs[certID] = crt

	return nil
}

// Return the default target. Persist changes to the default target by calling SaveDefaultTarget.
func (s *Store) DefaultTarget() *Target {
	return s.defaultTarget
}

// Set the default provider directory URL.
func (s *Store) SetDefaultProvider(providerURL string) error {
	s.defaultTarget.Request.Provider = providerURL
	return s.SaveDefaultTarget()
}

// Serializes the default target to disk. Call after changing any default
// target settings.
func (s *Store) SaveDefaultTarget() error {
	// Some basic validation.
	err := s.defaultTarget.Validate()
	if err != nil {
		return err
	}

	// Save.
	confc := s.db.Collection("conf")

	b, err := yaml.Marshal(s.defaultTarget)
	if err != nil {
		return err
	}

	err = fdb.WriteBytes(confc, "target", b)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) loadTargets() error {
	s.targets = map[string]*Target{}

	// default target
	confc := s.db.Collection("conf")

	dtgt, err := s.validateTargetInner("target", confc, true)
	if err == nil {
		dtgt.Satisfy.Names = nil
		dtgt.Satisfy.ReducedNames = nil
		dtgt.Request.Names = nil
		s.defaultTarget = dtgt
	} else {
		s.defaultTarget = &Target{}
	}

	// targets
	c := s.db.Collection("desired")

	desiredKeys, err := c.List()
	if err != nil {
		return err
	}

	for _, desiredKey := range desiredKeys {
		err := s.validateTarget(desiredKey, c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *Store) validateTarget(desiredKey string, c *fdb.Collection) error {
	tgt, err := s.validateTargetInner(desiredKey, c, false)
	if err != nil {
		return err
	}

	s.targets[desiredKey] = tgt
	return nil
}

func (s *Store) validateTargetInner(desiredKey string, c *fdb.Collection, loadingDefault bool) (*Target, error) {
	b, err := fdb.Bytes(c.Open(desiredKey))
	if err != nil {
		return nil, err
	}

	var tgt *Target
	if loadingDefault {
		tgt = &Target{}
	} else {
		tgt = s.defaultTarget.CopyGeneric()
	}

	err = yaml.Unmarshal(b, tgt)
	if err != nil {
		return nil, err
	}

	if len(tgt.Satisfy.Names) == 0 {
		if len(tgt.LegacyNames) > 0 {
			tgt.Satisfy.Names = tgt.LegacyNames
		} else {
			tgt.Satisfy.Names = []string{desiredKey}
		}
	}

	if tgt.Request.Provider == "" {
		tgt.Request.Provider = tgt.LegacyProvider
	}

	err = normalizeNames(tgt.Satisfy.Names)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %s: %v", desiredKey, err)
	}

	if len(tgt.Request.Names) == 0 {
		tgt.Request.Names = tgt.Satisfy.Names
		tgt.Request.implicitNames = true
	}

	tgt.Request.Account, err = s.getAccountByProviderString(tgt.Request.Provider)
	if err != nil {
		return nil, err
	}

	// TODO: tgt.Priority
	return tgt, nil
}

func normalizeNames(names []string) error {
	for i := range names {
		n := strings.TrimSuffix(strings.ToLower(names[i]), ".")
		if !validHostname(n) {
			return fmt.Errorf("invalid hostname: %q", n)
		}

		names[i] = n
	}

	return nil
}

type targetSorter []*Target

func (ts targetSorter) Len() int {
	return len(ts)
}

func (ts targetSorter) Swap(i, j int) {
	ts[i], ts[j] = ts[j], ts[i]
}

func (ts targetSorter) Less(i, j int) bool {
	return targetGt(ts[j], ts[i])
}

func (s *Store) disjoinTargets() error {
	var targets []*Target

	for _, tgt := range s.targets {
		targets = append(targets, tgt)
	}

	sort.Stable(sort.Reverse(targetSorter(targets)))

	// Bijective hostname-target mapping.
	hostnameTargetMapping := map[string]*Target{}
	for _, tgt := range targets {
		tgt.Satisfy.ReducedNames = nil
		for _, name := range tgt.Satisfy.Names {
			_, exists := hostnameTargetMapping[name]
			if !exists {
				hostnameTargetMapping[name] = tgt
				tgt.Satisfy.ReducedNames = append(tgt.Satisfy.ReducedNames, name)
			}
		}
	}

	s.hostnameTargetMapping = hostnameTargetMapping
	for name, tgt := range s.hostnameTargetMapping {
		log.Debugf("disjoint hostname mapping: %s -> %v", name, tgt)
	}

	return nil
}

// Ensure that a registration exists and is ready to use for the default
// provider.
func (s *Store) EnsureRegistration() error {
	a, err := s.getAccountByProviderString("")
	if err != nil {
		return err
	}

	cl := s.getAccountClient(a)
	return solver.AssistedUpsertRegistration(cl, nil, context.TODO())
}

func (s *Store) getAccountByProviderString(p string) (*Account, error) {
	if p == "" && s.defaultTarget != nil {
		p = s.defaultTarget.Request.Provider
	}

	if p == "" {
		p = acmeendpoints.DefaultEndpoint.DirectoryURL
	}

	if !acmeapi.ValidURL(p) {
		return nil, fmt.Errorf("provider URI is not a valid HTTPS URL")
	}

	for _, a := range s.accounts {
		if a.MatchesURL(p) {
			return a, nil
		}
	}

	return s.createNewAccount(p)
}

func (s *Store) createNewAccount(baseURL string) (*Account, error) {
	u, err := accountURLPart(baseURL)
	if err != nil {
		return nil, err
	}

	pk, keyID, err := s.createKey(s.db.Collection("accounts/"+u), &TargetRequestKey{}) // TODO
	if err != nil {
		return nil, err
	}

	a := &Account{
		PrivateKey: pk,
		BaseURL:    baseURL,
	}

	s.accounts[u+"/"+keyID] = a

	return a, nil
}

func (s *Store) createNewCertKey(trk *TargetRequestKey) (crypto.PrivateKey, *Key, error) {
	pk, keyID, err := s.createKey(s.db.Collection("keys"), trk)
	if err != nil {
		return nil, nil, err
	}

	k := &Key{
		ID: keyID,
	}

	s.keys[keyID] = k

	return pk, k, nil
}

func (s *Store) createKey(c *fdb.Collection, trk *TargetRequestKey) (pk crypto.PrivateKey, keyID string, err error) {
	switch trk.Type {
	default:
		fallthrough // ...
	case "", "rsa":
		pk, err = rsa.GenerateKey(rand.Reader, clampRSAKeySize(trk.RSASize))
	case "ecdsa":
		pk, err = ecdsa.GenerateKey(getECDSACurve(trk.ECDSACurve), rand.Reader)
	}

	if err != nil {
		return
	}

	keyID, err = s.saveKeyUnderID(c, pk)
	return
}

// Give a PEM-encoded key file, imports the key into the store. If the key is
// already installed, returns nil.
func (s *Store) ImportKey(r io.Reader) error {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	pk, err := acmeutils.LoadPrivateKey(data)
	if err != nil {
		return err
	}

	keyID, err := determineKeyIDFromKey(pk)
	if err != nil {
		return err
	}

	c := s.db.Collection("keys/" + keyID)

	f, err := c.Open("privkey")
	if err == nil {
		f.Close()
		return nil
	}

	ff, err := c.Create("privkey")
	if err != nil {
		return err
	}
	defer ff.CloseAbort()

	_, err = ff.Write(data)
	if err != nil {
		return err
	}

	ff.Close()
	return nil
}

// Given a certificate URL, imports the certificate into the store. The
// certificate will be retrirved on the next reconcile. If a certificate with
// that URL already exists, this is a no-op and returns nil.
func (s *Store) ImportCertificate(url string) error {
	certID := determineCertificateID(url)
	_, ok := s.certs[certID]
	if ok {
		return nil
	}

	return fdb.WriteBytes(s.db.Collection("certs/"+certID), "url", []byte(url))
}

// Given an account private key and the provider directory URL, imports that account key.
// If the account already exists and has a private key, this is a no-op and returns nil.
func (s *Store) ImportAccountKey(providerURL string, privateKey interface{}) error {
	accountID, err := determineAccountID(providerURL, privateKey)
	if err != nil {
		return err
	}

	_, ok := s.accounts[accountID]
	if ok {
		return nil
	}

	err = s.saveKey(s.db.Collection("accounts/"+accountID), privateKey)
	return err
}

// Saves a key as a file named "privkey" inside the given collection.
func (s *Store) saveKey(c *fdb.Collection, privateKey interface{}) error {
	var kb []byte
	var hdr string

	switch v := privateKey.(type) {
	case *rsa.PrivateKey:
		kb = x509.MarshalPKCS1PrivateKey(v)
		hdr = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		var err error
		kb, err = x509.MarshalECPrivateKey(v)
		if err != nil {
			return err
		}
		hdr = "EC PRIVATE KEY"
	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	f, err := c.Create("privkey")
	if err != nil {
		return err
	}
	defer f.CloseAbort()

	err = pem.Encode(f, &pem.Block{
		Type:  hdr,
		Bytes: kb,
	})
	if err != nil {
		return err
	}

	f.Close()
	return nil
}

// Save a private key inside a key ID collection under the given collection.
func (s *Store) saveKeyUnderID(c *fdb.Collection, privateKey interface{}) (keyID string, err error) {
	keyID, err = determineKeyIDFromKey(privateKey)
	if err != nil {
		return
	}

	err = s.saveKey(c.Collection(keyID), privateKey)
	return
}

func (s *Store) linkTargets() error {
	var updatedHostnames []string

	for name, tgt := range s.hostnameTargetMapping {
		c, err := s.findBestCertificateSatisfying(tgt)
		if err != nil {
			log.Debugf("could not find certificate satisfying %v: %v", tgt, err)
			continue
		}

		log.Tracef("relink: best certificate satisfying %v is %v", tgt, c)
		lt := "certs/" + c.ID()
		lnk, err := s.db.Collection("live").ReadLink(name)
		log.Tracef("link: %s: %v %q %q", name, err, lnk.Target, lt)
		if err != nil || lnk.Target != lt {
			log.Debugf("relinking: %v -> %v (was %v)", name, lt, lnk.Target)
			err = s.db.Collection("live").WriteLink(name, fdb.Link{Target: lt})
			if err != nil {
				return err
			}

			updatedHostnames = append(updatedHostnames, name)
		}
	}

	err := notify.Notify("", s.path, updatedHostnames) // ignore error
	log.Errore(err, "failed to call notify hooks")

	return nil
}

// Return a string containing a summary of the stored state.
func (s *Store) StatusString() (string, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Settings:\n")
	fmt.Fprintf(&buf, "  ACME_STATE_DIR: %s\n", s.path)
	fmt.Fprintf(&buf, "  ACME_HOOKS_DIR: %s\n", notify.DefaultHookPath)
	fmt.Fprintf(&buf, "  Default directory URL: %s\n", s.defaultTarget.Request.Provider)
	fmt.Fprintf(&buf, "  Preferred key type: %v\n", &s.defaultTarget.Request.Key)
	fmt.Fprintf(&buf, "  Additional webroots:\n")
	for _, wr := range s.defaultTarget.Request.Challenge.WebrootPaths {
		fmt.Fprintf(&buf, "    %s\n", wr)
	}

	fmt.Fprintf(&buf, "\nAvailable accounts:\n")
	for _, a := range s.accounts {
		fmt.Fprintf(&buf, "  %v\n", a)
	}

	fmt.Fprintf(&buf, "\n")
	for _, t := range s.targets {
		fmt.Fprintf(&buf, "%v:\n", t)
		c, err := s.findBestCertificateSatisfying(t)
		if err != nil {
			fmt.Fprintf(&buf, "  error: %v\n", err)
			continue
		}

		renewStr := ""
		if s.certificateNeedsRenewing(c) {
			renewStr = " needs-renewing"
		}

		fmt.Fprintf(&buf, "  best: %v%s\n", c, renewStr)
	}

	if s.haveUncachedCertificates() {
		fmt.Fprintf(&buf, "\nThere are uncached certificates.\n")
	}

	return buf.String(), nil
}

// Runs the reconciliation operation and reloads state.
func (s *Store) Reconcile() error {
	err := s.reconcile()

	err2 := s.load()
	if err == nil {
		err = err2
	} else {
		log.Errore(err2, "failed to reload after reconciliation")
	}

	return err
}

// Error associated with a specific target, for clarity of error messages.
type TargetSpecificError struct {
	Target *Target
	Err    error
}

func (tse *TargetSpecificError) Error() string {
	return fmt.Sprintf("error satisfying target %v: %v", tse.Target, tse.Err)
}

// Used to return multiple errors, for example when several targets cannot be
// reconciled. This prevents one failing target from blocking others.
type MultiError []error

func (merr MultiError) Error() string {
	s := ""
	for _, e := range merr {
		if s != "" {
			s += "; \n"
		}
		s += e.Error()
	}
	return "the following errors occurred:\n" + s
}

func (s *Store) reconcile() error {
	if s.haveUncachedCertificates() {
		log.Debug("there are uncached certificates - downloading them")

		err := s.downloadUncachedCertificates()
		if err != nil {
			return err
		}

		log.Debug("reloading after downloading uncached certificates")
		err = s.load()
		log.Debugf("finished reloading after downloading uncached certificates (%v)", err)
		if err != nil {
			return err
		}
		if s.haveUncachedCertificates() {
			log.Error("failed to download all uncached certificates")
			return fmt.Errorf("cannot obtain one or more uncached certificates")
		}
	}

	err := s.processPendingRevocations()
	log.Errore(err, "could not process pending revocations")

	log.Debugf("now processing targets")
	var merr MultiError
	for _, t := range s.targets {
		c, err := s.findBestCertificateSatisfying(t)
		log.Debugf("best certificate satisfying %v is %v, err=%v", t, c, err)
		if err == nil && !s.certificateNeedsRenewing(c) {
			log.Debug("have best certificate which does not need renewing, skipping target")
			continue
		}

		log.Debugf("requesting certificate for target %v", t)
		err = s.requestCertificateForTarget(t)
		log.Errore(err, "failed to request certificate for target ", t)
		if err != nil {
			// do not block satisfaction of other targets just because one fails;
			// collect errors and return them as one
			merr = append(merr, &TargetSpecificError{
				Target: t,
				Err:    err,
			})
		}
	}
	log.Debugf("done processing targets, reconciliation complete, %d errors occurred", len(merr))

	if len(merr) != 0 {
		return merr
	}

	return nil
}

func (s *Store) haveUncachedCertificates() bool {
	for _, c := range s.certs {
		if !c.Cached {
			return true
		}
	}
	return false
}

func (s *Store) downloadUncachedCertificates() error {
	for _, c := range s.certs {
		if c.Cached {
			continue
		}

		err := s.downloadCertificate(c)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) downloadCertificate(c *Certificate) error {
	log.Debugf("downloading certificate %v", c)

	col := s.db.Collection("certs/" + c.ID())
	if col == nil {
		return fmt.Errorf("cannot get collection")
	}

	cl := acmeapi.Client{}

	crt := acmeapi.Certificate{
		URI: c.URL,
	}

	err := cl.WaitForCertificate(&crt, context.TODO())
	if err != nil {
		return err
	}

	if len(crt.Certificate) == 0 {
		return fmt.Errorf("nil certificate?")
	}

	fcert, err := col.Create("cert")
	if err != nil {
		return err
	}
	defer fcert.CloseAbort()

	fchain, err := col.Create("chain")
	if err != nil {
		return err
	}
	defer fchain.CloseAbort()

	ffullchain, err := col.Create("fullchain")
	if err != nil {
		return err
	}
	defer ffullchain.CloseAbort()

	err = pem.Encode(io.MultiWriter(fcert, ffullchain), &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crt.Certificate,
	})
	if err != nil {
		return err
	}

	for _, ec := range crt.ExtraCertificates {
		err = pem.Encode(io.MultiWriter(fchain, ffullchain), &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: ec,
		})
		if err != nil {
			return err
		}
	}

	fcert.Close()
	fchain.Close()
	ffullchain.Close()

	c.Certificates = nil
	c.Certificates = append(c.Certificates, crt.Certificate)
	c.Certificates = append(c.Certificates, crt.ExtraCertificates...)
	c.Cached = true

	return nil
}

// Try to revoke the certificate with the given certificate ID.
// If a key ID is given, revoke all certificates with using key ID.
func (s *Store) RevokeByCertificateOrKeyID(certID string) error {
	c, ok := s.certs[certID]
	if !ok {
		return s.revokeByKeyID(certID)
	}

	if c.Revoked {
		log.Warnf("%v already revoked", c)
		return nil
	}

	col := s.db.Collection("certs/" + c.ID())
	err := fdb.CreateEmpty(col, "revoke")
	if err != nil {
		return err
	}

	c.RevocationDesired = true
	return nil
}

func (s *Store) revokeByKeyID(keyID string) error {
	k, ok := s.keys[keyID]
	if !ok {
		return fmt.Errorf("cannot find certificate or key with given ID: %q", keyID)
	}

	var merr MultiError
	for _, c := range s.certs {
		if c.Key != k {
			continue
		}

		err := s.RevokeByCertificateOrKeyID(c.ID())
		if err != nil {
			merr = append(merr, fmt.Errorf("failed to mark %v for revocation: %v", c, err))
		}
	}

	if len(merr) > 0 {
		return merr
	}

	return nil
}

func (s *Store) processPendingRevocations() error {
	var me MultiError

	for _, c := range s.certs {
		if c.Revoked || !c.RevocationDesired {
			continue
		}

		err := s.revokeCertificate(c)
		if err != nil {
			me = append(me, fmt.Errorf("failed to revoke %v: %v", c, err))
			continue
		}
	}

	if len(me) > 0 {
		return me
	}

	return nil
}

func (s *Store) revokeCertificate(c *Certificate) error {
	err := s.revokeCertificateInner(c)
	if err != nil {
		return err
	}

	col := s.db.Collection("certs/" + c.ID())
	fdb.CreateEmpty(col, "revoked") // ignore errors

	c.Revoked = true
	return nil
}

func (s *Store) revokeCertificateInner(c *Certificate) error {
	if len(c.Certificates) == 0 {
		return fmt.Errorf("no certificates in certificate: %v", c)
	}

	endCertificate := c.Certificates[0]

	crt, err := x509.ParseCertificate(endCertificate)
	if err != nil {
		return err
	}

	// Get the endpoint which issued the certificate.
	endpoint, err := acmeendpoints.CertificateToEndpoint(s.getGenericClient(), crt, context.TODO())
	if err != nil {
		return fmt.Errorf("could not map certificate to endpoint: %v", err)
	}

	// In order to revoke a certificate, one needs either the private
	// key of the certificate, or the account key with authorizations
	// for all names on the certificate. Try and find the private key
	// first.
	var client *acmeapi.Client
	var revocationKey crypto.PrivateKey
	if c.Key != nil {
		revocationKey = c.Key.PrivateKey
		client = &acmeapi.Client{
			DirectoryURL: endpoint.DirectoryURL,
		}
	}

	if revocationKey == nil {
		acct, err := s.getAccountByProviderString(endpoint.DirectoryURL)
		if err != nil {
			return err
		}

		client = s.getAccountClient(acct)

		// If we have no private key for the certificate, obtain all necessary
		// authorizations.
		err = s.getRevocationAuthorizations(acct, crt)
		if err != nil {
			return err
		}
	}

	return client.Revoke(endCertificate, revocationKey, context.TODO())
}

func (s *Store) getRevocationAuthorizations(acct *Account, crt *x509.Certificate) error {
	log.Debugf("obtaining authorizations to facilitate revocation")
	return s.obtainNecessaryAuthorizations(crt.DNSNames, acct, &s.defaultTarget.Request.Challenge)
}

func (s *Store) findBestCertificateSatisfying(t *Target) (*Certificate, error) {
	var bestCert *Certificate

	for _, c := range s.certs {
		if s.doesCertSatisfy(c, t) {
			isBetterThan, err := s.certBetterThan(c, bestCert)
			if err != nil {
				return nil, err
			}

			if isBetterThan {
				log.Tracef("findBestCertificateSatisfying: %v > %v", c, bestCert)
				bestCert = c
			} else {
				log.Tracef("findBestCertificateSatisfying: %v <= %v", c, bestCert)
			}
		}
	}

	if bestCert == nil {
		return nil, fmt.Errorf("no certificate satisfies this target")
	}

	return bestCert, nil
}

func (s *Store) doesCertSatisfy(c *Certificate, t *Target) bool {
	if c.Revoked {
		log.Debugf("certificate %v cannot satisfy %v because it is revoked", c, t)
		return false
	}

	if len(c.Certificates) == 0 {
		log.Debugf("certificate %v cannot satisfy %v because it has no actual certificates", c, t)
		return false
	}

	if c.Key == nil {
		// a certificate we don't have the key for is unusable.
		log.Debugf("certificate %v cannot satisfy %v because we do not have a key for it", c, t)
		return false
	}

	cc, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		log.Debugf("certificate %v cannot satisfy %v because we cannot parse it: %v", c, t, err)
		return false
	}

	names := map[string]struct{}{}
	for _, name := range cc.DNSNames {
		names[name] = struct{}{}
	}

	for _, name := range t.Satisfy.Names {
		_, ok := names[name]
		if !ok {
			log.Debugf("certificate %v cannot satisfy %v because required hostname %#v is not listed on it: %#v", c, t, name, cc.DNSNames)
			return false
		}
	}

	log.Debugf("certificate %v satisfies %v", c, t)
	return true
}

func (s *Store) certificateNeedsRenewing(c *Certificate) bool {
	if len(c.Certificates) == 0 {
		log.Debugf("not renewing %v because it has no actual certificates (???)", c)
		return false
	}

	cc, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		log.Debugf("not renewing %v because its end certificate is unparseable", c)
		return false
	}

	renewSpan := renewTime(cc.NotBefore, cc.NotAfter)
	needsRenewing := !time.Now().Before(renewSpan)

	log.Debugf("%v needsRenewing=%v notAfter=%v", c, needsRenewing, cc.NotAfter)
	return needsRenewing
}

func renewTime(notBefore, notAfter time.Time) time.Time {
	validityPeriod := notAfter.Sub(notBefore)
	renewSpan := validityPeriod / 3
	if renewSpan > 30*24*time.Hour { // close enough to 30 days
		renewSpan = 30 * 24 * time.Hour
	}

	return notAfter.Add(-renewSpan)
}

func (s *Store) certBetterThan(a *Certificate, b *Certificate) (bool, error) {
	if b == nil || a == nil {
		return (b == nil && a != nil), nil
	}

	if len(a.Certificates) == 0 || len(b.Certificates) == 0 {
		return false, fmt.Errorf("need two certificates to compare")
	}

	ac, err := x509.ParseCertificate(a.Certificates[0])
	bc, err2 := x509.ParseCertificate(b.Certificates[0])
	if err != nil || err2 != nil {
		if err == nil && err2 != nil {
			log.Tracef("certBetterThan: parseable certificate is better than non-parseable certificate")
			return true, nil
		}
		return false, nil
	}

	isAfter := ac.NotAfter.After(bc.NotAfter)
	log.Tracef("certBetterThan: (%v > %v)=%v", ac.NotAfter, bc.NotAfter, isAfter)
	return isAfter, nil
}

func (s *Store) getGenericClient() *acmeapi.Client {
	return &acmeapi.Client{}
}

func (s *Store) getAccountClient(a *Account) *acmeapi.Client {
	cl := s.getGenericClient()
	cl.AccountInfo.AccountKey = a.PrivateKey
	cl.DirectoryURL = a.BaseURL
	return cl
}

func (s *Store) getPriorKey(publicKey crypto.PublicKey) (crypto.PrivateKey, error) {
	// Returning an error here short circuits. If any errors occur, return (nil,nil).

	keyID, err := determineKeyIDFromPublicKey(publicKey)
	if err != nil {
		log.Errore(err, "failed to get key ID from public key")
		return nil, nil
	}

	if _, ok := s.keys[keyID]; !ok {
		log.Infof("failed to find key ID wanted by proofOfPossession: %s", keyID)
		return nil, nil // unknown key
	}

	c := s.db.Collection("keys/" + keyID)

	f, err := c.Open("privkey")
	if err != nil {
		log.Errore(err, "failed to open privkey for key with ID: ", keyID)
		return nil, nil
	}
	defer f.Close()

	b, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	privateKey, err := acmeutils.LoadPrivateKey(b)
	if err != nil {
		log.Errore(err, "failed to load private key for key with ID: ", keyID)
		return nil, nil
	}

	log.Infof("found key for proofOfPossession: %s", keyID)
	return privateKey, nil
}

func (s *Store) obtainAuthorization(name string, a *Account, trc *TargetRequestChallenge) error {
	cl := s.getAccountClient(a)

	ccfg := responder.ChallengeConfig{
		WebPaths:     trc.WebrootPaths,
		HTTPPorts:    trc.HTTPPorts,
		PriorKeyFunc: s.getPriorKey,
	}

	az, err := solver.Authorize(cl, name, ccfg, nil, context.TODO())
	if err != nil {
		return err
	}

	err = cl.LoadAuthorization(az, context.TODO())
	if err != nil {
		// Try proceeding anyway.
		return nil
	}

	c := s.db.Collection("accounts/" + a.ID() + "/authorizations/" + name)

	err = fdb.WriteBytes(c, "expiry", []byte(az.Expires.Format(time.RFC3339)))
	if err != nil {
		return err
	}

	err = fdb.WriteBytes(c, "url", []byte(az.URI))
	if err != nil {
		return err
	}

	saz := &Authorization{
		URL:     az.URI,
		Name:    az.Identifier.Value,
		Expires: az.Expires,
	}

	a.Authorizations[az.Identifier.Value] = saz

	return nil
}

var (
	oidTLSFeature          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	mustStapleFeatureValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

func (s *Store) createCSR(t *Target) ([]byte, error) {
	csr := &x509.CertificateRequest{
		DNSNames: t.Request.Names,
	}

	if t.Request.OCSPMustStaple {
		csr.Extensions = append(csr.Extensions, pkix.Extension{
			Id:    oidTLSFeature,
			Value: mustStapleFeatureValue,
		})
	}

	pk, _, err := s.createNewCertKey(&t.Request.Key)
	if err != nil {
		return nil, err
	}

	csr.SignatureAlgorithm, err = signatureAlgorithmFromKey(pk)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand.Reader, csr, pk)
}

func signatureAlgorithmFromKey(pk crypto.PrivateKey) (x509.SignatureAlgorithm, error) {
	switch pk.(type) {
	case *rsa.PrivateKey:
		return x509.SHA256WithRSA, nil
	case *ecdsa.PrivateKey:
		return x509.ECDSAWithSHA256, nil
	default:
		return x509.UnknownSignatureAlgorithm, fmt.Errorf("unknown key type %T", pk)
	}
}

func (s *Store) obtainNecessaryAuthorizations(names []string, account *Account, ccfg *TargetRequestChallenge) error {
	authsNeeded, err := s.determineNecessaryAuthorizations(names, account)
	if err != nil {
		return err
	}

	for _, name := range authsNeeded {
		log.Debugf("trying to obtain authorization for %#v", name)
		err := s.obtainAuthorization(name, account, ccfg)
		if err != nil {
			log.Errore(err, "could not obtain authorization for ", name)
			return err
		}
	}

	return nil
}

func (s *Store) requestCertificateForTarget(t *Target) error {
	//return fmt.Errorf("not requesting certificate")
	cl := s.getAccountClient(t.Request.Account)

	err := solver.AssistedUpsertRegistration(cl, nil, context.TODO())
	if err != nil {
		return err
	}

	err = s.obtainNecessaryAuthorizations(t.Request.Names, t.Request.Account, &t.Request.Challenge)
	if err != nil {
		return err
	}

	csr, err := s.createCSR(t)
	if err != nil {
		return err
	}

	log.Debugf("requesting certificate for %v", t)
	acrt, err := cl.RequestCertificate(csr, context.TODO())
	if err != nil {
		log.Errore(err, "could not request certificate")
		return err
	}

	crt := &Certificate{
		URL: acrt.URI,
	}

	certID := crt.ID()

	c := s.db.Collection("certs/" + certID)

	err = fdb.WriteBytes(c, "url", []byte(crt.URL))
	if err != nil {
		log.Errore(err, "could not write certificate URL")
		return err
	}

	s.certs[certID] = crt

	log.Debugf("downloading certificate which was just requested: %#v", crt.URL)
	err = s.downloadCertificate(crt)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) determineNecessaryAuthorizations(names []string, a *Account) ([]string, error) {
	needed := map[string]struct{}{}
	for _, n := range names {
		needed[n] = struct{}{}
	}

	for _, auth := range a.Authorizations {
		if auth.IsValid() {
			delete(needed, auth.Name)
		}
	}

	// preserve the order of the names in case the user considers that important
	var neededs []string
	for _, name := range names {
		if _, ok := needed[name]; ok {
			neededs = append(neededs, name)
		}
	}

	return neededs, nil
}

// Update targets to remove any mention of hostname from all targets. The
// targets are resaved to disk.
func (s *Store) RemoveTargetHostname(hostname string) error {
	for fn, tgt := range s.targets {
		if !containsName(tgt.Satisfy.Names, hostname) {
			continue
		}

		tgt.Satisfy.Names = removeStringFromList(tgt.Satisfy.Names, hostname)
		tgt.Request.Names = removeStringFromList(tgt.Request.Names, hostname)

		if len(tgt.Satisfy.Names) == 0 {
			err := s.deleteTarget(fn)
			if err != nil {
				return err
			}

			continue
		}

		err := s.serializeTarget(fn, tgt)
		if err != nil {
			return err
		}
	}

	return nil
}

func removeStringFromList(ss []string, s string) []string {
	var r []string
	for _, x := range ss {
		if x != s {
			r = append(r, x)
		}
	}
	return r
}

// Add a new target, saving it to disk.
func (s *Store) AddTarget(tgt Target) error {
	if len(tgt.Satisfy.Names) == 0 {
		return nil
	}

	for _, n := range tgt.Satisfy.Names {
		if !validHostname(n) {
			return fmt.Errorf("invalid hostname: %v", n)
		}
	}

	t := s.findTargetWithAllNames(tgt.Satisfy.Names)
	if t != nil {
		return nil
	}

	return s.serializeTarget(s.makeUniqueTargetName(&tgt), &tgt)
}

func (s *Store) serializeTarget(filename string, tgt *Target) error {
	tcopy := *tgt

	// don't serialize default request names list
	if tcopy.Request.implicitNames {
		tcopy.Request.Names = nil
	}

	b, err := yaml.Marshal(&tcopy)
	if err != nil {
		return err
	}

	c := s.db.Collection("desired")
	return fdb.WriteBytes(c, filename, b)
}

func (s *Store) deleteTarget(filename string) error {
	return s.db.Collection("desired").Delete(filename)
}

func (s *Store) findTargetWithAllNames(names []string) *Target {
T:
	for _, t := range s.targets {
		for _, n := range names {
			if !containsName(t.Satisfy.Names, n) {
				continue T
			}
		}

		return t
	}
	return nil
}

func (s *Store) makeUniqueTargetName(tgt *Target) string {
	// Unfortunately we can't really check if the first hostname exists as a filename
	// and use another name instead as this would create all sorts of race conditions.
	// We have to use a random name.

	nprefix := ""
	if len(tgt.Satisfy.Names) > 0 {
		nprefix = tgt.Satisfy.Names[0] + "-"
	}

	b := uuid.NewV4().Bytes()
	str := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))

	return nprefix + str
}

// © 2015—2016 Hugo Landau <hlandau@devever.net>    MIT License
