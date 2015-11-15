package storage

import "fmt"
import "github.com/hlandau/xlog"
import "strings"
import "net/url"
import "encoding/pem"
import "crypto/x509"
import "crypto/sha256"
import "encoding/base32"
import "github.com/hlandau/acme/acmeapi"
import "github.com/hlandau/acme/solver"
import "github.com/hlandau/acme/fdb"
import "github.com/hlandau/acme/notify"
import "io"
import "crypto/rsa"
import "crypto/rand"
import "crypto"
import "time"
import "gopkg.in/yaml.v2"
import "regexp"
import "golang.org/x/net/context"
import "github.com/satori/go.uuid"

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
	u, err := accountURLPart(a.BaseURL)
	log.Panice(err)

	keyID, err := determineKeyIDFromKey(a.PrivateKey)
	log.Panice(err)

	return u + "/" + keyID
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

func (a *Authorization) IsValid() bool {
	return time.Now().Before(a.Expires)
}

// Represents a stored target descriptor.
type Target struct {
	// N. List of SANs to place on any obtained certificate. May include
	// hostnames (and maybe one day SRV-IDs). May include wildcard hostnames.
	Names []string `yaml:"names"`

	// N. If this is a substring of a known account ID, that account is used.
	// Otherwise, if this is the URL of an ACME server, or the first part of an
	// account ID or a substring thereof, an account for that server is used.
	// This relies on a list of known ACME servers.
	//
	// Valid examples:
	//   "https://acme-staging.letsencrypt.org/directory"
	//   "https://acme-live.letsencrypt.org/directory"
	//   "asl39aldskl"
	//   "acme-staging.letsencrypt.org%2fdirectory/asl39"
	//   "acme-staging.letsencrypt.org%2fdirectory"
	//   "acme-staging"
	Provider string `yaml:"provider,omitempty"`

	// D. Account to use, determined via Provider string.
	Account *Account `yaml:"-"`

	// N. Priority as a symlink target.
	Priority int `yaml:"priority,omitempty"`
}

// Represents stored certificate information.
type Certificate struct {
	// N. URL from which the certificate can be retrieved.
	URL string

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

func (c *Certificate) ID() string {
	return getCertID(c.URL)
}

// Represents a stored key.
type Key struct {
	// N. The key. Not kept in memory as there's no need to.

	// D. ID: Derived from the key itself.
	ID string

	// D. Path: formed from ID.
}

// ACME client store.
type Store struct {
	db *fdb.DB

	path            string
	referencedCerts map[string]struct{}
	certs           map[string]*Certificate
	accounts        map[string]*Account
	keys            map[string]*Key
	targets         map[string]*Target
	defaultBaseURL  string
}

const RecommendedPath = "/var/lib/acme"

var storePermissions = []fdb.Permission{
	{Path: ".", DirMode: 0755, FileMode: 0644},
	{Path: "accounts", DirMode: 0700, FileMode: 0600},
	{Path: "desired", DirMode: 0755, FileMode: 0644},
	{Path: "live", DirMode: 0755, FileMode: 0644},
	{Path: "certs", DirMode: 0755, FileMode: 0644},
	{Path: "keys", DirMode: 0700, FileMode: 0600},
	//{Path: "policy/default", DirMode: 0755, FileMode: 0644},
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
		db:             db,
		defaultBaseURL: acmeapi.DefaultBaseURL,
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

	err = s.linkTargets()
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) loadAccounts() error {
	c := s.db.Collection("accounts")
	if c == nil {
		return fmt.Errorf("cannot open accounts collection")
	}

	serverNames, err := c.List()
	if err != nil {
		return err
	}

	s.accounts = map[string]*Account{}
	for _, serverName := range serverNames {
		sc := c.Collection(serverName)
		if sc == nil {
			return fmt.Errorf("cannot open account collection: %v", serverName)
		}

		accountNames, err := sc.List()
		if err != nil {
			return err
		}

		for _, accountName := range accountNames {
			ac := sc.Collection(accountName)
			if ac == nil {
				return fmt.Errorf("cannot open account: %v/%v", serverName, accountName)
			}

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

	pk, err := acmeapi.LoadPrivateKey(f)
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
	if ac == nil {
		return fmt.Errorf("cannot open authorizations collection")
	}

	auths, err := ac.List()
	if err != nil {
		return err
	}

	for _, auth := range auths {
		auc := ac.Collection(auth)
		if auc == nil {
			return fmt.Errorf("cannot open authorization")
		}
		err := s.validateAuthorization(account, auth, auc)
		if err != nil {
			return err
		}
	}

	return nil
}

func validURI(u string) bool {
	ur, err := url.Parse(u)
	if err != nil {
		return false
	}
	return ur.Scheme == "https"
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
	if !validURI(azURL) {
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
	if c == nil {
		return fmt.Errorf("cannot open keys collection")
	}

	keyIDs, err := c.List()
	if err != nil {
		return err
	}

	for _, keyID := range keyIDs {
		kc := c.Collection(keyID)
		if kc == nil {
			return fmt.Errorf("cannot open key collection: %v", keyID)
		}

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

	pk, err := acmeapi.LoadPrivateKey(f)
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
		ID: actualKeyID,
	}

	s.keys[actualKeyID] = k

	return nil
}

func (s *Store) loadCerts() error {
	s.certs = map[string]*Certificate{}

	c := s.db.Collection("certs")
	if c == nil {
		return fmt.Errorf("cannot open certs collection")
	}

	certIDs, err := c.List()
	if err != nil {
		return err
	}

	for _, certID := range certIDs {
		kc := c.Collection(certID)
		if kc == nil {
			return fmt.Errorf("cannot open cert collection: %v", certID)
		}

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
	if !validURI(ss) {
		return fmt.Errorf("certificate has invalid URI")
	}

	actualCertID := getCertID(ss)
	if certID != actualCertID {
		return fmt.Errorf("cert ID mismatch: %#v != %#v", certID, actualCertID)
	}

	crt := &Certificate{
		URL:          ss,
		Certificates: nil,
		Cached:       false,
	}

	fullchain, err := fdb.Bytes(c.Open("fullchain"))
	if err == nil {
		certs, err := acmeapi.LoadCertificates(fullchain)
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
			err := c.WriteLink("privkey", fdb.Link{"keys/" + keyID + "/privkey"})
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

func getCertID(url string) string {
	h := sha256.New()
	h.Write([]byte(url))
	b := h.Sum(nil)
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))
}

func (s *Store) loadTargets() error {
	s.targets = map[string]*Target{}

	c := s.db.Collection("desired")
	if c == nil {
		return fmt.Errorf("cannot open desired collection")
	}

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
	b, err := fdb.Bytes(c.Open(desiredKey))
	if err != nil {
		return err
	}

	tgt := &Target{}
	err = yaml.Unmarshal(b, tgt)
	if err != nil {
		return err
	}

	if len(tgt.Names) == 0 {
		tgt.Names = []string{desiredKey}
	}

	for _, n := range tgt.Names {
		n = strings.ToLower(n)
		n = strings.TrimSuffix(n, ".")
		if !validHostname(n) {
			return fmt.Errorf("invalid hostname in target %s: %s", desiredKey, n)
		}
	}

	tgt.Account, err = s.getAccountByProviderString(tgt.Provider)
	if err != nil {
		return err
	}

	//tgt.Priority
	s.targets[desiredKey] = tgt

	return nil
}

var re_hostname = regexp.MustCompilePOSIX(`^([a-z0-9_-]+\.)*[a-z0-9_-]+$`)

func validHostname(name string) bool {
	return re_hostname.MatchString(name)
}

func (s *Store) getAccountByProviderString(p string) (*Account, error) {
	// TODO
	if len(s.accounts) > 0 {
		for _, a := range s.accounts {
			return a, nil
		}
	}

	return s.createNewAccount(acmeapi.DefaultBaseURL)
}

func (s *Store) createNewAccount(baseURL string) (*Account, error) {
	u, err := accountURLPart(baseURL)
	if err != nil {
		return nil, err
	}

	pk, keyID, err := s.createKey(s.db.Collection("accounts/" + u))
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

func (s *Store) createNewCertKey() (crypto.PrivateKey, *Key, error) {
	pk, keyID, err := s.createKey(s.db.Collection("keys"))
	if err != nil {
		return nil, nil, err
	}

	k := &Key{
		ID: keyID,
	}

	s.keys[keyID] = k

	return pk, k, nil
}

func (s *Store) createKey(c *fdb.Collection) (pk *rsa.PrivateKey, keyID string, err error) {
	if c == nil {
		err = fmt.Errorf("cannot obtain key collection")
		return
	}

	pk, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	keyID, err = determineKeyIDFromKey(pk)
	if err != nil {
		return
	}

	pkb := x509.MarshalPKCS1PrivateKey(pk)

	kc := c.Collection(keyID)
	if kc == nil {
		err = fmt.Errorf("cannot create key ID collection")
		return
	}

	f, err := kc.Create("privkey")
	if err != nil {
		return
	}
	defer f.CloseAbort()

	err = pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pkb,
	})
	if err != nil {
		return
	}

	f.Close()
	return
}

func (s *Store) linkTargets() error {
	names := map[string]*Target{}

	for _, tgt := range s.targets {
		for _, name := range tgt.Names {
			t2 := names[name]
			if targetGt(tgt, t2) {
				names[name] = tgt
			}
		}
	}

	for name, tgt := range names {
		c, err := s.findBestCertificateSatisfying(tgt)
		if err == nil {
			lt := "certs/" + c.ID()
			err = s.db.Collection("live").WriteLink(name, fdb.Link{Target: lt})
			if err != nil {
				return err
			}

			err = notify.Notify("", s.path, name) // ignore error
			log.Errore(err, "failed to call notify hooks")
		}
	}

	return nil
}

func targetGt(a *Target, b *Target) bool {
	if a == nil && b == nil {
		return false
	} else if b == nil {
		return true
	} else if a == nil {
		return false
	}

	if a.Priority > b.Priority {
		return true
	}
	return len(a.Names) > len(b.Names)
}

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

func (s *Store) reconcile() error {
	if s.haveUncachedCertificates() {
		err := s.downloadUncachedCertificates()
		if err != nil {
			return err
		}

		err = s.load()
		if err != nil {
			return err
		}
		if s.haveUncachedCertificates() {
			return fmt.Errorf("cannot obtain one or more uncached certificates")
		}
	}

	for _, t := range s.targets {
		c, err := s.findBestCertificateSatisfying(t)
		if err == nil && !s.certificateNeedsRenewing(c) {
			continue
		}

		err = s.requestCertificateForTarget(t)
		if err != nil {
			return err
		}
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

func (s *Store) findBestCertificateSatisfying(t *Target) (*Certificate, error) {
	var bestCert *Certificate

	for _, c := range s.certs {
		if s.doesCertSatisfy(c, t) && (bestCert == nil || s.certBetterThan(c, bestCert)) {
			bestCert = c
		}
	}

	if bestCert == nil {
		return nil, fmt.Errorf("no certificate satisifes this target")
	}

	return bestCert, nil
}

func (s *Store) doesCertSatisfy(c *Certificate, t *Target) bool {
	if len(c.Certificates) == 0 {
		return false
	}

	if c.Key == nil {
		// a certificate we don't have the key for is unusable.
		return false
	}

	cc, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		return false
	}

	names := map[string]struct{}{}
	for _, name := range cc.DNSNames {
		names[name] = struct{}{}
	}

	for _, name := range t.Names {
		_, ok := names[name]
		if !ok {
			return false
		}
	}

	return true
}

func (s *Store) certificateNeedsRenewing(c *Certificate) bool {
	if len(c.Certificates) == 0 {
		return false
	}

	cc, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		return false
	}

	return cc.NotAfter.Before(time.Now().AddDate(0, 0, 30))
}

func (s *Store) certBetterThan(a *Certificate, b *Certificate) bool {
	if len(a.Certificates) <= len(b.Certificates) || len(b.Certificates) == 0 {
		return false
	}

	ac, err := x509.ParseCertificate(a.Certificates[0])
	bc, err2 := x509.ParseCertificate(b.Certificates[0])
	if err != nil || err2 != nil {
		if err == nil && err2 != nil {
			return true
		}
		return false
	}

	return ac.NotAfter.After(bc.NotAfter)
}

func (s *Store) getAccountClient(a *Account) *acmeapi.Client {
	cl := &acmeapi.Client{}
	cl.AccountInfo.AccountKey = a.PrivateKey
	cl.BaseURL = a.BaseURL
	return cl
}

func (s *Store) obtainAuthorization(name string, a *Account) error {
	cl := s.getAccountClient(a)

	az, err := solver.Authorize(cl, name, nil, context.TODO())
	if err != nil {
		return err
	}

	err = cl.LoadAuthorization(az)
	if err != nil {
		// Try proceeding anyway.
		return nil
	}

	c := s.db.Collection("accounts/" + a.ID() + "/authorizations/" + name)
	if c == nil {
		return fmt.Errorf("cannot get authorizations collection")
	}

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

func (s *Store) createCSR(t *Target) ([]byte, error) {
	csr := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           t.Names,
	}

	pk, _, err := s.createNewCertKey()
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand.Reader, csr, pk)
}

func (s *Store) requestCertificateForTarget(t *Target) error {
	//return fmt.Errorf("not requesting certificate")
	cl := s.getAccountClient(t.Account)

	err := solver.AssistedUpsertRegistration(cl, nil)
	if err != nil {
		return err
	}

	authsNeeded, err := s.determineNecessaryAuthorizations(t)
	if err != nil {
		return err
	}

	for _, name := range authsNeeded {
		err := s.obtainAuthorization(name, t.Account)
		if err != nil {
			return err
		}
	}

	csr, err := s.createCSR(t)
	if err != nil {
		return err
	}

	acrt, err := cl.RequestCertificate(csr)
	if err != nil {
		return err
	}

	crt := &Certificate{
		URL: acrt.URI,
	}

	certID := crt.ID()

	c := s.db.Collection("certs/" + certID)
	if c == nil {
		return fmt.Errorf("cannot create collection for certificate")
	}

	err = fdb.WriteBytes(c, "url", []byte(crt.URL))
	if err != nil {
		return err
	}

	s.certs[certID] = crt

	err = s.downloadCertificate(crt)
	if err != nil {
		return err
	}

	return nil
}

func (s *Store) determineNecessaryAuthorizations(t *Target) ([]string, error) {
	needed := map[string]struct{}{}
	for _, n := range t.Names {
		needed[n] = struct{}{}
	}

	a := t.Account
	for _, auth := range a.Authorizations {
		if auth.IsValid() {
			delete(needed, auth.Name)
		}
	}

	// preserve the order of the names in case the user considers that important
	var neededs []string
	for _, name := range t.Names {
		if _, ok := needed[name]; ok {
			neededs = append(neededs, name)
		}
	}

	return neededs, nil
}

func (s *Store) AddTarget(tgt Target) error {
	if len(tgt.Names) == 0 {
		return nil
	}

	for _, n := range tgt.Names {
		if !validHostname(n) {
			return fmt.Errorf("invalid hostname: %v", n)
		}
	}

	t := s.findTargetWithAllNames(tgt.Names)
	if t != nil {
		return nil
	}

	b, err := yaml.Marshal(&tgt)
	if err != nil {
		return err
	}

	c := s.db.Collection("desired")
	if c == nil {
		return fmt.Errorf("cannot get desired collection")
	}

	fn := s.makeUniqueTargetName(&tgt)
	return fdb.WriteBytes(c, fn, b)
}

func (s *Store) findTargetWithAllNames(names []string) *Target {
T:
	for _, t := range s.targets {
		for _, n := range names {
			if !containsName(t.Names, n) {
				continue T
			}
		}

		return t
	}
	return nil
}

func containsName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

func (s *Store) makeUniqueTargetName(tgt *Target) string {
	// Unfortunately we can't really check if the first hostname exists as a filename
	// and use another name instead as this would create all sorts of race conditions.
	// We have to use a random name.

	nprefix := ""
	if len(tgt.Names) > 0 {
		nprefix = tgt.Names[0] + "-"
	}

	b := uuid.NewV4().Bytes()
	str := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))

	return nprefix + str
}
