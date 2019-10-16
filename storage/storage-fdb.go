// Package storage implements the state directory specification, providing
// a logical API access layer.
package storage

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/hlandau/acmetool/fdb"
	"github.com/hlandau/acmetool/util"
	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/acmeapi.v2"
	"gopkg.in/hlandau/acmeapi.v2/acmeutils"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

var log, Log = xlog.New("acme.storage")

// ACME client store. {{{1
type fdbStore struct {
	db *fdb.DB

	path          string
	certs         map[string]*Certificate // key: certificate ID
	accounts      map[string]*Account     // key: account ID
	keys          map[string]*Key         // key: key ID
	targets       map[string]*Target      // key: target filename
	preferred     map[string]*Certificate // key: hostname
	defaultTarget *Target                 // from conf
}

func (s *fdbStore) WriteMiscellaneousConfFile(filename string, data []byte) error {
	return fdb.WriteBytes(s.db.Collection("conf"), filename, data)
}

// Trivial accessors. {{{1

func (s *fdbStore) AccountByID(accountID string) *Account {
	return s.accounts[accountID]
}

func (s *fdbStore) AccountByDirectoryURL(directoryURL string) *Account {
	for _, a := range s.accounts {
		if a.MatchesURL(directoryURL) {
			return a
		}
	}

	return nil
}

func (s *fdbStore) VisitAccounts(f func(a *Account) error) error {
	for _, a := range s.accounts {
		err := f(a)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *fdbStore) CertificateByID(certificateID string) *Certificate {
	return s.certs[certificateID]
}

func (s *fdbStore) VisitCertificates(f func(c *Certificate) error) error {
	for _, c := range s.certs {
		err := f(c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *fdbStore) TargetByFilename(filename string) *Target {
	return s.targets[filename]
}

func (s *fdbStore) VisitTargets(f func(t *Target) error) error {
	for _, t := range s.targets {
		err := f(t)
		if err != nil {
			return err
		}
	}

	return nil
}

// Return the default target. Persist changes to the default target by calling SaveTarget.
func (s *fdbStore) DefaultTarget() *Target {
	return s.defaultTarget
}

func (s *fdbStore) KeyByID(keyID string) *Key {
	return s.keys[keyID]
}

func (s *fdbStore) VisitKeys(f func(k *Key) error) error {
	for _, k := range s.keys {
		err := f(k)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *fdbStore) loadPreferred() error {
	s.preferred = map[string]*Certificate{}

	c := s.db.Collection("live")
	links, err := c.List()
	if err != nil {
		return err
	}

	for _, linkName := range links {
		link, err := c.ReadLink(linkName)
		if err != nil {
			return err
		}

		certID := link.Target[6:]
		cert := s.CertificateByID(certID)
		if cert == nil {
			// This should never happen because fdb checks symlinks, though maybe if
			// there was an empty certificate directory...
			return fmt.Errorf("unknown certificate: %q", certID)
		}

		s.preferred[linkName] = cert
	}

	return nil
}

func (s *fdbStore) VisitPreferredCertificates(f func(hostname string, c *Certificate) error) error {
	for hostname, c := range s.preferred {
		err := f(hostname, c)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *fdbStore) PreferredCertificateForHostname(hostname string) (*Certificate, error) {
	c := s.preferred[hostname]
	if c == nil {
		return nil, fmt.Errorf("not found: %q", hostname)
	}

	return c, nil
}

func (s *fdbStore) SetPreferredCertificateForHostname(hostname string, c *Certificate) error {
	err := s.db.Collection("live").WriteLink(hostname, fdb.Link{Target: "certs/" + c.ID()})
	if err != nil {
		return err
	}

	s.preferred[hostname] = c
	return nil
}

// Default paths and permissions. {{{1

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

// Initialization and loading. {{{1

// Create a new client store using the given path.
func NewFDB(path string) (Store, error) {
	if path == "" {
		path = RecommendedPath
	}

	dbCfg := fdb.Config{
		Path: path,
	}
	if !isNeutered {
		dbCfg.Permissions = storePermissions
		dbCfg.PermissionsPath = "conf/perm"
	}

	db, err := fdb.Open(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("open fdb: %v", err)
	}

	s := &fdbStore{
		db:   db,
		path: path,
	}

	err = s.Reload()
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Close the store.
func (s *fdbStore) Close() error {
	return nil
}

// State directory path.
func (s *fdbStore) Path() string {
	return s.path
}

// Reload from disk.
func (s *fdbStore) Reload() error {
	if !isNeutered {
		hasTouchedSensitiveData = true

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
	}

	err := s.loadTargets()
	if err != nil {
		return err
	}

	if !isNeutered {
		err = s.loadPreferred()
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *fdbStore) loadAccounts() error {
	c := s.db.Collection("accounts")

	serverNames, err := c.List()
	if err != nil {
		return err
	}

	s.accounts = map[string]*Account{}
	for _, serverName := range serverNames {
		sc := c.Collection(serverName)

		accountNames, err := sc.List()
		log.Errore(err, "failed to list accounts for server ", serverName)
		if err != nil {
			return err
		}

		for _, accountName := range accountNames {
			ac := sc.Collection(accountName)

			err := s.validateAccount(serverName, accountName, ac)
			log.Errore(err, "failed to load account ", accountName)
			if err != nil && IsWellFormattedCertificateOrKeyID(accountName) {
				// If the account name is not a well-formatted key ID and it fails to
				// load, ignore errors.
				return err
			}
		}
	}

	return nil
}

func (s *fdbStore) validateAccount(serverName, accountName string, c *fdb.Collection) error {
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

	directoryURL, err := decodeAccountURLPart(serverName)
	if err != nil {
		return err
	}

	account := &Account{
		PrivateKey:   pk,
		DirectoryURL: directoryURL,
	}

	accountID := account.ID()
	actualAccountID := serverName + "/" + accountName
	if accountID != actualAccountID {
		return fmt.Errorf("account ID mismatch: %#v != %#v", accountID, actualAccountID)
	}

	s.accounts[accountID] = account

	return nil
}

func (s *fdbStore) loadKeys() error {
	s.keys = map[string]*Key{}

	c := s.db.Collection("keys")

	keyIDs, err := c.List()
	if err != nil {
		return err
	}

	for _, keyID := range keyIDs {
		kc := c.Collection(keyID)

		err := s.validateKey(keyID, kc)
		log.Errore(err, "failed to load key ", keyID)
		if err != nil && IsWellFormattedCertificateOrKeyID(keyID) {
			// If the key fails to load and it has an invalid key ID, ignore errors.
			return err
		}
	}

	return nil
}

func (s *fdbStore) validateKey(keyID string, kc *fdb.Collection) error {
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

func (s *fdbStore) loadCerts() error {
	s.certs = map[string]*Certificate{}

	c := s.db.Collection("certs")

	certIDs, err := c.List()
	if err != nil {
		return err
	}

	for _, certID := range certIDs {
		kc := c.Collection(certID)

		err := s.validateCert(certID, kc)
		log.Errore(err, "failed to load certificate ", certID)
		if err != nil && IsWellFormattedCertificateOrKeyID(certID) {
			// If the certificate fails to load and it has an invalid cert ID,
			// ignore errors.
			return err
		}
	}

	return nil
}

func (s *fdbStore) validateCert(certID string, c *fdb.Collection) error {
	ss, err := fdb.String(c.Open("url"))
	if err != nil {
		return err
	}

	ss = strings.TrimSpace(ss)
	if !acmeapi.ValidURL(ss) {
		return fmt.Errorf("certificate order has invalid URI")
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

	acctLink, err := c.ReadLink("account")
	if err == nil {
		if !strings.HasPrefix(acctLink.Target, "accounts/") {
			return fmt.Errorf("malformed certificate account symlink: %q %q", certID, acctLink.Target)
		}

		crt.Account = s.AccountByID(acctLink.Target[9:])
		if crt.Account == nil {
			log.Warnf("certificate directory %#v contains account reference %#v but no such account was found", certID, acctLink.Target)
		}
	}

	s.certs[certID] = crt

	return nil
}

func (s *fdbStore) loadTargets() error {
	s.targets = map[string]*Target{}

	// default target
	confc := s.db.Collection("conf")

	dtgt, err := s.validateTargetInner("target", confc, true)
	if err == nil {
		dtgt.genericise()
		s.defaultTarget = dtgt
	} else {
		if !os.IsNotExist(err) {
			log.Errore(err, "error loading default target file")
		}
		s.defaultTarget = &Target{}
	}

	// Legacy support. We have to do this here so that these defaults get copied
	// across to the targets.
	s.loadWebrootPaths()
	s.loadRSAKeySize()

	// targets
	c := s.db.Collection("desired")

	desiredKeys, err := c.List()
	if err != nil {
		return err
	}

	for _, desiredKey := range desiredKeys {
		err := s.validateTarget(desiredKey, c)
		log.Errore(err, "failed to load target ", desiredKey)
		// Ignore errors, best effort.
	}

	return nil
}

func (s *fdbStore) validateTarget(desiredKey string, c *fdb.Collection) error {
	tgt, err := s.validateTargetInner(desiredKey, c, false)
	if err != nil {
		return err
	}

	s.targets[desiredKey] = tgt
	return nil
}

func (s *fdbStore) validateTargetInner(desiredKey string, c *fdb.Collection, loadingDefault bool) (*Target, error) {
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

	tgt.Filename = desiredKey

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

	// tgt.Request.Account is not set; it is for use by other code.

	return tgt, nil
}

// Saving {{{1

// Serializes the target to disk. Call after changing any settings.
func (s *fdbStore) SaveTarget(t *Target) error {
	// Some basic validation.
	err := t.Validate()
	if err != nil {
		return err
	}

	if t != s.defaultTarget {
		t.ensureFilename()
	}

	tcopy := *t

	if t == s.defaultTarget {
		tcopy.genericise()
	}

	// don't serialize default request names list
	if tcopy.Request.implicitNames {
		tcopy.Request.Names = nil
	}

	b, err := yaml.Marshal(&tcopy)
	if err != nil {
		return err
	}

	// Save.
	if t == s.defaultTarget {
		return fdb.WriteBytes(s.db.Collection("conf"), "target", b)
	}

	return fdb.WriteBytes(s.db.Collection("desired"), t.Filename, b)
}

func (s *fdbStore) RemoveTarget(filename string) error {
	return s.db.Collection("desired").Delete(filename)
}

func (s *fdbStore) SaveCertificate(cert *Certificate) error {
	c := s.db.Collection("certs/" + cert.ID())

	if cert.RevocationDesired {
		err := fdb.CreateEmpty(c, "revoke")
		if err != nil {
			return err
		}
	}

	if cert.Revoked {
		err := fdb.CreateEmpty(c, "revoked")
		if err != nil {
			return err
		}
	}

	if len(cert.Certificates) == 0 {
		return nil
	}

	fcert, err := c.Create("cert")
	if err != nil {
		return err
	}
	defer fcert.CloseAbort()

	fchain, err := c.Create("chain")
	if err != nil {
		return err
	}
	defer fchain.CloseAbort()

	ffullchain, err := c.Create("fullchain")
	if err != nil {
		return err
	}
	defer ffullchain.CloseAbort()

	err = acmeutils.SaveCertificates(io.MultiWriter(fcert, ffullchain), cert.Certificates[0])
	if err != nil {
		return err
	}

	for _, ec := range cert.Certificates[1:] {
		err = acmeutils.SaveCertificates(io.MultiWriter(fchain, ffullchain), ec)
		if err != nil {
			return err
		}
	}

	fcert.Close()
	fchain.Close()
	ffullchain.Close()

	return nil
}

func (s *fdbStore) SaveAccount(a *Account) error {
	coll := s.db.Collection("accounts/" + a.ID())
	w, err := coll.Create("privkey")
	if err != nil {
		return err
	}
	defer w.CloseAbort()

	err = acmeutils.SavePrivateKey(w, a.PrivateKey)
	if err != nil {
		return err
	}

	w.Close()

	return nil
}

// Removal {{{1

func (s *fdbStore) RemoveCertificate(certificateID string) error {
	_, ok := s.certs[certificateID]
	if !ok {
		return fmt.Errorf("certificate does not exist: %s", certificateID)
	}

	err := s.db.Collection("certs").Delete(certificateID)
	if err != nil {
		return err
	}

	delete(s.certs, certificateID)
	return nil
}

func (s *fdbStore) RemoveKey(keyID string) error {
	_, ok := s.keys[keyID]
	if !ok {
		return fmt.Errorf("key does not exist: %s", keyID)
	}

	err := s.db.Collection("keys").Delete(keyID)
	if err != nil {
		return err
	}

	delete(s.keys, keyID)
	return nil
}

// Importing {{{1

// Give a PEM-encoded key file, imports the key into the store. If the key is
// already installed, returns nil.
func (s *fdbStore) ImportKey(privateKey crypto.PrivateKey) (*Key, error) {
	keyID, err := determineKeyIDFromKey(privateKey)
	if err != nil {
		return nil, err
	}

	k, ok := s.keys[keyID]
	if ok {
		return k, nil
	}

	c := s.db.Collection("keys/" + keyID)
	err = s.saveKey(c, privateKey)
	if err != nil {
		return nil, err
	}

	k = &Key{
		PrivateKey: privateKey,
		ID:         keyID,
	}

	s.keys[keyID] = k
	return k, nil
}

// Given a certificate URL, imports the certificate into the store. The
// certificate will be retrieved on the next reconcile. If a certificate with
// that URL already exists, this is a no-op and returns nil.
func (s *fdbStore) ImportCertificate(acct *Account, url string) (*Certificate, error) {
	certID := determineCertificateID(url)
	c, ok := s.certs[certID]
	if ok {
		return c, nil
	}

	coll := s.db.Collection("certs/" + certID)
	err := coll.WriteLink("account", fdb.Link{"accounts/" + acct.ID()})
	if err != nil {
		return nil, err
	}

	err = fdb.WriteBytes(coll, "url", []byte(url))
	if err != nil {
		return nil, err
	}

	c = &Certificate{
		URL:     url,
		Account: acct,
	}

	s.certs[certID] = c
	return c, nil
}

// Given an account private key and the provider directory URL, imports that account key.
// If the account already exists and has a private key, this is a no-op and returns nil.
func (s *fdbStore) ImportAccount(directoryURL string, privateKey crypto.PrivateKey) (*Account, error) {
	accountID, err := determineAccountID(directoryURL, privateKey)
	if err != nil {
		return nil, err
	}

	a, ok := s.accounts[accountID]
	if ok {
		return a, nil
	}

	err = s.saveKey(s.db.Collection("accounts/"+accountID), privateKey)
	if err != nil {
		return nil, err
	}

	a = &Account{
		PrivateKey:   privateKey,
		DirectoryURL: directoryURL,
	}
	s.accounts[accountID] = a

	return a, nil
}

// Saves a key as a file named "privkey" inside the given collection.
func (s *fdbStore) saveKey(c *fdb.Collection, privateKey crypto.PrivateKey) error {
	f, err := c.Create("privkey")
	if err != nil {
		return err
	}
	defer f.CloseAbort()

	err = acmeutils.SavePrivateKey(f, privateKey)
	if err != nil {
		return err
	}

	return f.Close()
}

// Save a private key inside a key ID collection under the given collection.
func (s *fdbStore) saveKeyUnderID(c *fdb.Collection, privateKey crypto.PrivateKey) (keyID string, err error) {
	keyID, err = determineKeyIDFromKey(privateKey)
	if err != nil {
		return
	}

	err = s.saveKey(c.Collection(keyID), privateKey)
	return
}

// Revocation marking {{{1

// Try to revoke the certificate with the given certificate ID.
// If a key ID is given, revoke all certificates with using key ID.
func (s *fdbStore) RevokeByCertificateOrKeyID(certID string) error {
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

func (s *fdbStore) revokeByKeyID(keyID string) error {
	k, ok := s.keys[keyID]
	if !ok {
		return fmt.Errorf("cannot find certificate or key with given ID: %q", keyID)
	}

	var merr util.MultiError
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
