// Package storageops implements operations on the state directory.
package storageops

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeendpoints"
	"github.com/hlandau/acme/acmeapi/acmeutils"
	"github.com/hlandau/acme/hooks"
	"github.com/hlandau/acme/responder"
	"github.com/hlandau/acme/solver"
	"github.com/hlandau/acme/storage"
	"github.com/hlandau/xlog"
	"github.com/jmhodges/clock"
	"golang.org/x/net/context"
	"sort"
	"strings"
)

var log, Log = xlog.New("acme.storageops")

// Internal use only. Used for testing purposes. Do not change.
var InternalClock = clock.Default()

type reconcile struct {
	store storage.Store

	// Cache of account clients to avoid duplicated directory lookups.
	accountClients map[*storage.Account]*acmeapi.Client
}

func makeReconcile(store storage.Store) *reconcile {
	return &reconcile{
		store:          store,
		accountClients: map[*storage.Account]*acmeapi.Client{},
	}
}

func EnsureRegistration(store storage.Store) error {
	r := makeReconcile(store)
	return r.EnsureRegistration()
}

func (r *reconcile) EnsureRegistration() error {
	a, err := r.getAccountByDirectoryURL("")
	if err != nil {
		return err
	}

	cl := r.getClientForAccount(a)
	return solver.AssistedUpsertRegistration(cl, nil, context.TODO())
}

// Runs the reconcilation operation.
func Reconcile(store storage.Store) error {
	r := makeReconcile(store)

	reconcileErr := r.Reconcile()
	log.Errore(reconcileErr, "failed to reconcile")

	reloadErr := r.store.Reload()
	log.Errore(reloadErr, "failed to reload after reconcilation")

	relinkErr := r.Relink()
	log.Errore(relinkErr, "failed to relink after reconcilation")

	err := reconcileErr
	if err == nil {
		err = reloadErr
	}
	if err == nil {
		err = relinkErr
	}

	return err
}

// Runs the relink operation without running the reconcile operation.
func Relink(store storage.Store) error {
	r := makeReconcile(store)

	err := r.Relink()
	log.Errore(err, "failed to relink")
	return err
}

func (r *reconcile) Relink() error {
	hostnameTargetMapping, err := r.disjoinTargets()
	if err != nil {
		return err
	}

	var updatedHostnames []string

	for name, tgt := range hostnameTargetMapping {
		c, err := FindBestCertificateSatisfying(r.store, tgt)
		if err != nil {
			log.Debugf("could not find certificate satisfying %v: %v", tgt, err)
			continue
		}

		log.Tracef("relink: best certificate satisfying %v is %v", tgt, c)

		cprev, err := r.store.PreferredCertificateForHostname(name)

		if c != cprev || err != nil {
			log.Debugf("relinking: %v -> %v (was %v)", name, c, cprev)
			updatedHostnames = append(updatedHostnames, name)

			err = r.store.SetPreferredCertificateForHostname(name, c)
			log.Errore(err, "failed to set preferred certificate for hostname")
		}
	}

	ctx := &hooks.Context{
		HooksDir: "",
		StateDir: r.store.Path(),
	}

	err = hooks.NotifyLiveUpdated(ctx, updatedHostnames) // ignore error
	log.Errore(err, "failed to call notify hooks")

	return nil
}

func (r *reconcile) disjoinTargets() (hostnameTargetMapping map[string]*storage.Target, err error) {
	var targets []*storage.Target

	r.store.VisitTargets(func(t *storage.Target) error {
		targets = append(targets, t)
		return nil
	})

	sort.Stable(sort.Reverse(targetSorter(targets)))

	// Hostname-target mapping.
	hostnameTargetMapping = map[string]*storage.Target{}
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

	// Debugging information.
	for name, tgt := range hostnameTargetMapping {
		log.Debugf("disjoint hostname mapping: %s -> %v", name, tgt)
	}

	return
}

func (r *reconcile) Reconcile() error {
	err := r.processUncachedCertificates()
	if err != nil {
		return err
	}

	err = r.processPendingRevocations()
	log.Errore(err, "could not process pending revocations")

	err = r.processTargets()
	log.Errore(err, "error while processing targets")
	if err != nil {
		return err
	}

	return nil
}

func (r *reconcile) processUncachedCertificates() error {
	if !HaveUncachedCertificates(r.store) {
		return nil
	}

	log.Debug("there are uncached certificates - downloading them")

	err := r.downloadUncachedCertificates()
	if err != nil {
		log.Errore(err, "error while downloading uncached certificates")
		return err
	}

	log.Debug("reloading after downloading uncached certificates")
	err = r.store.Reload()
	if err != nil {
		log.Errore(err, "failed to reload after downloading uncached certificates")
		return err
	}

	log.Debug("finished reloading after downloading uncached certificates")

	if HaveUncachedCertificates(r.store) {
		log.Error("failed to download all uncached certificates")
		return fmt.Errorf("cannot obtain one or more uncached certificates")
	}

	return nil
}

func HaveUncachedCertificates(s storage.Store) bool {
	haveUncached := false

	s.VisitCertificates(func(c *storage.Certificate) error {
		if !c.Cached {
			haveUncached = true
		}

		return nil
	})

	return haveUncached
}

func (r *reconcile) downloadUncachedCertificates() error {
	return r.store.VisitCertificates(func(c *storage.Certificate) error {
		if c.Cached {
			return nil
		}

		return r.downloadCertificate(c)
	})
}

func (r *reconcile) downloadCertificate(c *storage.Certificate) error {
	log.Debugf("downloading certificate %v", c)

	cl := r.getGenericClient()

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

	c.Certificates = [][]byte{crt.Certificate}
	c.Certificates = append(c.Certificates, crt.ExtraCertificates...)
	c.Cached = true

	err = r.store.SaveCertificate(c)
	if err != nil {
		log.Errore(err, "failed to save certificate after retrieval: %v", c)
		return err
	}

	return nil
}

func (r *reconcile) processPendingRevocations() error {
	var me storage.MultiError

	r.store.VisitCertificates(func(c *storage.Certificate) error {
		if c.Revoked || !c.RevocationDesired {
			return nil
		}

		err := r.revokeCertificate(c)
		if err != nil {
			me = append(me, fmt.Errorf("failed to revoke %v: %v", c, err))
			// keep processing revocations
		}

		return nil
	})

	if len(me) > 0 {
		return me
	}

	return nil
}

func (r *reconcile) revokeCertificate(c *storage.Certificate) error {
	err := r.revokeCertificateInner(c)
	if err != nil {
		return err
	}

	c.Revoked = true
	err = r.store.SaveCertificate(c)
	if err != nil {
		log.Errore(err, "failed to save certificate after revocation: ", c)
		return err
	}

	return nil
}

func (r *reconcile) revokeCertificateInner(c *storage.Certificate) error {
	if len(c.Certificates) == 0 {
		return fmt.Errorf("no certificates in certificate to revoke: %v", c)
	}

	endCertificate := c.Certificates[0]

	crt, err := x509.ParseCertificate(endCertificate)
	if err != nil {
		return err
	}

	// Get the endpoint which issued the certificate.
	endpoint, err := acmeendpoints.CertificateToEndpoint(r.getGenericClient(), crt, context.TODO())
	if err != nil {
		return fmt.Errorf("could not map certificate %v to endpoint: %v", c, err)
	}

	// In order to revoke a certificate, one needs either the private key of the
	// certificate, or the account key with authorizations for all names on the
	// certificate. Try and find the private key first.
	var client *acmeapi.Client
	var revocationKey crypto.PrivateKey
	if c.Key != nil {
		revocationKey = c.Key.PrivateKey
		client = r.getClientForDirectoryURL(endpoint.DirectoryURL)
	}

	if revocationKey == nil {
		acct, err := r.getAccountByDirectoryURL(endpoint.DirectoryURL)
		if err != nil {
			return err
		}

		client = r.getClientForAccount(acct)

		// If we have no private key for the certificate, obtain all necessary
		// authorizations.
		err = r.getRevocationAuthorizations(acct, crt)
		if err != nil {
			return err
		}
	}

	return client.Revoke(endCertificate, revocationKey, context.TODO())
}

func (r *reconcile) getGenericClient() *acmeapi.Client {
	return &acmeapi.Client{}
}

func (r *reconcile) getClientForDirectoryURL(directoryURL string) *acmeapi.Client {
	cl := r.getGenericClient()
	cl.DirectoryURL = directoryURL
	return cl
}

func (r *reconcile) getClientForAccount(a *storage.Account) *acmeapi.Client {
	cl := r.accountClients[a]
	if cl == nil {
		cl = r.getClientForDirectoryURL(a.DirectoryURL)
		cl.AccountKey = a.PrivateKey
		r.accountClients[a] = cl
	}

	return cl
}

func (r *reconcile) getRevocationAuthorizations(acct *storage.Account, crt *x509.Certificate) error {
	log.Debugf("obtaining authorizations needed to facilitate revocation")
	return r.obtainNecessaryAuthorizations(crt.DNSNames, acct, "", &r.store.DefaultTarget().Request.Challenge)
}

func (r *reconcile) obtainNecessaryAuthorizations(names []string, a *storage.Account, targetFilename string, ccfg *storage.TargetRequestChallenge) error {
	authsNeeded := r.determineNecessaryAuthorizations(names, a)

	for _, name := range authsNeeded {
		log.Debugf("trying to obtain authorization for %q", name)
		err := r.obtainAuthorization(name, a, targetFilename, ccfg)
		if err != nil {
			log.Errore(err, "could not obtain authorization for ", name)
			return err
		}
	}

	return nil
}

func (r *reconcile) determineNecessaryAuthorizations(names []string, a *storage.Account) []string {
	needed := map[string]struct{}{}
	for _, n := range names {
		needed[n] = struct{}{}
	}

	for _, auth := range a.Authorizations {
		if auth.IsValid(InternalClock) {
			delete(needed, auth.Name)
		}
	}

	// Preserve the order of the names in case the user considers that important.
	var neededs []string
	for _, name := range names {
		if _, ok := needed[name]; ok {
			neededs = append(neededs, name)
		}
	}

	return neededs
}

func generateHookPEM(info *responder.TLSSNIChallengeInfo) (string, error) {
	b := bytes.Buffer{}

	err := acmeutils.SaveCertificates(&b, info.Certificate)
	if err != nil {
		return "", err
	}

	err = acmeutils.SavePrivateKey(&b, info.Key)
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func (r *reconcile) obtainAuthorization(name string, a *storage.Account, targetFilename string, trc *storage.TargetRequestChallenge) error {
	cl := r.getClientForAccount(a)

	ctx := &hooks.Context{
		HooksDir: "",
		StateDir: r.store.Path(),
		Env:      map[string]string{},
	}
	for k, v := range trc.InheritedEnv {
		ctx.Env[k] = v
	}
	for k, v := range trc.Env {
		ctx.Env[k] = v
	}

	startHookFunc := func(challengeInfo interface{}) error {
		switch v := challengeInfo.(type) {
		case *responder.HTTPChallengeInfo:
			_, err := hooks.ChallengeHTTPStart(ctx, name, targetFilename, v.Filename, v.Body)
			return err
		case *responder.TLSSNIChallengeInfo:
			hookPEM, err := generateHookPEM(v)
			if err != nil {
				return err
			}

			_, err = hooks.ChallengeTLSSNIStart(ctx, name, targetFilename, v.Hostname1, v.Hostname2, hookPEM)
			return err
		case *responder.DNSChallengeInfo:
			installed, err := hooks.ChallengeDNSStart(ctx, name, targetFilename, v.Body)
			if err == nil && !installed {
				return fmt.Errorf("could not install DNS challenge, no hooks succeeded")
			}
			return err
		default:
			return nil
		}
	}

	stopHookFunc := func(challengeInfo interface{}) error {
		switch v := challengeInfo.(type) {
		case *responder.HTTPChallengeInfo:
			return hooks.ChallengeHTTPStop(ctx, name, targetFilename, v.Filename, v.Body)
		case *responder.TLSSNIChallengeInfo:
			hookPEM, err := generateHookPEM(v)
			if err != nil {
				return err
			}

			_, err = hooks.ChallengeTLSSNIStop(ctx, name, targetFilename, v.Hostname1, v.Hostname2, hookPEM)
			return err
		case *responder.DNSChallengeInfo:
			uninstalled, err := hooks.ChallengeDNSStop(ctx, name, targetFilename, v.Body)
			if err == nil && !uninstalled {
				return fmt.Errorf("could not uninstall DNS challenge, no hooks succeeded")
			}
			return err
		default:
			return nil
		}
	}

	httpSelfTest := true
	if trc.HTTPSelfTest != nil {
		httpSelfTest = *trc.HTTPSelfTest
	}

	ccfg := responder.ChallengeConfig{
		WebPaths:       trc.WebrootPaths,
		HTTPPorts:      trc.HTTPPorts,
		HTTPNoSelfTest: !httpSelfTest,
		PriorKeyFunc:   r.getPriorKey,
		StartHookFunc:  startHookFunc,
		StopHookFunc:   stopHookFunc,
	}

	az, err := solver.Authorize(cl, name, ccfg, context.TODO())
	if err != nil {
		return err
	}

	err = cl.LoadAuthorization(az, context.TODO())
	if err != nil {
		// Try proceeding anyway.
		return nil
	}

	if a.Authorizations == nil {
		a.Authorizations = map[string]*storage.Authorization{}
	}

	a.Authorizations[az.Identifier.Value] = &storage.Authorization{
		URL:     az.URI,
		Name:    az.Identifier.Value,
		Expires: az.Expires,
	}

	err = r.store.SaveAccount(a)
	if err != nil {
		return err
	}

	return nil
}

func (r *reconcile) getPriorKey(publicKey crypto.PublicKey) (crypto.PrivateKey, error) {
	// Returning an error here short circuits. If any errors occur here, return (nil,nil).

	keyID, err := storage.DetermineKeyIDFromPublicKey(publicKey)
	if err != nil {
		log.Errore(err, "failed to get key ID from public key")
		return nil, nil
	}

	k := r.store.KeyByID(keyID)

	if k == nil {
		log.Infof("failed to find key ID wanted by proofOfPossession: %s", keyID)
		return nil, nil // unknown key
	}

	return k.PrivateKey, nil
}

func (r *reconcile) getAccountByDirectoryURL(directoryURL string) (*storage.Account, error) {
	if directoryURL == "" {
		directoryURL = r.store.DefaultTarget().Request.Provider
	}

	if directoryURL == "" {
		directoryURL = acmeendpoints.DefaultEndpoint.DirectoryURL
	}

	if !acmeapi.ValidURL(directoryURL) {
		return nil, fmt.Errorf("directory URL is not a valid HTTPS URL")
	}

	ma := r.store.AccountByDirectoryURL(directoryURL)
	if ma != nil {
		return ma, nil
	}

	return r.createNewAccount(directoryURL)
}

func (r *reconcile) createNewAccount(directoryURL string) (*storage.Account, error) {
	pk, err := generateKey(&r.store.DefaultTarget().Request.Key)
	if err != nil {
		return nil, err
	}

	a := &storage.Account{
		PrivateKey:   pk,
		DirectoryURL: directoryURL,
	}

	err = r.store.SaveAccount(a)
	if err != nil {
		log.Errore(err, "failed to save account")
		return nil, err
	}

	return a, nil
}

func (r *reconcile) processTargets() error {
	var merr storage.MultiError

	r.store.VisitTargets(func(t *storage.Target) error {
		c, err := FindBestCertificateSatisfying(r.store, t)
		log.Debugf("%v: best certificate satisfying is %v, err=%v", t, c, err)
		if err == nil && !CertificateNeedsRenewing(c) {
			log.Debugf("%v: have best certificate which does not need renewing, skipping target", t)
			return nil // continue
		}

		log.Debugf("%v: requesting certificate", t)
		err = r.requestCertificateForTarget(t)
		log.Errore(err, t, ": failed to request certificate")
		if err != nil {
			// Do not block satisfaction of other targets just because one fails;
			// collect errors and return them as one.
			merr = append(merr, &TargetSpecificError{
				Target: t,
				Err:    err,
			})
		}

		return nil
	})

	log.Debugf("done processing targets, reconciliation complete, %d errors occurred", len(merr))

	if len(merr) != 0 {
		return merr
	}

	return nil
}

func (r *reconcile) getRequestAccount(tr *storage.TargetRequest) (*storage.Account, error) {
	if tr.Account != nil {
		return tr.Account, nil
	}

	// This will create the account if it doesn't exist.
	acct, err := r.getAccountByDirectoryURL(tr.Provider)
	if err != nil {
		return nil, err
	}

	return acct, nil
}

// Returns the strings in ys not contained in xs.
func stringsNotIn(xs, ys []string) []string {
	m := map[string]struct{}{}
	for _, x := range xs {
		m[x] = struct{}{}
	}
	var zs []string
	for _, y := range ys {
		_, ok := m[y]
		if !ok {
			zs = append(zs, y)
		}
	}
	return zs
}

func ensureConceivablySatisfiable(t *storage.Target) {
	// We ensure that every stipulation in the satisfy section can be met by the request
	// parameters.
	excludedNames := stringsNotIn(t.Request.Names, t.Satisfy.Names)
	if len(excludedNames) > 0 {
		log.Warnf("%v can never be satisfied because names to be requested are not a superset of the names to be satisfied; adding names automatically to render target satisfiable", t)
	}

	for _, n := range excludedNames {
		t.Request.Names = append(t.Request.Names, n)
	}
}

func (r *reconcile) requestCertificateForTarget(t *storage.Target) error {
	//return fmt.Errorf("not requesting certificate") // debugging neuter

	ensureConceivablySatisfiable(t)

	acct, err := r.getRequestAccount(&t.Request)
	if err != nil {
		return err
	}

	cl := r.getClientForAccount(acct)

	err = solver.AssistedUpsertRegistration(cl, nil, context.TODO())
	if err != nil {
		return err
	}

	err = r.obtainNecessaryAuthorizations(t.Request.Names, acct, t.Filename, &t.Request.Challenge)
	if err != nil {
		return err
	}

	csr, err := r.createCSR(t)
	if err != nil {
		return err
	}

	log.Debugf("%v: requesting certificate", t)
	acrt, err := cl.RequestCertificate(csr, context.TODO())
	if err != nil {
		log.Errore(err, "could not request certificate")
		return err
	}

	c, err := r.store.ImportCertificate(acrt.URI)
	if err != nil {
		log.Errore(err, "could not import certificate")
		return err
	}

	err = r.downloadCertificate(c)
	if err != nil {
		log.Errore(err, "failed to download certificate")
		return err
	}

	return nil
}

var (
	oidTLSFeature          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	mustStapleFeatureValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

func (r *reconcile) createCSR(t *storage.Target) ([]byte, error) {
	if len(t.Request.Names) == 0 {
		return nil, fmt.Errorf("cannot request a certificate with no names")
	}

	csr := &x509.CertificateRequest{
		DNSNames: t.Request.Names,
		Subject: pkix.Name{
			CommonName: t.Request.Names[0],
		},
	}

	if t.Request.OCSPMustStaple {
		csr.ExtraExtensions = append(csr.ExtraExtensions, pkix.Extension{
			Id:    oidTLSFeature,
			Value: mustStapleFeatureValue,
		})
	}

	pk, err := r.generateOrGetKey(&t.Request.Key)
	if err != nil {
		log.Errore(err, "could not generate key while generating CSR for %v", t)
		return nil, err
	}

	_, err = r.store.ImportKey(pk)
	if err != nil {
		log.Errore(err, "could not import freshly generated key while generating CSR for %v", t)
		return nil, err
	}

	csr.SignatureAlgorithm, err = signatureAlgorithmFromKey(pk)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificateRequest(rand.Reader, csr, pk)
}

func (r *reconcile) generateOrGetKey(trk *storage.TargetRequestKey) (crypto.PrivateKey, error) {
	if trk.ID != "" {
		k := r.store.KeyByID(strings.TrimSpace(strings.ToLower(trk.ID)))
		if k != nil {
			return k.PrivateKey, nil
		}

		log.Warnf("target requests specific key %q but it cannot be found, generating a new key", trk.ID)
	}

	return generateKey(trk)
}

func DoesCertificateSatisfy(c *storage.Certificate, t *storage.Target) bool {
	if c.Revoked {
		log.Debugf("%v cannot satisfy %v because it is revoked", c, t)
		return false
	}

	if len(c.Certificates) == 0 {
		log.Debugf("%v cannot satisfy %v because it has no actual certificates", c, t)
		return false
	}

	if c.Key == nil {
		// A certificate we don't have the key for is unusable.
		log.Debugf("%v cannot satisfy %v because we do not have a key for it", c, t)
		return false
	}

	cc, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		log.Debugf("%v cannot satisfy %v because we cannot parse it: %v", c, t, err)
		return false
	}

	names := map[string]struct{}{}
	for _, name := range cc.DNSNames {
		names[name] = struct{}{}
	}

	for _, name := range t.Satisfy.Names {
		_, ok := names[name]
		if !ok {
			log.Debugf("%v cannot satisfy %v because required hostname %q is not listed on it: %#v", c, t, name, cc.DNSNames)
			return false
		}
	}

	log.Debugf("%v satisfies %v", c, t)
	return true
}

func FindBestCertificateSatisfying(s storage.Store, t *storage.Target) (*storage.Certificate, error) {
	var bestCert *storage.Certificate

	err := s.VisitCertificates(func(c *storage.Certificate) error {
		if DoesCertificateSatisfy(c, t) {
			isBetterThan, err := CertificateBetterThan(c, bestCert)
			if err != nil {
				return err
			}

			if isBetterThan {
				log.Tracef("findBestCertificateSatisfying: %v > %v", c, bestCert)
				bestCert = c
			} else {
				log.Tracef("findBestCertificateSatisfying: %v <= %v", c, bestCert)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if bestCert == nil {
		return nil, fmt.Errorf("%v: no certificate satisfies this target", t)
	}

	return bestCert, nil
}

func CertificateBetterThan(a, b *storage.Certificate) (bool, error) {
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
			log.Tracef("certBetterThan: parseable certificate is better than unparseable certificate")
			return true, nil
		}

		return false, nil
	}

	isAfter := ac.NotAfter.After(bc.NotAfter)
	log.Tracef("certBetterThan: (%v > %v)=%v", ac.NotAfter, bc.NotAfter, isAfter)
	return isAfter, nil
}

func CertificateNeedsRenewing(c *storage.Certificate) bool {
	if len(c.Certificates) == 0 {
		log.Debugf("%v: not renewing because it has no actual certificates (???)", c)
		return false
	}

	cc, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		log.Debugf("%v: not renewing because its end certificate is unparseable", c)
		return false
	}

	renewTime := renewTime(cc.NotBefore, cc.NotAfter)
	needsRenewing := !InternalClock.Now().Before(renewTime)

	log.Debugf("%v needsRenewing=%v notAfter=%v", c, needsRenewing, cc.NotAfter)
	return needsRenewing
}

// This is used to detertmine whether to cull certificates.
func CertificateGenerallyValid(c *storage.Certificate) bool {
	// This function is very conservative because if we return false
	// the certificate will get deleted. Revocation and expiry are
	// good reasons to delete. We already know the certificate is
	// unreferenced.

	if c.Revoked {
		log.Debugf("%v not generally valid because it is revoked", c)
		return false
	}

	if len(c.Certificates) == 0 {
		// If we have no actual certificates, give the benefit of the doubt.
		// Maybe the certificate is undownloaded.
		log.Debugf("%v has no actual certificates, assuming valid", c)
		return true
	}

	cc, err := x509.ParseCertificate(c.Certificates[0])
	if err != nil {
		log.Debugf("%v cannot be parsed, assuming valid", c)
		return false
	}

	if !InternalClock.Now().Before(cc.NotAfter) {
		log.Debugf("%v not generally valid because it is expired", c)
		return false
	}

	return true
}
