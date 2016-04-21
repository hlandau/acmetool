package main

import (
	"crypto/x509"
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeapi/acmeendpoints"
	"github.com/hlandau/acme/acmeapi/acmeutils"
	"github.com/hlandau/acme/storage"
	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v1"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func cmdImportLE() {
	s, err := storage.NewFDB(*stateFlag)
	log.Fatale(err, "storage")

	lePath := *importLEArg
	accountNames, err := getLEAccountNames(lePath)
	log.Fatale(err, "cannot inspect accounts directory - do you have permissions to read the Let's Encrypt directory (i.e. are you root)?")

	// In order to import a Let's Encrypt state directory, we must:
	//   - import the account keys
	//   - import the certificate keys
	//   - import the certificates

	// Import account keys.
	durls := map[string]struct{}{}

	for _, accountName := range accountNames {
		acct, err := importLEAccount(s, lePath, accountName)
		log.Fatale(err, "import account")

		durls[acct.DirectoryURL] = struct{}{}
	}

	keyFiles, err := filepath.Glob(filepath.Join(lePath, "keys", "*.pem"))
	log.Fatale(err)

	// Import certificate keys.
	for _, keyFile := range keyFiles {
		err := importKey(s, keyFile)
		log.Fatale(err, "import key")
	}

	// Import certificates.
	certFiles, err := filepath.Glob(filepath.Join(lePath, "archive", "*", "cert*.pem"))
	log.Fatale(err)

	for _, certFile := range certFiles {
		err := importCert(s, certFile)
		log.Fatale(err, "import certificate")
	}

	// If there is no default provider set, and we have only one directory URL
	// imported, set it as the default provider.
	if len(durls) == 1 && s.DefaultTarget().Request.Provider == "" {
		for p := range durls {
			s.DefaultTarget().Request.Provider = p
			err := s.SaveTarget(s.DefaultTarget())
			log.Fatale(err, "couldn't set default provider")
			break
		}
	}
}

var knownProviderURLs = map[string]struct{}{}

func importLEAccount(s storage.Store, lePath, accountName string) (*storage.Account, error) {
	providerURL, err := getProviderURLFromAccountName(accountName)
	if err != nil {
		return nil, err
	}

	knownProviderURLs[providerURL] = struct{}{}

	pkPath := filepath.Join(lePath, "accounts", accountName, "private_key.json")
	b, err := ioutil.ReadFile(pkPath)
	if err != nil {
		return nil, err
	}

	k := jose.JsonWebKey{}
	err = k.UnmarshalJSON(b)
	if err != nil {
		return nil, err
	}

	acct, err := s.ImportAccount(providerURL, k.Key)
	if err != nil {
		return nil, err
	}

	return acct, nil
}

func importKey(s storage.Store, filename string) error {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	pk, err := acmeutils.LoadPrivateKey(b)
	if err != nil {
		return err
	}

	_, err = s.ImportKey(pk)
	return err
}

func importCert(s storage.Store, filename string) error {
	certURL, err := determineLECertificateURL(filename)
	if err != nil {
		return err
	}

	_, err = s.ImportCertificate(certURL)
	return err
}

// The Let's Encrypt state directory format keeps certificates but not their
// URLs. Since boulder uses the serial number to form the URL, we can
// reconstruct the URL. But since not even the provider association is stored,
// we have to guess.
func determineLECertificateURL(certFilename string) (string, error) {
	b, err := ioutil.ReadFile(certFilename)
	if err != nil {
		return "", err
	}

	certs, err := acmeutils.LoadCertificates(b)
	if err != nil {
		return "", err
	}

	if len(certs) == 0 {
		return "", fmt.Errorf("no certs")
	}

	c, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return "", err
	}

	// Don't need directory URL, direct certificate URL load only.
	cl := acmeapi.Client{}

	_, certURL, err := acmeendpoints.CertificateToEndpointURL(&cl, c, context.TODO())
	if err != nil {
		return "", err
	}

	return certURL, nil
}

func getProviderURLFromAccountName(accountName string) (string, error) {
	idx := strings.LastIndexByte(accountName, '/')
	if idx < 0 || idx != len(accountName)-33 {
		return "", fmt.Errorf("does not appear to be an account name: %#v", accountName)
	}
	return "https://" + accountName[0:idx], nil
}

func getLEAccountNames(path string) (accountNames []string, err error) {
	err = filepath.Walk(filepath.Join(path, "accounts"), func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		m := re_leAccountPath.FindStringSubmatch(path)

		if fi.IsDir() && m != nil {
			accountNames = append(accountNames, m[1])
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return accountNames, nil
}

var re_leAccountPath = regexp.MustCompilePOSIX(`.*/([^/]+/directory/[0-9a-f]{32})$`)
