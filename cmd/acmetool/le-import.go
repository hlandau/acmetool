package main

import (
	"crypto/x509"
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/acmeutils"
	"github.com/hlandau/acme/storage"
	"github.com/square/go-jose"
	"golang.org/x/net/context"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func cmdImportLE() {
	s, err := storage.New(*stateFlag)
	log.Fatale(err, "storage")

	lePath := *importLEArg
	accountNames, err := getLEAccountNames(lePath)
	log.Fatale(err, "cannot inspect accounts directory - do you have permissions to read the Let's Encrypt directory (i.e. are you root)?")

	// In order to import a Let's Encrypt state directory, we must:
	//   - import the account keys
	//   - import the certificate keys
	//   - import the certificates

	// Import account keys.
	for _, accountName := range accountNames {
		err := importLEAccount(s, lePath, accountName)
		log.Fatale(err, "import account")
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
}

var knownProviderURLs = map[string]struct{}{}

func importLEAccount(s *storage.Store, lePath, accountName string) error {
	providerURL, err := getProviderURLFromAccountName(accountName)
	if err != nil {
		return err
	}

	knownProviderURLs[providerURL] = struct{}{}

	pkPath := filepath.Join(lePath, "accounts", accountName, "private_key.json")
	b, err := ioutil.ReadFile(pkPath)
	if err != nil {
		return err
	}

	k := jose.JsonWebKey{}
	err = k.UnmarshalJSON(b)
	if err != nil {
		return err
	}

	err = s.ImportAccountKey(providerURL, k.Key)
	if err != nil {
		return err
	}

	return nil
}

func importKey(s *storage.Store, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return s.ImportKey(f)
}

func importCert(s *storage.Store, filename string) error {
	certURL, err := determineLECertificateURL(filename)
	if err != nil {
		return err
	}

	return s.ImportCertificate(certURL)
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

	sn := fmt.Sprintf("%036x", c.SerialNumber)
	for u := range knownProviderURLs {
		certURL, err := convertBoulderProviderURLToCertificateURL(u, sn)
		if err != nil {
			continue
		}

		cl := acmeapi.Client{
			DirectoryURL: u,
		}

		crt := acmeapi.Certificate{
			URI: certURL,
		}
		err = cl.LoadCertificate(&crt, context.TODO())
		if err != nil {
			continue
		}

		return certURL, nil
	}

	return "", fmt.Errorf("cannot find certificate URL for %#v (serial %#v)", certFilename, sn)
}

func convertBoulderProviderURLToCertificateURL(providerURL, sn string) (string, error) {
	if !strings.HasSuffix(providerURL, "/directory") {
		return "", fmt.Errorf("does not appear to be a boulder directory URL")
	}

	return providerURL[0:len(providerURL)-9] + "acme/cert/" + sn, nil
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
