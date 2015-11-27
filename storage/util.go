package storage

import "net/url"
import "fmt"
import "crypto"
import "crypto/x509"
import "crypto/rsa"
import "path/filepath"
import "strings"
import "crypto/sha256"
import "encoding/base32"
import "math/big"
import "crypto/rand"
import "io"

func decodeAccountURLPart(part string) (string, error) {
	unesc, err := url.QueryUnescape(part)
	if err != nil {
		return "", err
	}

	p := "https://" + unesc
	u, err := url.Parse(p)
	if err != nil {
		return "", err
	}

	if u.Path == "" {
		u.Path = "/"
	}

	return u.String(), nil
}

func accountURLPart(directoryURL string) (string, error) {
	u, err := url.Parse(directoryURL)
	if err != nil {
		return "", err
	}

	if u.Scheme != "https" {
		return "", fmt.Errorf("scheme must be HTTPS")
	}

	directoryURL = u.String()
	s := directoryURL[8:]
	if u.Path == "/" {
		s = s[0 : len(s)-1]
	}

	return lowerEscapes(url.QueryEscape(s)), nil
}

func lowerEscapes(s string) string {
	b := []byte(s)
	state := 0
	for i := 0; i < len(b); i++ {
		switch state {
		case 0:
			if b[i] == '%' {
				state = 1
			}
		case 1:
			if b[i] == '%' {
				state = 0
			} else {
				state = 2
			}
			b[i] = lowerChar(b[i])
		case 2:
			state = 0
			b[i] = lowerChar(b[i])
		}
	}
	return string(b)
}

func lowerChar(c byte) byte {
	if c >= 'A' && c <= 'F' {
		return c - 'A' + 'a'
	}
	return c
}

// 'root' must be an absolute path.
func pathIsWithin(subject, root string) (bool, error) {
	os := subject
	subject, err := filepath.EvalSymlinks(subject)
	if err != nil {
		log.Errore(err, "eval symlinks: ", os, " ", root)
		return false, err
	}

	subject, err = filepath.Abs(subject)
	if err != nil {
		return false, err
	}

	return strings.HasPrefix(subject, ensureSeparator(root)), nil
}

func ensureSeparator(p string) string {
	if !strings.HasSuffix(p, string(filepath.Separator)) {
		return p + string(filepath.Separator)
	}

	return p
}

func determineKeyIDFromCert(c *x509.Certificate) string {
	h := sha256.New()
	h.Write(c.RawSubjectPublicKeyInfo)
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(h.Sum(nil)), "="))
}

func getPublicKey(pk crypto.PrivateKey) crypto.PublicKey {
	switch pkv := pk.(type) {
	case *rsa.PrivateKey:
		return &pkv.PublicKey
	default:
		panic("unsupported key type")
	}
}

func determineKeyIDFromKey(pk crypto.PrivateKey) (string, error) {
	return determineKeyIDFromKeyIntl(getPublicKey(pk), pk)
}

func determineKeyIDFromKeyIntl(pubk crypto.PublicKey, pk crypto.PrivateKey) (string, error) {
	cc := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	cb, err := x509.CreateCertificate(rand.Reader, cc, cc, pubk, pk)
	if err != nil {
		return "", err
	}

	c, err := x509.ParseCertificate(cb)
	if err != nil {
		return "", err
	}

	return determineKeyIDFromCert(c), nil
}

type psuedoPrivateKey struct {
	pk crypto.PublicKey
}

func (ppk *psuedoPrivateKey) Public() crypto.PublicKey {
	return ppk.pk
}

func (ppk *psuedoPrivateKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return []byte{0}, nil
}

func determineKeyIDFromPublicKey(pubk crypto.PublicKey) (string, error) {
	// Trick crypto/x509 into creating a certificate so we can grab the
	// subjectPublicKeyInfo by giving it a fake private key generating an invalid
	// signature. ParseCertificate doesn't verify the signature so this will
	// work.
	//
	// Yes, this is very hacky, but avoids having to duplicate code in crypto/x509.

	determineKeyIDFromKeyIntl(pubk, psuedoPrivateKey{})

	cc := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	cb, err := x509.CreateCertificate(rand.Reader, cc, cc, pubk, &psuedoPrivateKey{pubk})
	if err != nil {
		return "", err
	}

	c, err := x509.ParseCertificate(cb)
	if err != nil {
		return "", err
	}

	return determineKeyIDFromCert(c), nil
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
