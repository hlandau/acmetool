package acmeapi

import "crypto"
import "crypto/rsa"
import "crypto/ecdsa"
import "crypto/x509"
import "encoding/pem"
import "fmt"
import "io"
import "io/ioutil"
import "strings"

func LoadCertificates(pemBlock []byte) ([][]byte, error) {
	var derBlock *pem.Block
	var certs [][]byte
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			break
		}
		if derBlock.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("is not a certificate")
		}

		certs = append(certs, derBlock.Bytes)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return certs, nil
}

// Load a PEM private key from a stream.
func LoadPrivateKey(r io.Reader) (crypto.PrivateKey, error) {
	keyPEMBlock, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			return nil, fmt.Errorf("failed to parse key PEM data")
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
	}

	pk, err := ParsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// Parse a DER private key.
func ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	pk, err := x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		return pk, nil
	}

	pk2, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		switch pk2 := pk2.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return pk2, nil
		default:
			return nil, fmt.Errorf("unknown private key type")
		}
	}

	if pk, err := x509.ParseECPrivateKey(der); err == nil {
		return pk, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// Load a PEM CSR from a stream and return it in DER form.
func LoadCSR(r io.Reader) ([]byte, error) {
	pemBlock, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var derBlock *pem.Block
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			return nil, fmt.Errorf("failed to parse CSR PEM data")
		}
		if derBlock.Type == "NEW CERTIFICATE REQUEST" {
			break
		}
	}

	return derBlock.Bytes, nil
}
