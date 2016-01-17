// Package acmeutils provides miscellaneous ACME-related utility functions.
package acmeutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

// Load one or more certificates from a sequence of PEM-encoded certificates.
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
func LoadPrivateKey(keyPEMBlock []byte) (crypto.PrivateKey, error) {
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

	pk, err := LoadPrivateKeyDER(keyDERBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return pk, nil
}

// Parse a DER private key. The key can be RSA or ECDSA. PKCS8 containers are
// supported.
func LoadPrivateKeyDER(der []byte) (crypto.PrivateKey, error) {
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

	epk, err := x509.ParseECPrivateKey(der)
	if err == nil {
		return epk, nil
	}

	return nil, fmt.Errorf("failed to parse private key")
}

// Load a PEM CSR from a stream and return it in DER form.
func LoadCSR(pemBlock []byte) ([]byte, error) {
	var derBlock *pem.Block
	for {
		derBlock, pemBlock = pem.Decode(pemBlock)
		if derBlock == nil {
			return nil, fmt.Errorf("failed to parse CSR PEM data")
		}
		if derBlock.Type == "CERTIFICATE REQUEST" {
			break
		}
	}

	return derBlock.Bytes, nil
}

// © 2015—2016 Hugo Landau <hlandau@devever.net>    MIT License
