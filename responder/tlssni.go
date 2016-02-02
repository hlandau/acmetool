package responder

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"time"
)

type tlssniResponder struct {
	requestDetectedChan chan struct{}
	stoppedChan         chan struct{}
	cfg                 *tls.Config
	l                   net.Listener
	validation          []byte
}

func newTLSSNIResponder(rcfg Config) (Responder, error) {
	if rcfg.N == 0 {
		rcfg.N = 2
		// boulder doesn't return N currently.
		//return nil, fmt.Errorf("tls-sni-01: N must be nonzero")
	}

	r := &tlssniResponder{
		requestDetectedChan: make(chan struct{}, 1),
		stoppedChan:         make(chan struct{}),
	}

	ka, err := rcfg.keyAuthorization()
	if err != nil {
		return nil, err
	}

	zN := make([]string, 0, rcfg.N)
	zN = append(zN, hashBytesHex([]byte(ka)))
	for i := 1; i < rcfg.N; i++ {
		zN = append(zN, hashBytesHex([]byte(zN[i-1])))
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	certs := map[string]*tls.Certificate{}

	r.cfg = &tls.Config{
		GetCertificate: func(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
			crt := certs[ch.ServerName]
			return crt, nil
		},
	}

	for i := 0; i < rcfg.N; i++ {
		name := zN[i][0:32] + "." + zN[i][32:64] + ".acme.invalid"

		xc := x509.Certificate{
			Subject: pkix.Name{
				CommonName: name,
			},
			Issuer: pkix.Name{
				CommonName: name,
			},
			SerialNumber:          big.NewInt(1),
			NotBefore:             time.Now().Add(-24 * time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			DNSNames:              []string{name},
		}

		b, err := x509.CreateCertificate(rand.Reader, &xc, &xc, &pk.PublicKey, pk)
		if err != nil {
			return nil, err
		}

		c := &tls.Certificate{
			Certificate: [][]byte{
				b,
			},
			PrivateKey: pk,
		}

		if i == 0 {
			r.cfg.Certificates = []tls.Certificate{*c}
		}

		certs[name] = c
		//r.cfg.NameToCertificate[name] = c
	}

	r.validation, err = rcfg.responseJSON("tls-sni-01")
	if err != nil {
		return nil, err
	}

	return r, nil
}

// Internal use only. This can be used to change the port the TLSSNI responder
// listens on for development purposes.
var InternalTLSSNIPort uint16 = 443

func (r *tlssniResponder) Start() error {
	l, err := tls.Listen("tcp", fmt.Sprintf(":%d", InternalTLSSNIPort), r.cfg)
	if err != nil {
		return err
	}

	r.l = l
	go func() {
		defer close(r.stoppedChan)
		defer l.Close()

		for {
			c, err := l.Accept()
			if err != nil {
				break
			}

			c.(*tls.Conn).Handshake() // Ignore error
			c.Close()
			r.notify()
		}
	}()

	return nil
}

func (r *tlssniResponder) Stop() error {
	r.l.Close()
	<-r.stoppedChan
	return nil
}

func (r *tlssniResponder) notify() {
	select {
	case r.requestDetectedChan <- struct{}{}:
	default:
	}
}

func (r *tlssniResponder) RequestDetectedChan() <-chan struct{} {
	return r.requestDetectedChan
}

func (r *tlssniResponder) Validation() json.RawMessage {
	return json.RawMessage(r.validation)
}

func (r *tlssniResponder) ValidationSigningKey() crypto.PrivateKey {
	return nil
}

func init() {
	RegisterResponder("tls-sni-01", newTLSSNIResponder)
}
