package responder

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"gopkg.in/square/go-jose.v1"
)

type proofOfPossessionResponder struct {
	validation []byte
	pk         crypto.PrivateKey
}

func (rcfg *Config) findAcceptablePrivateKey() (crypto.PrivateKey, error) {
	for _, der := range rcfg.AcceptableCertificates {
		crt, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}

		if rcfg.ChallengeConfig.PriorKeyFunc == nil {
			continue
		}

		pk, err := rcfg.ChallengeConfig.PriorKeyFunc(crt.PublicKey)
		if err != nil {
			return nil, err
		}

		if pk != nil {
			return pk, nil
		}
	}

	return nil, nil
}

func newProofOfPossessionResponder(rcfg Config) (Responder, error) {
	if rcfg.Hostname == "" {
		return nil, fmt.Errorf("hostname is required for proofOfPossession")
	}

	pk, err := rcfg.findAcceptablePrivateKey()
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, fmt.Errorf("no acceptable private keys could be found")
	}

	r := &proofOfPossessionResponder{
		pk: pk,
	}

	info := map[string]interface{}{
		"resource": "challenge",
		"type":     "proofOfPossession",
		"identifiers": []acmeapi.Identifier{
			{
				Type:  "dns",
				Value: rcfg.Hostname,
			},
		},
		"accountKey": &jose.JsonWebKey{
			Key: rcfg.AccountKey,
		},
	}

	r.validation, err = json.Marshal(&info)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (r *proofOfPossessionResponder) Start() error {
	return nil
}

func (r *proofOfPossessionResponder) Stop() error {
	return nil
}

func (r *proofOfPossessionResponder) RequestDetectedChan() <-chan struct{} {
	return nil
}

func (r *proofOfPossessionResponder) Validation() json.RawMessage {
	return json.RawMessage(r.validation)
}

func (r *proofOfPossessionResponder) ValidationSigningKey() crypto.PrivateKey {
	return r.pk
}

func init() {
	RegisterResponder("proofOfPossession", newProofOfPossessionResponder)
}
