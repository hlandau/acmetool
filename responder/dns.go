package responder

import (
	"crypto"
	"encoding/json"
	"fmt"
	"gopkg.in/hlandau/acmeapi.v2/acmeutils"
)

type DNSChallengeInfo struct {
	Hostname string
	Body     string
}

type dnsResponder struct {
	rcfg       Config
	validation []byte
	dnsString  string
}

func newDNSResponder(rcfg Config) (Responder, error) {
	s := &dnsResponder{
		rcfg:       rcfg,
		validation: []byte("{}"),
	}

	if rcfg.Hostname == "" {
		return nil, fmt.Errorf("must provide a hostname")
	}

	var err error
	s.dnsString, err = acmeutils.DNSKeyAuthorization(rcfg.AccountKey, rcfg.Token)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Start is a no-op for the DNS method.
func (s *dnsResponder) Start() error {
	// Try hooks.
	if startFunc := s.rcfg.ChallengeConfig.StartHookFunc; startFunc != nil {
		err := startFunc(&DNSChallengeInfo{
			Hostname: s.rcfg.Hostname,
			Body:     s.dnsString,
		})
		return err
	}

	return fmt.Errorf("DNS challenge not supported")
}

// Stop is a no-op for the DNS method.
func (s *dnsResponder) Stop() error {
	// Try hooks.
	if stopFunc := s.rcfg.ChallengeConfig.StopHookFunc; stopFunc != nil {
		err := stopFunc(&DNSChallengeInfo{
			Hostname: s.rcfg.Hostname,
			Body:     s.dnsString,
		})
		log.Warne(err, "failed to uninstall DNS challenge via hook (ignoring)")
		return nil
	}

	return fmt.Errorf("DNS challenge not supported")
}

func (s *dnsResponder) RequestDetectedChan() <-chan struct{} {
	return nil
}

func (s *dnsResponder) Validation() json.RawMessage {
	return json.RawMessage(s.validation)
}

func (s *dnsResponder) ValidationSigningKey() crypto.PrivateKey {
	return nil
}

func init() {
	RegisterResponder("dns-01", newDNSResponder)
}
