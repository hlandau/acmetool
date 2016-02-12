package responder

import (
	"crypto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/hlandau/acme/acmeapi/acmeutils"
	"net"
	"strings"
)

type TLSSNIChallengeInfo struct {
	Hostname1, Hostname2 string // must appear in certificate
	Certificate          []byte
	Key                  crypto.PrivateKey
}

type tlssniResponder struct {
	requestDetectedChan chan struct{}
	notifySupported     bool
	rcfg                Config

	stoppedChan        chan struct{}
	cfg                *tls.Config
	l                  net.Listener
	validation         []byte
	validationHostname string
	cert               []byte
	privateKey         crypto.PrivateKey
}

func newTLSSNIResponder(rcfg Config) (Responder, error) {
	r := &tlssniResponder{
		rcfg:                rcfg,
		requestDetectedChan: make(chan struct{}, 1),
		stoppedChan:         make(chan struct{}),
		notifySupported:     true,
	}

	// Validation hostname.
	var err error
	r.validationHostname, err = acmeutils.TLSSNIHostname(rcfg.AccountKey, rcfg.Token)
	if err != nil {
		return nil, err
	}

	// Certificate and private key.
	r.cert, r.privateKey, err = acmeutils.CreateTLSSNICertificate(r.validationHostname)
	if err != nil {
		return nil, err
	}

	c := &tls.Certificate{
		Certificate: [][]byte{r.cert},
		PrivateKey:  r.privateKey,
	}

	r.cfg = &tls.Config{
		Certificates: []tls.Certificate{*c},
	}

	// Validation response.
	r.validation, err = acmeutils.ChallengeResponseJSON(rcfg.AccountKey, rcfg.Token, "tls-sni-01")
	if err != nil {
		return nil, err
	}

	return r, nil
}

// Internal use only. This can be used to change the port the TLSSNI responder
// listens on for development purposes.
var InternalTLSSNIPort uint16 = 443

func (r *tlssniResponder) Start() error {
	listenErr := r.startListener()
	log.Debuge(listenErr, "failed to start TLS-SNI listener")

	// Try hooks.
	var hookErr error
	if startFunc := r.rcfg.ChallengeConfig.StartHookFunc; startFunc != nil {
		hookErr = startFunc(&TLSSNIChallengeInfo{
			Hostname1:   r.validationHostname,
			Hostname2:   r.validationHostname,
			Certificate: r.cert,
			Key:         r.privateKey,
		})
		log.Debuge(hookErr, "failed to install TLS-SNI challenge via hook")
	}

	if listenErr != nil && hookErr != nil {
		return listenErr
	}

	err := r.selfTest()
	if err != nil {
		log.Debuge(err, "tls-sni-01 self-test failed")
		r.Stop()
		return err
	}

	return nil
}

func (r *tlssniResponder) startListener() error {
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
	if r.l != nil {
		r.l.Close()
		<-r.stoppedChan
		r.l = nil
	}

	// Try hooks.
	if stopFunc := r.rcfg.ChallengeConfig.StopHookFunc; stopFunc != nil {
		err := stopFunc(&TLSSNIChallengeInfo{
			Hostname1:   r.validationHostname,
			Hostname2:   r.validationHostname,
			Certificate: r.cert,
			Key:         r.privateKey,
		})
		log.Errore(err, "failed to uninstall TLS-SNI challenge via hook")
	}

	return nil
}

func containsHostname(hostname string, hostnames []string) bool {
	for _, x := range hostnames {
		if strings.TrimSuffix(strings.ToLower(x), ".") == hostname {
			return true
		}
	}
	return false
}

func (r *tlssniResponder) selfTest() error {
	if r.rcfg.Hostname == "" {
		return nil
	}

	conn, err := tls.Dial("tcp", net.JoinHostPort(r.rcfg.Hostname, fmt.Sprintf("%d", InternalTLSSNIPort)), &tls.Config{
		ServerName:         r.validationHostname,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}

	defer conn.Close()
	err = conn.Handshake()
	if err != nil {
		return err
	}

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) != 1 {
		return fmt.Errorf("when doing self-test, got %d certificates, expected 1", len(certs))
	}

	if !containsHostname(r.validationHostname, certs[0].DNSNames) {
		return fmt.Errorf("certificate does not contain expected challenge name")
	}

	// If we detected a request, we support notifications, otherwise we don't.
	select {
	case <-r.requestDetectedChan:
	default:
		r.notifySupported = false
	}

	// Drain the notification channel in case we somehow made several requests.
L:
	for {
		select {
		case <-r.requestDetectedChan:
		default:
			break L
		}
	}

	return nil
}

func (r *tlssniResponder) notify() {
	select {
	case r.requestDetectedChan <- struct{}{}:
	default:
	}
}

func (r *tlssniResponder) RequestDetectedChan() <-chan struct{} {
	if !r.notifySupported {
		return nil
	}

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
