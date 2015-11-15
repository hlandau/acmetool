package responder

import "encoding/json"
import "net"
import "net/http"
import "gopkg.in/tylerb/graceful.v1"
import "github.com/hlandau/acme/interaction"

type httpResponder struct {
	serveMux            *http.ServeMux
	response            []byte
	server              graceful.Server
	requestDetectedChan chan struct{}
	ka                  []byte
	validation          []byte
}

func newHTTP(rcfg Config) (Responder, error) {
	s := &httpResponder{
		serveMux: http.NewServeMux(),
		server: graceful.Server{
			NoSignalHandling: true,
			Server: &http.Server{
				Addr: ":80",
			},
		},
		requestDetectedChan: make(chan struct{}, 1),
	}

	// Configure the HTTP server
	s.serveMux.HandleFunc("/.well-known/acme-challenge/"+rcfg.Token, s.handle)
	s.server.Handler = s.serveMux

	ka, err := rcfg.keyAuthorization()
	if err != nil {
		return nil, err
	}

	s.ka = []byte(ka)

	s.validation, err = rcfg.responseJSON("http-01")
	if err != nil {
		return nil, err
	}

	return s, nil
}

// HTTP handler.
func (s *httpResponder) handle(rw http.ResponseWriter, req *http.Request) {
	// Send the precomputed response.
	rw.Header().Set("Content-Type", "text/plain")
	rw.Write(s.ka)
	s.notify()
}

func (s *httpResponder) notify() {
	// Notify callers that a request has been detected.
	select {
	case s.requestDetectedChan <- struct{}{}:
	default:
	}
}

// Start handling HTTP requests.
func (s *httpResponder) Start(interactionFunc interaction.Func) error {
	l, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return err
	}

	go func() {
		s.server.Serve(l)
	}()

	return nil
}

// Stop handling HTTP requests.
func (s *httpResponder) Stop() error {
	s.server.Stop(0)
	<-s.server.StopChan()
	return nil
}

func (s *httpResponder) RequestDetectedChan() <-chan struct{} {
	return s.requestDetectedChan
}

func (s *httpResponder) Validation() json.RawMessage {
	return json.RawMessage(s.validation)
}

func init() {
	RegisterResponder("http-01", newHTTP)
}
