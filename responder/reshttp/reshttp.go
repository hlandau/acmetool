// Package reshttp allows multiple goroutines to register challenge responses
// on an HTTP server concurrently.
package reshttp

import (
	"github.com/hlandau/xlog"
	"gopkg.in/tylerb/graceful.v1"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var log, Log = xlog.New("acmetool.reshttp")

type PortClaim interface {
	Close() error
}

type portClaim struct {
	port       *port
	released   bool
	filename   string
	body       []byte
	notifyFunc func()
}

func (pc *portClaim) Close() error {
	mutex.Lock()
	defer mutex.Unlock()

	if pc.released {
		return nil
	}

	delete(pc.port.claims, pc.filename)

	pc.port.refcount--
	if pc.port.refcount == 0 {
		pc.port.Destroy()
	}

	pc.released = true
	return nil
}

type port struct {
	addr     string
	refcount int
	server   *graceful.Server
	claims   map[string]*portClaim
}

func (p *port) Init() error {
	p.claims = map[string]*portClaim{}

	p.server = &graceful.Server{
		NoSignalHandling: true,
		Server: &http.Server{
			Addr:    p.addr,
			Handler: p,
		},
	}

	l, err := net.Listen("tcp", p.addr)
	if err != nil {
		log.Debuge(err, "failed to listen on ", p.addr)
		return err
	}

	log.Debugf("listening on %v", p.addr)

	go func() {
		defer l.Close()
		p.server.Serve(l)
	}()

	return nil
}

func (p *port) Destroy() {
	delete(ports, p.addr)
	p.server.Stop(10 * time.Millisecond)
	<-p.server.StopChan()
}

func (p *port) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !strings.HasPrefix(req.URL.Path, "/.well-known/acme-challenge/") {
		http.NotFound(rw, req)
		return
	}

	fn := req.URL.Path[28:]
	body, notifyFunc := p.getClaim(fn)
	if body == nil {
		http.NotFound(rw, req)
		return
	}

	rw.Header().Set("Content-Type", "text/plain")
	rw.Write(body)

	if notifyFunc != nil {
		notifyFunc()
	}
}

func (p *port) getClaim(filename string) (body []byte, notifyFunc func()) {
	mutex.Lock()
	defer mutex.Unlock()

	pc, ok := p.claims[filename]
	if !ok {
		return nil, nil
	}

	return pc.body, pc.notifyFunc
}

var mutex sync.Mutex
var ports = map[string]*port{}

func AcquirePort(bindAddr, filename string, body []byte, notifyFunc func()) (PortClaim, error) {
	log.Debugf("acquire port %q %q", bindAddr, filename)
	mutex.Lock()
	defer mutex.Unlock()

	p, ok := ports[bindAddr]
	if !ok {
		p = &port{
			addr:     bindAddr,
			refcount: 0,
		}
		err := p.Init()
		if err != nil {
			return nil, err
		}
		ports[bindAddr] = p
	}

	p.refcount++
	pc := &portClaim{
		port:       p,
		filename:   filename,
		body:       body,
		notifyFunc: notifyFunc,
	}
	p.claims[filename] = pc
	return pc, nil
}
