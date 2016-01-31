package acmeendpoints

import (
	"fmt"
	"testing"
)

func TestVisit(t *testing.T) {
	ep := map[*Endpoint]struct{}{}
	err := Visit(func(e *Endpoint) error {
		ep[e] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fail()
	}
	_, ok := ep[&LetsEncryptLive]
	if !ok {
		t.Fail()
	}
	_, ok = ep[&LetsEncryptStaging]
	if !ok {
		t.Fail()
	}

	ep = map[*Endpoint]struct{}{}
	e1 := fmt.Errorf("e1")
	i := 0
	err = Visit(func(e *Endpoint) error {
		if i == 1 {
			return e1
		}
		i++
		ep[e] = struct{}{}
		return nil
	})
	if err != e1 {
		t.Fail()
	}
	if len(ep) != 1 {
		t.Fail()
	}
	_, ok = ep[&LetsEncryptLive]
	if !ok {
		t.Fail()
	}
}
