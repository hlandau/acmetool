package acmeapi

type nonceSource struct {
	pool map[string]struct{}
}

func (ns *nonceSource) init() {
	if ns.pool != nil {
		return
	}

	ns.pool = map[string]struct{}{}
}

func (ns *nonceSource) Nonce() (string, error) {
	ns.init()

	var k string
	for k = range ns.pool {
		break
	}
	if k == "" {
		return ns.obtainNonce()
	}

	delete(ns.pool, k)
	return k, nil
}

func (ns *nonceSource) obtainNonce() (string, error) {
	panic("...")
}

func (ns *nonceSource) AddNonce(nonce string) {
	ns.init()
	ns.pool[nonce] = struct{}{}
}
