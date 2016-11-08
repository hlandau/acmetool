package acmeapi

import (
	"errors"
	"golang.org/x/net/context"
)

type nonceSource struct {
	pool         map[string]struct{}
	GetNonceFunc func(ctx context.Context) error
}

func (ns *nonceSource) init() {
	if ns.pool != nil {
		return
	}

	ns.pool = map[string]struct{}{}
}

func (ns *nonceSource) Nonce(ctx context.Context) (string, error) {
	ns.init()

	var k string
	for k = range ns.pool {
		break
	}
	if k == "" {
		err := ns.obtainNonce(ctx)
		if err != nil {
			return "", err
		}
		for k = range ns.pool {
			break
		}
		if k == "" {
			return "", errors.New("failed to retrieve additional nonce")
		}
	}

	delete(ns.pool, k)
	return k, nil
}

func (ns *nonceSource) obtainNonce(ctx context.Context) error {
	if ns.GetNonceFunc == nil {
		return errors.New("out of nonces - this should never happen")
	}

	return ns.GetNonceFunc(ctx)
}

func (ns *nonceSource) AddNonce(nonce string) {
	ns.init()
	ns.pool[nonce] = struct{}{}
}

func (ns *nonceSource) WithContext(ctx context.Context) *nonceSourceWithCtx {
	return &nonceSourceWithCtx{ns, ctx}
}

type nonceSourceWithCtx struct {
	nonceSource *nonceSource
	ctx         context.Context
}

func (nc *nonceSourceWithCtx) Nonce() (string, error) {
	return nc.nonceSource.Nonce(nc.ctx)
}
