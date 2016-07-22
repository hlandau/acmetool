// Package solver figures out how to complete authorizations and completes them
// by instantiating responders.
package solver

import (
	"fmt"
	"github.com/hlandau/acme/acmeapi"
	"github.com/hlandau/acme/responder"
	denet "github.com/hlandau/goutils/net"
	"github.com/hlandau/xlog"
	"golang.org/x/net/context"
	"time"
)

var log, Log = xlog.New("acme.solver")

// Returned if all combinations fail.
var ErrFailedAllCombinations = fmt.Errorf("failed all combinations")

type authState struct {
	c            *acmeapi.Client
	dnsName      string
	ccfg         responder.ChallengeConfig
	ctx          context.Context
	pref         TypePreferencer
	webPaths     []string
	listenAddrs  []string
	priorKeyFunc responder.PriorKeyFunc
}

// Attempts to authorize a hostname using the given client. webPaths and
// priorKeyFunc are passed to responders. Returns the successfully validated
// authorization on success.
func Authorize(c *acmeapi.Client, dnsName string, ccfg responder.ChallengeConfig, ctx context.Context) (*acmeapi.Authorization, error) {
	as := authState{
		c:       c,
		dnsName: dnsName,
		ctx:     ctx,
		pref:    PreferFast.Copy(),
		ccfg:    ccfg,
	}

	for {
		az, fatal, err := as.authorize()
		if err == nil {
			return az, nil
		}

		if fatal {
			return nil, err
		}
	}
}

func (as *authState) authorize() (az *acmeapi.Authorization, fatal bool, err error) {
	az, err = as.c.NewAuthorization(as.dnsName, as.ctx)
	if err != nil {
		return nil, true, err
	}

	SortCombinations(az, as.pref)

	for _, com := range az.Combinations {
		invalidated, err := as.attemptCombination(az, com)
		if err != nil {
			if !invalidated {
				continue
			}

			// The combination failed and failed challenge types have been removed
			// from the preference map. Assume that a newly created authorization
			// will offer the same combinations. So, if we still don't have a
			// viable combination, we fail here rather than creating an authorization
			// that won't get used.
			if !as.haveAnyViableCombinations(az) {
				break
			}

			return nil, false, err
		}
		return az, false, nil
	}

	return nil, true, ErrFailedAllCombinations
}

func (as *authState) haveAnyViableCombinations(az *acmeapi.Authorization) bool {
	for _, com := range az.Combinations {
		for _, i := range com {
			ch := az.Challenges[i]
			p, ok := as.pref[ch.Type]
			if ok && p > NonviableThreshold {
				return true
			}
		}
	}
	return false
}

func (as *authState) attemptCombination(az *acmeapi.Authorization, combination []int) (invalidated bool, err error) {
	for _, i := range combination {
		ch := az.Challenges[i]
		invalidated, err := CompleteChallenge(as.c, ch, as.dnsName, as.ccfg, as.ctx)
		if err != nil {
			delete(as.pref, ch.Type)
			return invalidated, err
		}
	}

	return false, nil
}

// Completes a given challenge, polling it until it is complete. Can be
// cancelled using ctx.
//
// dnsName is the hostname which is being authorized. webPaths and priorKeyFunc
// are passed to responders.
//
// The return value indicates whether the whole authorization has been invalidated
// (set to "failed" status) as a result of an error. In this case a new authorization
// must be created.
func CompleteChallenge(c *acmeapi.Client, ch *acmeapi.Challenge, dnsName string, ccfg responder.ChallengeConfig, ctx context.Context) (invalidated bool, err error) {
	log.Debugf("attempting challenge type %s", ch.Type)

	var certs [][]byte
	for _, c := range ch.Certs {
		certs = append(certs, c)
	}

	r, err := responder.New(responder.Config{
		Type:                   ch.Type,
		Token:                  ch.Token,
		AccountKey:             c.AccountKey,
		Hostname:               dnsName,
		AcceptableCertificates: certs,
		ChallengeConfig:        ccfg,
	})

	if err != nil {
		log.Debuge(err, "challenge instantiation failed")
		return false, err
	}

	err = r.Start()
	if err != nil {
		log.Debuge(err, "challenge start failed")
		return false, err
	}

	defer r.Stop()

	err = c.RespondToChallenge(ch, r.Validation(), r.ValidationSigningKey(), ctx)
	if err != nil {
		return false /* ??? */, err
	}

	b := denet.Backoff{
		InitialDelay: 5 * time.Second,
		MaxDelay:     30 * time.Second,
	}

	for {
		log.Debug("waiting to poll challenge")
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-r.RequestDetectedChan():
			log.Debug("request detected")
		case <-time.After(b.NextDelay()):
		}

		log.Debug("querying challenge status")
		err := c.WaitLoadChallenge(ch, ctx)
		if err != nil {
			return false, err
		}

		if ch.Status.Final() {
			log.Debug("challenge now in final state")
			break
		}
	}

	if ch.Status != "valid" {
		return true, fmt.Errorf("challenge failed with status %#v", ch.Status)
	}

	return false, nil
}
