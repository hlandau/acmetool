// Package solver figures out how to complete authorizations and completes them
// by instantiating responders.
package solver

import "github.com/hlandau/acme/acmeapi"
import "github.com/hlandau/acme/responder"
import "github.com/hlandau/acme/interaction"
import denet "github.com/hlandau/degoutils/net"
import "time"
import "fmt"
import "golang.org/x/net/context"
import "github.com/hlandau/xlog"

var log, Log = xlog.New("acme.solver")

var ErrFailedAllCombinations = fmt.Errorf("failed all combinations")

type authState struct {
	c            *acmeapi.Client
	dnsName      string
	interactor   interaction.Interactor
	ctx          context.Context
	pref         TypePreferencer
	webPath      string
	priorKeyFunc responder.PriorKeyFunc
}

func Authorize(c *acmeapi.Client, dnsName, webPath string, interactor interaction.Interactor, priorKeyFunc responder.PriorKeyFunc, ctx context.Context) (*acmeapi.Authorization, error) {
	as := authState{
		c:            c,
		dnsName:      dnsName,
		interactor:   defaultInteraction(interactor),
		ctx:          ctx,
		pref:         PreferFast.Copy(),
		webPath:      webPath,
		priorKeyFunc: priorKeyFunc,
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
	az, err = as.c.NewAuthorization(as.dnsName)
	if err != nil {
		return nil, true, err
	}

	SortCombinations(az, as.pref)

	for _, com := range az.Combinations {
		invalidated, err := as.attemptCombination(az, com)
		if err != nil {
			if invalidated {
				return nil, false, err
			} else {
				continue
			}
		}
		return az, false, nil
	}

	return nil, true, ErrFailedAllCombinations
}

func (as *authState) attemptCombination(az *acmeapi.Authorization, combination []int) (invalidated bool, err error) {
	for _, i := range combination {
		ch := az.Challenges[i]
		invalidated, err := CompleteChallenge(as.c, ch, as.dnsName, as.webPath, as.interactor, as.priorKeyFunc, as.ctx)
		if err != nil {
			delete(as.pref, ch.Type)
			return invalidated, err
		}
	}

	return false, nil
}

// Completes a given challenge, polling it until it is complete. Can be
// cancelled using ctx.
func CompleteChallenge(c *acmeapi.Client, ch *acmeapi.Challenge, dnsName, webPath string, interactor interaction.Interactor, priorKeyFunc responder.PriorKeyFunc, ctx context.Context) (invalidated bool, err error) {
	log.Debugf("attempting challenge type %s", ch.Type)

	var certs [][]byte
	for _, c := range ch.Certs {
		certs = append(certs, c)
	}

	r, err := responder.New(responder.Config{
		Type:                   ch.Type,
		Token:                  ch.Token,
		N:                      ch.N,
		AccountKey:             c.AccountInfo.AccountKey,
		Hostname:               dnsName,
		WebPath:                webPath,
		AcceptableCertificates: certs,
		PriorKeyFunc:           priorKeyFunc,
	})

	if err != nil {
		log.Debuge(err, "challenge instantiation failed")
		return false, err
	}

	interactor = defaultInteraction(interactor)

	err = r.Start(interactor)
	if err != nil {
		log.Debuge(err, "challenge start failed")
		return false, err
	}

	defer r.Stop()

	err = c.RespondToChallenge(ch, r.Validation(), r.ValidationSigningKey())
	if err != nil {
		return false /* ??? */, err
	}

	b := denet.Backoff{
		InitialDelay: 5 * time.Second,
		MaxDelay:     30 * time.Second,
	}

	for {
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-r.RequestDetectedChan():
		case <-time.After(b.NextDelay()):
		}

		err := c.WaitLoadChallenge(ch, ctx)
		if err != nil {
			return false, err
		}

		if ch.Status.Final() {
			break
		}
	}

	if ch.Status != "valid" {
		return true, fmt.Errorf("challenge failed with status %#v", ch.Status)
	}

	return false, nil
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
