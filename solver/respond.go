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
	c               *acmeapi.Client
	dnsName         string
	interactionFunc interaction.Func
	ctx             context.Context
	pref            TypePreferencer
	webPath         string
}

func Authorize(c *acmeapi.Client, dnsName, webPath string, interactionFunc interaction.Func, ctx context.Context) (*acmeapi.Authorization, error) {
	as := authState{
		c:               c,
		dnsName:         dnsName,
		interactionFunc: defaultInteraction(interactionFunc),
		ctx:             ctx,
		pref:            PreferFast.Copy(),
		webPath:         webPath,
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
		invalidated, err := CompleteChallenge(as.c, ch, as.dnsName, as.webPath, as.interactionFunc, as.ctx)
		if err != nil {
			delete(as.pref, ch.Type)
			return invalidated, err
		}
	}

	return false, nil
}

// Completes a given challenge, polling it until it is complete. Can be
// cancelled using ctx.
func CompleteChallenge(c *acmeapi.Client, ch *acmeapi.Challenge, dnsName, webPath string, interactionFunc interaction.Func, ctx context.Context) (invalidated bool, err error) {
	r, err := responder.New(responder.Config{
		Type:       ch.Type,
		Token:      ch.Token,
		N:          ch.N,
		AccountKey: c.AccountInfo.AccountKey,
		Hostname:   dnsName,
		WebPath:    webPath,
	})

	if err != nil {
		return false, err
	}

	interactionFunc = defaultInteraction(interactionFunc)

	err = r.Start(interactionFunc)
	if err != nil {
		return false, err
	}

	defer r.Stop()

	err = c.RespondToChallenge(ch, r.Validation())
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
