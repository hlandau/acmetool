package interaction

import (
	"fmt"
	"github.com/hlandau/xlog"
)

var log, Log = xlog.New("acme.interactor")

// Used by Auto. If this is set, only autoresponses can be used. Any challenge
// without an autoresponse fails. --batch.
var NonInteractive = false

type autoInteractor struct{}

// Interactor which automatically uses the most suitable challenge method.
var Auto Interactor = autoInteractor{}

// Used by Auto. If this is non-nil, all challenges are directed to it. There
// is no fallback if the interceptor fails. Autoresponses and NonInteractive
// take precedence over this.
var Interceptor Interactor

// Used by Auto. Do not use the Dialog mode. --stdio.
var NoDialog = false

var responsesReceived = map[string]*Response{}

func (ai autoInteractor) Prompt(c *Challenge) (*Response, error) {
	res, err := ai.prompt(c)
	if err == nil && c.UniqueID != "" {
		responsesReceived[c.UniqueID] = res
	}

	return res, err
}

// Returns a map from challenge UniqueIDs to responses received for those
// UniqueIDs. Do not mutate the returned map.
func ResponsesReceived() map[string]*Response {
	return responsesReceived
}

func (autoInteractor) prompt(c *Challenge) (*Response, error) {
	r, err := Responder.Prompt(c)
	if err == nil || c.Implicit {
		return r, err
	}
	log.Infoe(err, "interaction auto-responder couldn't give a canned response")

	if NonInteractive {
		return nil, fmt.Errorf("cannot prompt the user: currently non-interactive; try running without --batch flag")
	}

	if Interceptor != nil {
		return Interceptor.Prompt(c)
	}

	if !NoDialog {
		r, err := Dialog.Prompt(c)
		if err == nil {
			return r, nil
		}
	}

	return Stdio.Prompt(c)
}

type dummySink struct{}

func (dummySink) Close() error {
	return nil
}

func (dummySink) SetProgress(n, ofM int) {
}

func (dummySink) SetStatusLine(status string) {
}

func (autoInteractor) Status(info *StatusInfo) (StatusSink, error) {
	if NonInteractive {
		return dummySink{}, nil
	}

	if Interceptor != nil {
		s, err := Interceptor.Status(info)
		if err != nil {
			return dummySink{}, nil
		}
		return s, err
	}

	if !NoDialog {
		r, err := Dialog.Status(info)
		if err == nil {
			return r, nil
		}
	}

	return Stdio.Status(info)
}
