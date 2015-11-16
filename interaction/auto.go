package interaction

import "fmt"

var NonInteractive = false

type autoInteractor struct{}

var Auto Interactor = autoInteractor{}

func (autoInteractor) Prompt(c *Challenge) (*Response, error) {
	if NonInteractive {
		return nil, fmt.Errorf("cannot prompt the user: currently non-interactive")
	}

	r, err := Dialog.Prompt(c)
	if err == nil {
		return r, nil
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

	r, err := Dialog.Status(info)
	if err == nil {
		return r, nil
	}

	return Stdio.Status(info)
}
