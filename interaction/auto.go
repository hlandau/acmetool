package interaction

import "fmt"

var NonInteractive = false

type autoInteractor struct{}

var Auto Interactor = autoInteractor{}

var Interceptor Interactor = nil

func (autoInteractor) Prompt(c *Challenge) (*Response, error) {
	if NonInteractive {
		return nil, fmt.Errorf("cannot prompt the user: currently non-interactive")
	}

	if Interceptor != nil {
		return Interceptor.Prompt(c)
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

	if Interceptor != nil {
		s, err := Interceptor.Status(info)
		if err != nil {
			return dummySink{}, nil
		}
		return s, err
	}

	r, err := Dialog.Status(info)
	if err == nil {
		return r, nil
	}

	return Stdio.Status(info)
}
