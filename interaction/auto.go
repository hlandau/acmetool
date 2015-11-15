package interaction

import "fmt"

var NonInteractive = false

func Auto(c *Challenge) (*Response, error) {
	if NonInteractive {
		return nil, fmt.Errorf("cannot prompt the user: currently non-interactive")
	}

	r, err := Dialog(c)
	if err == nil {
		return r, nil
	}

	return Stdio(c)
}
