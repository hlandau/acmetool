package interaction

func Auto(c *Challenge) (*Response, error) {
	r, err := Dialog(c)
	if err == nil {
		return r, nil
	}

	return Stdio(c)
}
