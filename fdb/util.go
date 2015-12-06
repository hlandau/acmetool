package fdb

import (
	"io/ioutil"
	"strconv"
	"strings"
)

func String(rs ReadStream, err error) (string, error) {
	if err != nil {
		return "", err
	}

	defer rs.Close()
	b, err := ioutil.ReadAll(rs)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func Bytes(rs ReadStream, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}

	defer rs.Close()
	b, err := ioutil.ReadAll(rs)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func WriteBytes(c *Collection, name string, bs ...[]byte) error {
	f, err := c.Create(name)
	if err != nil {
		return err
	}
	defer f.CloseAbort()

	for _, b := range bs {
		_, err = f.Write(b)
		if err != nil {
			return err
		}
	}

	f.Close()
	return nil
}

func Uint(c *Collection, name string, bits int) (uint64, error) {
	s, err := String(c.Open(name))
	if err != nil {
		return 0, err
	}

	s = strings.TrimSpace(s)
	return strconv.ParseUint(s, 10, bits)
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
