package fdb

import (
	"io/ioutil"
	"strconv"
	"strings"
)

// Read a file as a string. Use like this:
//
//   s, err := String(c.Open("file"))
//
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

// Read a file as []byte. Use like this:
//
//   s, err := Bytes(c.Open("file"))
//
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

// Create an empty file, overwriting it if it exists.
func CreateEmpty(c *Collection, name string) error {
	f, err := c.Create(name)
	if err != nil {
		return err
	}

	f.Close()
	return nil
}

// Determine whether a file exists.
func Exists(c *Collection, name string) bool {
	f, err := c.Open(name)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

// Write bytes to a file with the given name in the given collection.
//
// The byte arrays are concatenated in the given order.
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

// Retrieve an unsigned integer in decimal form from a file with the given name
// in the given collection. bits is passed to ParseUint.
func Uint(c *Collection, name string, bits int) (uint64, error) {
	s, err := String(c.Open(name))
	if err != nil {
		return 0, err
	}

	s = strings.TrimSpace(s)
	return strconv.ParseUint(s, 10, bits)
}
