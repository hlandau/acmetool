// +build cgo

package fdb

import (
	"reflect"
	"strings"
	"testing"
)

func TestParsePerm(t *testing.T) {
	var tests = []struct {
		In    string
		Out   []Permission
		Erase map[string]struct{}
	}{
		{``, nil, map[string]struct{}{}},
		{`

     # this is a comment
     foo/bar 0644 0755
     foo/*/baz  0640  0750  
     alpha  0644 0755  root root
     beta  0644 0755  42 42
     gamma  0644 0755  $r $r
     delta   inherit
     x 0644 0755 root -
     y 0644 0755 - root
     `, []Permission{
			{Path: "foo/bar", FileMode: 0644, DirMode: 0755},
			{Path: "foo/*/baz", FileMode: 0640, DirMode: 0750},
			{Path: "alpha", FileMode: 0644, DirMode: 0755, UID: "root", GID: "root"},
			{Path: "beta", FileMode: 0644, DirMode: 0755, UID: "42", GID: "42"},
			{Path: "gamma", FileMode: 0644, DirMode: 0755, UID: "$r", GID: "$r"},
			{Path: "x", FileMode: 0644, DirMode: 0755, UID: "root", GID: ""},
			{Path: "y", FileMode: 0644, DirMode: 0755, UID: "", GID: "root"},
		}, map[string]struct{}{"delta": struct{}{}}},
	}

	for _, tst := range tests {
		ps, erase, err := parsePermissions(strings.NewReader(tst.In))
		if err != nil {
			t.Fatalf("error parsing permissions: %v", err)
		}

		if !reflect.DeepEqual(ps, tst.Out) {
			t.Fatalf("permissions don't match: got %#v, expected %#v", ps, tst.Out)
		}

		if !reflect.DeepEqual(erase, tst.Erase) {
			t.Fatalf("erase list doesn't match: got %v, expected %v", erase, tst.Erase)
		}
	}
}
