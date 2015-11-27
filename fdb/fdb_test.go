package fdb

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestFDB(t *testing.T) {
	dir, err := ioutil.TempDir("", "acmefdbtest")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	db, err := Open(Config{
		Path: dir,
		Permissions: []Permission{
			{Path: ".", FileMode: 0644, DirMode: 0755},
			{Path: "alpha", FileMode: 0644, DirMode: 0755},
			{Path: "beta", FileMode: 0600, DirMode: 0700},
			{Path: "tmp", FileMode: 0600, DirMode: 0700},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	err = db.Verify()
	if err != nil {
		t.Fatal(err)
	}

	c := db.Collection("alpha/foo")
	if c.DB() != db {
		panic("...")
	}

	if c.Name() != "alpha/foo" {
		panic(c.Name())
	}

	if c.OSPath("") != filepath.Join(dir, "alpha/foo") {
		panic(c.OSPath(""))
	}

	if c.OSPath("xyz") != filepath.Join(dir, "alpha/foo/xyz") {
		panic(c.OSPath("xyz"))
	}

	b := []byte("Test file")
	err = WriteBytes(c, "xyz", b)
	if err != nil {
		t.Fatal(err)
	}

	f, err := c.Create("xyz")
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.Write([]byte("blah blah blah."))
	if err != nil {
		t.Fatal(err)
	}

	err = f.CloseAbort()
	if err != nil {
		t.Fatal(err)
	}

	b2, err := Bytes(c.Open("xyz"))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(b, b2) {
		t.Fatal("mismatch")
	}

	s2, err := String(c.Open("xyz"))
	if err != nil {
		t.Fatal(err)
	}

	if s2 != string(b2) {
		t.Fatal("mismatch")
	}

	err = c.WriteLink("lnk", Link{Target: "alpha/foo/xyz"})
	if err != nil {
		t.Fatal(err)
	}

	lnk, err := c.ReadLink("lnk")
	if err != nil {
		t.Fatal(err)
	}

	if lnk.Target != "alpha/foo/xyz" {
		t.Fatal(lnk.Target)
	}

	b2, err = Bytes(c.Openl("lnk"))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(b, b2) {
		t.Fatal("mismatch")
	}

	err = db.Verify()
	if err != nil {
		t.Fatal(err)
	}

	names, err := c.List()
	if err != nil {
		t.Fatal(err)
	}

	correctNames := []string{"lnk", "xyz"}
	if !reflect.DeepEqual(names, correctNames) {
		t.Fatalf("wrong names: %v != %v", names, correctNames)
	}

	err = c.Delete("xyz")
	if err != nil {
		t.Fatal(err)
	}

	err = db.Verify()
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.Open("lnk")
	if err == nil {
		t.Fatal("lnk should have been removed")
	}

	err = db.Verify()
	if err != nil {
		t.Fatal(err)
	}
}

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
