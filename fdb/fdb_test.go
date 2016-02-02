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

	const permissionsfile = `
  
  # This is an example permissions file
  alpha 0604 0705
  alpha/foo  0640 0750
  `
	err = ioutil.WriteFile(filepath.Join(dir, "Permissionsfile"), []byte(permissionsfile), 0644)
	if err != nil {
		t.Fatal(err)
	}

	db, err := Open(Config{
		Path: dir,
		Permissions: []Permission{
			{Path: ".", FileMode: 0644, DirMode: 0755},
			{Path: "alpha", FileMode: 0644, DirMode: 0755},
			{Path: "beta", FileMode: 0600, DirMode: 0700},
			{Path: "tmp", FileMode: 0600, DirMode: 0700},
		},
		PermissionsPath: "Permissionsfile",
	})
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	err = db.Verify()
	if err != nil {
		t.Fatal(err)
	}

	c := db.Collection("alpha/foo/x")
	if c.DB() != db {
		panic("...")
	}

	if c.Name() != "alpha/foo/x" {
		panic(c.Name())
	}

	if c.OSPath("") != filepath.Join(dir, "alpha/foo/x") {
		panic(c.OSPath(""))
	}

	if c.OSPath("xyz") != filepath.Join(dir, "alpha/foo/x/xyz") {
		panic(c.OSPath("xyz"))
	}

	cc := db.Collection("alpha").Collection("foo").Collection("x")
	if cc.OSPath("xyz") != filepath.Join(dir, "alpha/foo/x/xyz") {
		panic(c.OSPath("xyz"))
	}

	b := []byte("\r\n\t  42 \n\n")
	err = WriteBytes(c, "xyz", b)
	if err != nil {
		t.Fatal(err)
	}

	n, err := Uint(c, "xyz", 31)
	if err != nil {
		t.Fatal(err)
	}
	if n != 42 {
		t.Fatalf("expected 42, got %v", n)
	}

	if !Exists(c, "xyz") {
		t.Fatalf("expected xyz to exist")
	}

	if Exists(c, "xyz1") {
		t.Fatalf("did not expect xyz1 to exist")
	}

	fi, err := os.Stat(c.OSPath("xyz"))
	if err != nil {
		t.Fatal(err)
	}

	if fi.Mode() != 0640 {
		t.Fatal("unexpected mode")
	}

	err = CreateEmpty(db.Collection("alpha"), "nak")
	if err != nil {
		t.Fatal(err)
	}

	fi, err = os.Stat(db.Collection("alpha").OSPath("nak"))
	if err != nil {
		t.Fatal(err)
	}

	if fi.Mode() != 0604 {
		t.Fatal("unexpected mode")
	}

	err = CreateEmpty(c, "xyz1")
	if err != nil {
		t.Fatal(err)
	}

	if !Exists(c, "xyz1") {
		t.Fatalf("expected xyz1 to exist")
	}

	err = c.Delete("xyz1")
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

	err = c.WriteLink("lnk", Link{Target: "alpha/foo/x/xyz"})
	if err != nil {
		t.Fatal(err)
	}

	lnk, err := c.ReadLink("lnk")
	if err != nil {
		t.Fatal(err)
	}

	if lnk.Target != "alpha/foo/x/xyz" {
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
