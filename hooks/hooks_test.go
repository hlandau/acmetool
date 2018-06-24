package hooks

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

const fileTpl = `#!/bin/sh
%s
[ -n "$ACME_STATE_DIR" ] || exit 1
echo NOTIFY-%d >> "$ACME_STATE_DIR/log"
while read line; do
  echo L-$line >> "$ACME_STATE_DIR/log"
done`

var answer = []string{
	`NOTIFY-0
L-a.b
L-c.d
L-e.f.g
NOTIFY-1
L-a.b
L-c.d
L-e.f.g
`,
	`NOTIFY-0
L-a.b
L-c.d
L-e.f.g
NOTIFY-3
L-a.b
L-c.d
L-e.f.g
`,
}

func TestNotify(t *testing.T) {
	dir, err := ioutil.TempDir("", "acme-notify-test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	notify1 := filepath.Join(dir, "notify1")
	notify2 := filepath.Join(dir, "notify2")
	notifyDirs := []string{notify1, notify2}

	for i := 0; i < 2; i++ {
		err = Replace(notifyDirs, "alpha", fmt.Sprintf(fileTpl, "", i*2+0))
		if err != nil {
			t.Fatal(err)
		}

		err = Replace(notifyDirs, "beta", fmt.Sprintf(fileTpl, "#!acmetool-managed!#", i*2+1))
		if err != nil {
			t.Fatal(err)
		}

		os.Remove(filepath.Join(dir, "log"))

		ctx := &Context{
			HookDirs: notifyDirs,
			StateDir: dir,
		}
		err = NotifyLiveUpdated(ctx, []string{"a.b", "c.d", "e.f.g"})
		if err != nil {
			t.Fatal(err)
		}

		b, err := ioutil.ReadFile(filepath.Join(dir, "log"))
		if err != nil {
			t.Fatal(err)
		}

		s := string(b)
		if s != answer[i] {
			t.Fatalf("mismatch: %v != %v", s, answer[i])
		}
	}
}
