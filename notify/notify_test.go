package notify

import "testing"
import "io/ioutil"
import "os"
import "path/filepath"
import "fmt"

const fileTpl = `#!/bin/sh
[ -n "$ACME_STATE_DIR" ] || exit 1
echo NOTIFY-%d >> "$ACME_STATE_DIR/log"
while read line; do
  echo L-$line >> "$ACME_STATE_DIR/log"
done`

const answer = `NOTIFY-1
L-a.b
L-c.d
L-e.f.g
NOTIFY-2
L-a.b
L-c.d
L-e.f.g
`

func TestNotify(t *testing.T) {
	dir, err := ioutil.TempDir("", "acme-notify-test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.RemoveAll(dir)

	notifyDir := filepath.Join(dir, "notify")
	err = os.Mkdir(notifyDir, 0755)
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(filepath.Join(notifyDir, "alpha"), []byte(fmt.Sprintf(fileTpl, 1)), 0755)
	if err != nil {
		t.Fatal(err)
	}

	err = ioutil.WriteFile(filepath.Join(notifyDir, "beta"), []byte(fmt.Sprintf(fileTpl, 2)), 0755)
	if err != nil {
		t.Fatal(err)
	}

	err = Notify(notifyDir, dir, []string{"a.b", "c.d", "e.f.g"})
	if err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(filepath.Join(dir, "log"))
	if err != nil {
		t.Fatal(err)
	}

	s := string(b)
	if s != answer {
		t.Fatalf("mismatch: %v != %v", s, answer)
	}
}
