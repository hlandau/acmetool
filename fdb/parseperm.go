package fdb

import (
	"bufio"
	"fmt"
	"gopkg.in/hlandau/svcutils.v1/passwd"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var rePermissionLine = regexp.MustCompile(`^(?P<path>[^\s]+)\s+(?P<value>inherit|(?P<fileMode>[0-7]{3,4})\s+(?P<dirMode>[0-7]{3,4})(\s+(?P<uid>[^\s]+)\s+(?P<gid>[^\s]+))?)$`)

func parsePermissions(r io.Reader) (ps []Permission, erasePaths map[string]struct{}, err error) {
	br := bufio.NewReader(r)
	Lnum := 0
	erasePaths = map[string]struct{}{}
	seenPaths := map[string]struct{}{}

	for {
		Lnum++
		L, err := br.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}

		L = strings.TrimSpace(L)
		if L == "" || strings.HasPrefix(L, "#") {
			continue
		}

		// keys/*/privkey 0640 0750 - -
		m := rePermissionLine.FindStringSubmatch(L)
		if m == nil {
			return nil, nil, fmt.Errorf("line %d: badly formatted line: %q", Lnum, L)
		}

		path := filepath.Clean(m[1])
		if path == ".." || strings.HasPrefix(path, "../") || filepath.IsAbs(path) {
			return nil, nil, fmt.Errorf("line %d: path must remain within the DB root: %q", Lnum, L)
		}

		if _, seen := seenPaths[path]; seen {
			return nil, nil, fmt.Errorf("line %d: duplicate path entry: %q", Lnum, L)
		}

		seenPaths[path] = struct{}{}
		if m[2] == "inherit" {
			erasePaths[path] = struct{}{}
			continue
		}

		fileMode, err := strconv.ParseUint(m[3], 8, 12)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: invalid file mode: %q", Lnum, m[3])
		}

		dirMode, err := strconv.ParseUint(m[4], 8, 12)
		if err != nil {
			return nil, nil, fmt.Errorf("line %d: invalid dir mode: %q", Lnum, m[4])
		}

		// Validate UID
		uid := m[6]
		if uid == "-" {
			uid = ""
		}
		if uid != "" && uid != "$r" {
			_, err := passwd.ParseUID(uid)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d: invalid UID: %q: %v", Lnum, uid, err)
			}
		}

		// Validate GID
		gid := m[7]
		if gid == "-" {
			gid = ""
		}
		if gid != "" && gid != "$r" {
			_, err = passwd.ParseGID(gid)
			if err != nil {
				return nil, nil, fmt.Errorf("line %d: invalid GID: %q: %v", Lnum, gid, err)
			}
		}

		//
		p := Permission{
			Path:     path,
			FileMode: os.FileMode(fileMode),
			DirMode:  os.FileMode(dirMode),
			UID:      uid,
			GID:      gid,
		}

		ps = append(ps, p)
	}

	return ps, erasePaths, nil
}
