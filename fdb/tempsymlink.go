package fdb

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var rand uint32
var randmu sync.Mutex

func reseed() uint32 {
	return uint32(time.Now().UnixNano() + int64(os.Getpid()))
}

func nextSuffix() string {
	randmu.Lock()
	r := rand
	if r == 0 {
		r = reseed()
	}
	r = r*1664525 + 1013904223
	rand = r
	randmu.Unlock()
	return strconv.Itoa(int(1e9 + r%1e9))[1:]
}

func tempSymlink(target string, fromDir string) (tmpName string, err error) {
	nconflict := 0
	for i := 0; i < 10000; i++ {
		tmpName = filepath.Join(fromDir, "symlink."+nextSuffix())
		err = os.Symlink(target, tmpName)
		if os.IsExist(err) {
			if nconflict++; nconflict > 10 {
				randmu.Lock()
				rand = reseed()
				randmu.Unlock()
			}
			continue
		}
		break
	}
	return
}
