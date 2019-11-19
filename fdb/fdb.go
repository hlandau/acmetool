// Package fdb allows for the use of a filesystem directory as a simple
// database on UNIX-like systems.
package fdb

import (
	"fmt"
	deos "github.com/hlandau/goutils/os"
	"github.com/hlandau/xlog"
	"gopkg.in/hlandau/svcutils.v1/passwd"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

var log, Log = xlog.New("fdb")

// FDB instance.
type DB struct {
	cfg                  Config
	path                 string
	extantDirs           map[string]struct{}
	effectivePermissions []Permission
}

// FDB configuration.
type Config struct {
	Path            string
	Permissions     []Permission
	PermissionsPath string // If not "", allow permissions to be overriden from this file.
}

// Expresses the permission policy for a given path. The first match is used.
type Permission struct {
	// The path to which the permission applies. May contain wildcards and must
	// match a collection path, not an object path. e.g.
	//   accounts/*/*
	//   tmp
	// The directory will receive the DirMode and any objects inside will receive
	// the FileMode. Since all new files are initially created in tmp, it is
	// essential that tp have permissions specified which are strictly as strict
	// or stricter than the permissions of the strictest collection.
	// The root collection matches the path ".".
	Path     string
	FileMode os.FileMode
	DirMode  os.FileMode

	UID string // if not "", user/UID to enforce
	GID string // if not "", group/GID to enforce
}

// Merge b into a.
func mergePermissions(a, b []Permission) ([]Permission, error) {
	var r []Permission
	r = append(r, a...)

	am := map[string]int{}
	for i := range a {
		am[a[i].Path] = i
	}

	for i := range b {
		ai, ok := am[b[i].Path]
		if ok {
			r[ai] = b[i]
		} else {
			r = append(r, b[i])
		}
	}

	return r, nil
}

// Return a copy of a but without any permissions with paths in pathsToErase.
func erasePermissionsByPath(a []Permission, pathsToErase map[string]struct{}) []Permission {
	var r []Permission
	for i := range a {
		_, erase := pathsToErase[a[i].Path]
		if !erase {
			r = append(r, a[i])
		}
	}
	return r
}

// Open a fdb database or create a new database.
func Open(cfg Config) (*DB, error) {
	path, err := filepath.Abs(cfg.Path)
	if err != nil {
		return nil, err
	}

	db := &DB{
		cfg:        cfg,
		path:       path,
		extantDirs: map[string]struct{}{},
	}

	err = db.clearTmp()
	if err != nil {
		return nil, err
	}

	err = db.Verify()
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Closes the database.
func (db *DB) Close() error {
	return nil
}

// Integrity checks

// Verify the consistency and validity of the database (e.g. link targets).
// This is called automatically when opening the database so you shouldn't need
// to call it.
func (db *DB) Verify() error {
	err := db.loadPermissions()
	if err != nil {
		return err
	}

	err = db.createDirs()
	if err != nil {
		return err
	}

	// don't do this until now as EvalSymlinks requires the directory to exist
	db.path, err = filepath.EvalSymlinks(db.path)
	if err != nil {
		return err
	}

	if len(db.cfg.Permissions) > 0 {
		err = db.conformPermissions()
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *DB) createDirs() error {
	for _, p := range db.effectivePermissions {
		if strings.IndexByte(p.Path, '*') >= 0 {
			continue
		}

		uid, gid, err := resolveUIDGID(&p)
		if err != nil {
			return err
		}

		err = mkdirAllWithOwner(filepath.Join(db.path, p.Path), p.DirMode, uid, gid)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *DB) loadPermissions() error {
	db.effectivePermissions = db.cfg.Permissions

	if db.cfg.PermissionsPath == "" {
		return nil
	}

	r, err := db.Collection("").Open(db.cfg.PermissionsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}
	defer r.Close()

	ps, erasePaths, err := parsePermissions(r)
	if err != nil {
		return fmt.Errorf("badly formatted permissions file: %v", err)
	}

	mergedPermissions, err := mergePermissions(db.cfg.Permissions, ps)
	if err != nil {
		return err
	}

	mergedPermissions = erasePermissionsByPath(mergedPermissions, erasePaths)
	db.effectivePermissions = mergedPermissions
	return nil
}

// Returns the UID and GID to enforce. If the UID or GID is -1, it is not
// to be enforced. Neither or both or either of the UID or GID may be -1.
func resolveUIDGID(p *Permission) (uid, gid int, err error) {
	if p.UID == "$r" {
		uid = os.Getuid()
	} else if p.UID != "" {
		uid, err = passwd.ParseUID(p.UID)
		if err != nil {
			return
		}
	} else {
		uid = -1
	}

	if p.GID == "$r" {
		gid = os.Getgid()
	} else if p.GID != "" {
		gid, err = passwd.ParseGID(p.GID)
		if err != nil {
			return
		}
	} else {
		gid = -1
	}

	return
}

func isHiddenRelPath(rp string) bool {
	return strings.HasPrefix(rp, ".") || strings.Index(rp, "/.") >= 0
}

// Change all directory permissions to be correct.
func (db *DB) conformPermissions() error {
	err := filepath.Walk(db.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rpath, err := filepath.Rel(db.path, path)
		if err != nil {
			return err
		}

		// Some people want to store hidden files/directories inside the ACME state
		// directory without permissions enforcement. Since it's reasonable to
		// assume I'll never want to amend the ACME-SSS specification to specify
		// top-level directories inside a state directory, this shouldn't have any
		// security implications. Symlinks inside the state directory (whose state
		// directory paths themselves don't contain "/." and are thus ignored)
		// cannot reference ignored paths, as their permissions are not managed and
		// this is not safe. This is enforced elsewhere.
		if isHiddenRelPath(rpath) {
			return nil
		}

		mode := info.Mode()
		switch mode & os.ModeType {
		case 0:
		case os.ModeDir:
			db.extantDirs[rpath] = struct{}{}
		case os.ModeSymlink:
			l, err := os.Readlink(path)
			if err != nil {
				return err
			}

			if filepath.IsAbs(l) {
				return fmt.Errorf("database symlinks must not have absolute targets: %v: %v", path, l)
			}

			ll := filepath.Join(filepath.Dir(path), l)
			ll, err = filepath.Abs(ll)
			if err != nil {
				return err
			}

			ok, err := pathIsWithin(ll, db.path)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("database symlinks must point to within the database directory: %v: %v", path, ll)
			}

			rll, err := filepath.Rel(db.path, ll)
			if err != nil {
				return err
			}
			if isHiddenRelPath(rll) {
				return fmt.Errorf("database symlinks cannot target hidden files within the database directory: %v: %v", path, ll)
			}

			_, err = os.Stat(ll)
			if os.IsNotExist(err) {
				log.Warnf("broken symlink, removing: %v -> %v", path, l)
				err := os.Remove(path)
				if err != nil {
					return err
				}
			} else if err != nil {
				log.Errore(err, "stat symlink")
				return err
			}

		default:
			return fmt.Errorf("unexpected file type in state directory: %s", mode)
		}

		perm := db.longestMatching(rpath)
		if perm == nil {
			log.Warnf("object without any permissions specified: %v", rpath)
		} else {
			correctPerm := perm.FileMode
			if (mode & os.ModeType) == os.ModeDir {
				correctPerm = perm.DirMode
			}

			if (mode & os.ModeType) != os.ModeSymlink {
				if fperm := mode.Perm(); fperm != correctPerm {
					log.Warnf("%#v has wrong mode %v, changing to %v", rpath, fperm, correctPerm)

					err := os.Chmod(path, correctPerm)
					if err != nil {
						return err
					}
				}
			}

			correctUID, correctGID, err := resolveUIDGID(perm)
			if err != nil {
				return err
			}

			if correctUID >= 0 || correctGID >= 0 {
				curUID, err := deos.GetFileUID(info)
				if err != nil {
					return err
				}

				curGID, err := deos.GetFileGID(info)
				if err != nil {
					return err
				}

				if correctUID < 0 {
					correctUID = curUID
				}

				if correctGID < 0 {
					correctGID = curGID
				}

				if curUID != correctUID || curGID != correctGID {
					log.Warnf("%#v has wrong UID/GID %v/%v, changing to %v/%v", rpath, curUID, curGID, correctUID, correctGID)

					err := os.Lchown(path, correctUID, correctGID)
					// Can't chown if not root so be a bit forgiving, but always moan
					log.Errore(err, "could not lchown file ", rpath)
				}
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) longestMatching(path string) *Permission {
	pattern := ""
	var perm *Permission

	if filepath.IsAbs(path) {
		panic("do not call longestMatching with an absolute path")
	}

	for {
		for _, p := range db.effectivePermissions {
			m, err := filepath.Match(p.Path, path)
			if err != nil {
				return nil
			}

			if m && len(p.Path) > len(pattern) {
				pattern = p.Path
				p2 := p
				perm = &p2
			}
		}

		if perm != nil {
			return perm
		}

		if path == "." {
			break
		}

		path = filepath.Join(path, "..")
	}

	return nil
}

func pathIsWithin(subject, root string) (bool, error) {
	return strings.HasPrefix(subject, ensureSeparator(root)), nil
}

func ensureSeparator(p string) string {
	if !strings.HasSuffix(p, string(filepath.Separator)) {
		return p + string(filepath.Separator)
	}

	return p
}

func (db *DB) clearTmp() error {
	ms, err := filepath.Glob(filepath.Join(db.path, "tmp", "*"))
	if err != nil {
		return err
	}

	for _, m := range ms {
		err := os.RemoveAll(m)
		if err != nil {
			return err
		}
	}

	return nil
}

func (db *DB) ensurePath(path string) error {
	_, ok := db.extantDirs[path]
	if ok {
		return nil
	}

	mode := os.FileMode(0755)
	perm := db.longestMatching(path)
	if perm != nil {
		mode = perm.DirMode
	}

	uid, gid, err := resolveUIDGID(perm)
	if err != nil {
		return err
	}

	err = mkdirAllWithOwner(filepath.Join(db.path, path), mode, uid, gid)
	if err != nil {
		return err
	}

	db.extantDirs[path] = struct{}{}
	return nil
}

// Database Access

// Collection represents a collection of objects in an fdb database. More
// accurately, it is a contextual point in the database hierarchy which object
// references are interpreted relative to.
type Collection struct {
	db          *DB
	name        string
	ensuredPath bool
}

// Obtain a collection. The collection will be created automatically if it does
// not already exist. Guaranteed to return a non-nil value.
func (db *DB) Collection(collectionName string) *Collection {
	return &Collection{
		db:   db,
		name: collectionName,
	}
}

// Obtain a collection underneath the given collection. The collection will be
// created automatically if it does not already exist. Guaranteed to return a
// non-nil value.
func (c *Collection) Collection(name string) *Collection {
	return &Collection{
		db:   c.db,
		name: filepath.Join(c.name, name),
	}
}

func (c *Collection) ensurePath() error {
	if c.ensuredPath {
		return nil
	}

	err := c.db.ensurePath(c.name)
	if err != nil {
		return err
	}

	c.ensuredPath = true
	return nil
}

// Stream for reading an object from the database.
type ReadStream interface {
	Close() error
	Read([]byte) (int, error)
	Seek(int64, int) (int64, error)
}

// Stream for writing an object to the database. Changes do not take effect
// until the stream is closed, at which case they are applied atomically.
type WriteStream interface {
	ReadStream
	Write([]byte) (int, error)

	// Abort writing of the file. The file is not changed. Calling Close or
	// CloseAbort after calling this has no effect.
	CloseAbort() error
}

// A link points to a given name in a given collection. The database ensures
// referential integrity.
type Link struct {
	Target string // "collection1/subcollection/etc/objectName"
}

// Returns the database from which the collection was created.
func (c *Collection) DB() *DB {
	return c.db
}

// Returns the collection path.
func (c *Collection) Name() string {
	return c.name
}

// Returns the OS path to the file with the given name inside the collection.
// If name is "", returns the OS path to the collection.
func (c *Collection) OSPath(name string) string {
	c.ensurePath() // ignore error

	return filepath.Join(c.db.path, c.name, name)
}

// Atomically delete an existing object or link or subcollection in the given
// collection with the given name. Returns nil if the object does not exist.
func (c *Collection) Delete(name string) error {
	return os.RemoveAll(filepath.Join(c.db.path, c.name, name))
}

// Returned when calling Open() on a symlink. (To open symlinks, use Openl.)
var ErrIsLink = fmt.Errorf("cannot open symlink")

// Open an existing object in the given collection with the given name. The
// object is read-only. Returns an error if the object does not exist or
// is a link.
func (c *Collection) Open(name string) (ReadStream, error) {
	return c.open(name, false)
}

// Like Open(), but follows links automatically.
func (c *Collection) Openl(name string) (ReadStream, error) {
	return c.open(name, true)
}

func (c *Collection) open(name string, allowSymlinks bool) (ReadStream, error) {
	fi, err := os.Lstat(filepath.Join(c.db.path, c.name, name))
again:
	if err != nil {
		return nil, err
	}

	m := fi.Mode()
	switch m & os.ModeType {
	case 0:
	case os.ModeSymlink:
		if !allowSymlinks {
			return nil, ErrIsLink
		}

		fi, err = os.Stat(filepath.Join(c.db.path, c.name, name))
		goto again

	case os.ModeDir:
		return nil, fmt.Errorf("cannot open a collection")
	default:
		return nil, fmt.Errorf("unknown file type")
	}

	f, err := os.Open(filepath.Join(c.db.path, c.name, name))
	if err != nil {
		return nil, err
	}

	return f, nil
}

// Create a new object in the given collection with the given name. If the
// object already exists, it will be overwritten atomically.  Changes only take
// effect once the stream is closed.
func (c *Collection) Create(name string) (WriteStream, error) {
	err := c.ensurePath()
	if err != nil {
		return nil, err
	}

	f, err := ioutil.TempFile(filepath.Join(c.db.path, "tmp"), "tmp.")
	if err != nil {
		return nil, err
	}

	return &closeWrapper{
		db:           c.db,
		f:            f,
		finalName:    filepath.Join(c.db.path, c.name, name),
		finalNameRel: filepath.Join(c.name, name),
		writing:      true,
	}, nil
}

type closeWrapper struct {
	db           *DB
	f            *os.File
	finalName    string
	finalNameRel string
	closed       bool
	writing      bool
}

func (cw *closeWrapper) Close() error {
	if cw.closed {
		return nil
	}

	n := cw.f.Name()

	err := cw.f.Close()
	if err != nil {
		return err
	}

	err = os.Rename(n, cw.finalName)
	if err != nil {
		return err
	}

	if cw.writing {
		err = cw.db.enforcePermissionsOnFile(cw.finalNameRel, cw.finalNameRel, false)
		if err != nil {
			return err
		}
	}

	cw.closed = true
	return nil
}

func (db *DB) enforcePermissionsOnFile(rpath, rpathFinal string, symlink bool) error {
	p := db.longestMatching(rpathFinal)
	if p == nil {
		return nil
	}

	fpath := filepath.Join(db.path, rpath)

	// TempFile creates files with mode 0600, so it's OK to chmod/chown it here, race-wise.
	correctUID, correctGID, err := resolveUIDGID(p)
	if err != nil {
		return err
	}

	curUID, curGID := os.Getuid(), os.Getgid()
	if correctUID < 0 {
		correctUID = curUID
	}
	if correctGID < 0 {
		correctGID = curGID
	}

	log.Debugf("enforce permissions: %s %d/%d %d/%d", rpath, curUID, curGID, correctUID, correctGID)
	if correctUID != curUID || correctGID != curGID {
		err := os.Lchown(fpath, correctUID, correctGID)
		// failure is nonfatal, may not be root
		log.Errore(err, "could not set correct owner for file", fpath)
	}

	if !symlink {
		err = os.Chmod(fpath, p.FileMode)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cw *closeWrapper) CloseAbort() error {
	if cw.closed {
		return nil
	}

	err := cw.f.Close()
	if err != nil {
		return err
	}

	err = os.Remove(cw.f.Name())
	if err != nil {
		return err
	}

	cw.closed = true
	return nil
}

func (cw *closeWrapper) Read(b []byte) (int, error) {
	return cw.f.Read(b)
}

func (cw *closeWrapper) Write(b []byte) (int, error) {
	return cw.f.Write(b)
}

func (cw *closeWrapper) Seek(p int64, w int) (int64, error) {
	return cw.f.Seek(p, w)
}

// Read a link in the given collection with the given name. Returns an error
// if the object does not exist or is not a link.
func (c *Collection) ReadLink(name string) (Link, error) {
	fpath := filepath.Join(c.db.path, c.name, name)

	l, err := os.Readlink(fpath)
	if err != nil {
		return Link{}, err
	}

	flink := filepath.Join(filepath.Dir(fpath), l)

	lr, err := filepath.Rel(c.db.path, flink)
	if err != nil {
		return Link{}, err
	}

	return Link{Target: lr}, nil
}

// Write a link in the given collection with the given name. Any existing
// object or link is overwritten atomically.
func (c *Collection) WriteLink(name string, target Link) error {
	err := c.ensurePath()
	if err != nil {
		return err
	}

	from := filepath.Join(c.db.path, c.name, name)
	to := filepath.Join(c.db.path, target.Target)
	toRel, err := filepath.Rel(filepath.Dir(from), to)
	if err != nil {
		return err
	}

	// if the link already exists, do nothing
	existingTo, err := os.Readlink(from)
	if err == nil && existingTo == toRel {
		return nil
	}
	
	tmpName, err := tempSymlink(toRel, filepath.Join(c.db.path, "tmp"))
	if err != nil {
		return err
	}

	err = c.db.enforcePermissionsOnFile(filepath.Join("tmp", filepath.Base(tmpName)),
		filepath.Join(c.name, name), true)
	if err != nil {
		return err
	}

	return os.Rename(tmpName, from)
}

func (c *Collection) ListAll() ([]string, error) {
	ms, err := filepath.Glob(filepath.Join(c.db.path, c.name, "*"))
	if err != nil {
		return nil, err
	}

	var objs []string
	for _, m := range ms {
		objs = append(objs, filepath.Base(m))
	}

	return objs, nil
}

// List the objects and collections in the collection. Filenames beginning with
// '.' are hidden.
func (c *Collection) List() ([]string, error) {
	s, err := c.ListAll()
	if err != nil {
		return nil, err
	}

	s2 := make([]string, 0, len(s))
	for _, x := range s {
		if strings.HasPrefix(x, ".") {
			continue
		}

		s2 = append(s2, x)
	}

	return s2, nil
}
