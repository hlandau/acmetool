// Package fdb allows for the use of a filesystem directory as a simple
// database on UNIX-like systems.
package fdb

import "os"
import "io/ioutil"
import "path/filepath"
import "fmt"
import "github.com/hlandau/xlog"
import "strings"

var log, Log = xlog.New("fdb")

type DB struct {
	cfg        Config
	path       string
	extantDirs map[string]struct{}
}

type Config struct {
	Path        string
	Permissions []Permission
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

	err = db.Verify()
	if err != nil {
		return nil, err
	}

	err = db.clearTmp()
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
	err := db.createDirs()
	if err != nil {
		return err
	}

	// don't do this until now as EvalSymlinks requires the directory to exist
	db.path, err = filepath.EvalSymlinks(db.path)
	if err != nil {
		return err
	}

	err = db.conformPermissions()
	if err != nil {
		return err
	}

	return nil
}

func (db *DB) createDirs() error {
	for _, p := range db.cfg.Permissions {
		if strings.IndexByte(p.Path, '*') >= 0 {
			continue
		}

		//log.Debugf("making directory %#v with mode: %v", p.Path, p.DirMode)
		err := os.MkdirAll(filepath.Join(db.path, p.Path), p.DirMode)
		if err != nil {
			return err
		}
	}

	return nil
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
		for _, p := range db.cfg.Permissions {
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

	/*
		for _, p := range db.cfg.Permissions {
			ok, err := filepath.Match(p.Path, path)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}

			mode = p.DirMode
			break
		}
	*/

	err := os.MkdirAll(filepath.Join(db.path, path), mode)
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
	//err := db.ensurePath(collectionName)
	//log.Errore(err, "cannot ensure path")

	return &Collection{
		db:   db,
		name: collectionName,
	}
}

// Obtain a collection underneath the given collection. The collection will be
// created automatically if it does not already exist. Guaranteed to return a
// non-nil value.
func (c *Collection) Collection(name string) *Collection {
	//err := c.db.ensurePath(c.name + "/" + name)
	//log.Errore(err, "cannot ensure path")

	return &Collection{
		db:   c.db,
		name: c.name + "/" + name,
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

	if name == "" {
		return filepath.Join(c.db.path, c.name)
	}
	return filepath.Join(c.db.path, c.name, name)
}

// Atomically delete an existing object or link or subcollection in the given
// collection with the given name. Returns nil if the object does not exist.
func (c *Collection) Delete(name string) error {
	return os.RemoveAll(filepath.Join(c.db.path, c.name, name))
}

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
		p := cw.db.longestMatching(cw.finalNameRel)
		if p != nil {
			// TempFile creates files with mode 0600, so it's OK to chmod it here, race-wise
			err = os.Chmod(cw.finalName, p.FileMode)
			if err != nil {
				return err
			}
		}
	}

	cw.closed = true
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

	tmpName, err := tempSymlink(toRel, filepath.Join(c.db.path, "tmp"))
	if err != nil {
		return err
	}

	return os.Rename(tmpName, from)
}

// List the objects and collections in the collection.
func (c *Collection) List() ([]string, error) {
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

// © 2015 Hugo Landau <hlandau@devever.net>    MIT License
