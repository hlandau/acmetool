package storage

import (
	"crypto"
	"errors"
)

// Abstract storage interface.
type Store interface {
	Close() error  // Closes the database.
	Reload() error // Reloads the database from disk.
	Path() string  // ACME state directory path.

	// These methods find an object by its identifier. Returns nil if the object
	// is not found.
	AccountByID(accountID string) *Account
	AccountByDirectoryURL(directoryURL string) *Account
	CertificateByID(certificateID string) *Certificate
	KeyByID(keyID string) *Key
	TargetByFilename(filename string) *Target

	DefaultTarget() *Target // Returns the default target.
	PreferredCertificateForHostname(hostname string) (*Certificate, error)
	VisitPreferredCertificates(func(hostname string, c *Certificate) error) error

	// The Visit methods call the given function for each known object of the
	// given type. Returning an error short-circuits.
	VisitAccounts(func(*Account) error) error
	VisitCertificates(func(*Certificate) error) error
	VisitKeys(func(*Key) error) error
	VisitTargets(func(*Target) error) error

	// Mutators.
	SaveTarget(*Target) error           // Saves a target.
	RemoveTarget(filename string) error // Remove a target from the database.

	SaveCertificate(*Certificate) error // Saves certificate information.
	SaveAccount(*Account) error         // Save account information.

	// Erase a whole certificate directory including URL, certificates, etc.
	RemoveCertificate(certificateID string) error
	// Erase a private key directory.
	RemoveKey(keyID string) error

	ImportKey(privateKey crypto.PrivateKey) (*Key, error)                              // Imports the key if it isn't already imported.
	ImportAccount(directoryURL string, privateKey crypto.PrivateKey) (*Account, error) // Imports an account key if it isn't already imported.
	ImportCertificate(acct *Account, url string) (*Certificate, error)                 // Imports a certificate if it isn't already imported.

	SetPreferredCertificateForHostname(hostname string, c *Certificate) error

	WriteMiscellaneousConfFile(filename string, data []byte) error
}

// Return this sentinel value to stop visitation.
var StopVisiting = errors.New("[stop visiting]")
