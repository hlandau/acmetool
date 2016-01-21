package storage

// In some cases it is desirable to load configuration information such as the
// default target file, but very undesirable to load sensitive information such
// as private keys. For example, the HTTP to HTTPS redirector is a public-facing
// service and as such, is run privilege-dropped and chrooted for mitigation
// purposes in the unlikely event that a vulnerability is identified in this
// program or its dependencies, each written in a memory-safe language.
// However, this could all be for nought if extremely valuable data such as
// private keys is kept in process memory after dropping privileges. It is
// therefore essential that private keys NEVER touch the memory of an acmetool
// process launched to serve as a redirector.
//
// Hence this function. Calling this function neuters the storage package.
// Neuter does two things:
//
//   - It panics if a storage instance has ever been created in this process
//     before the first call to Neuter.
//
//   - It changes the behaviour of the storage package so that all future loads
//     of state directories load configuration information, but no private keys.
//
// Thus, once Neuter has returned, this is essentially a guarantee that no
// private keys ever have been or ever will be loaded into the process. A call
// to Neuter cannot be reversed except by starting a new process.
func Neuter() {
	if hasTouchedSensitiveData {
		panic("cannot neuter storage package after it has already been used")
	}

	isNeutered = true
}

var isNeutered = false
var hasTouchedSensitiveData = false
